import type { AuthRequest, CompleteAuthorizationOptions, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { describe, expect, it, vi } from "vitest";
import { commitAccountDraft, newAccountDraft } from "../src/accounts";
import { createCredentialAuthHandler, type CredentialAuthDependencies } from "../src/auth";
import { MailCredentialError } from "../src/credentials";
import { restrictMailPropsToTokenScope, type AppEnv, type StoredMailAccount } from "../src/types";

class MemoryKv {
  readonly values = new Map<string, string>();

  async put(key: string, value: string): Promise<void> {
    this.values.set(key, value);
  }

  async get(key: string, type?: "json"): Promise<unknown> {
    const value = this.values.get(key);
    if (value === undefined) return null;
    return type === "json" ? JSON.parse(value) as unknown : value;
  }

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }
}

function oauthRequest(): AuthRequest {
  return {
    responseType: "code",
    clientId: "client-1",
    redirectUri: "https://client.example/callback",
    scope: ["mail.read", "mail.write", "offline_access"],
    state: "client-state",
    codeChallenge: "client-challenge",
    codeChallengeMethod: "S256",
  };
}

function account(seed = "primary"): StoredMailAccount {
  return {
    accountId: `acct_${seed.padEnd(22, "x").slice(0, 22)}`,
    label: seed === "primary" ? "Personal" : "Second",
    preset: "icloud",
    address: `${seed}@icloud.com`,
    capabilities: { mail: true, calendar: true, contacts: true },
    config: {
      email: `${seed}@icloud.com`,
      imapUser: seed,
      password: "app-password",
      imapHost: "imap.mail.me.com",
      imapPort: 993,
      imapTlsMode: "implicit",
      smtpHost: "smtp.mail.me.com",
      smtpPort: 587,
      smtpTlsMode: "starttls",
      smtpUser: `${seed}@icloud.com`,
      smtpPassword: "app-password",
    },
  };
}

function oauthEnv(options: {
  oauthKv?: MemoryKv;
  credentialsKv?: MemoryKv;
  complete?: OAuthHelpers["completeAuthorization"];
  encryptionKey?: string;
} = {}): AppEnv {
  const request = oauthRequest();
  const helpers = {
    parseAuthRequest: async () => request,
    lookupClient: async () => ({
      clientId: request.clientId,
      redirectUris: [request.redirectUri],
      tokenEndpointAuthMethod: "none",
      clientName: "Test <client>",
    }),
    completeAuthorization: options.complete ?? (async () => ({ redirectTo: "https://client.example/callback?code=local" })),
  } as unknown as OAuthHelpers;
  return {
    OAUTH_KV: (options.oauthKv ?? new MemoryKv()) as unknown as KVNamespace,
    MAIL_CREDENTIALS_KV: (options.credentialsKv ?? new MemoryKv()) as unknown as KVNamespace,
    OAUTH_PROVIDER: helpers,
    CALDAV_URL: "https://caldav.icloud.com/",
    CARDDAV_URL: "https://contacts.icloud.com/",
    MAIL_CREDENTIALS_ENCRYPTION_KEY: options.encryptionKey ?? "a-secure-test-encryption-key-with-32-chars",
  };
}

function authFetchFor(dependencies?: CredentialAuthDependencies) {
  return createCredentialAuthHandler(dependencies).fetch as unknown as (
    request: Request,
    env: AppEnv,
    ctx: ExecutionContext,
  ) => Promise<Response>;
}

function stateAndCookie(response: Response): { state: string; cookie: string } {
  const setCookie = response.headers.get("Set-Cookie") ?? "";
  const cookie = setCookie.split(";", 1)[0];
  const [name, value = ""] = cookie.split("=", 2);
  const state = name.slice("mcp_oauth_state_".length);
  expect(value.startsWith(`${state}.`)).toBe(true);
  return { state, cookie };
}

function post(state: string, cookie: string | undefined, values: Record<string, string>, scopes = ["mail.read"]): Request {
  const body = new URLSearchParams({ authorization_state: state, ...values });
  if (!body.has("scope_form")) body.set("scope_form", "1");
  for (const scope of scopes) body.append("scope", scope);
  return new Request("https://mcp.example/authorize", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...(cookie ? { Cookie: cookie } : {}),
    },
    body,
  });
}

function initialAccountForm(state: string, cookie: string | undefined, mode: "create" | "manage" = "create"): Request {
  return post(state, cookie, {
    action: "verify",
    target: "start",
    mode,
    preset: "icloud",
    label: "Personal",
    address: "primary@icloud.com",
    app_password: "app-password",
    service_options_present: "1",
    enable_mail: "1",
  });
}

const context = {} as ExecutionContext;

describe("multi-account OAuth authorization", () => {
  it("narrows v2 and legacy props to the access token scope", () => {
    expect(restrictMailPropsToTokenScope(
      { userId: "usr_test", scopes: ["mail.read", "mail.write"] },
      ["mail.read", "offline_access"],
    )).toEqual({ userId: "usr_test", scopes: ["mail.read"] });
    expect(restrictMailPropsToTokenScope(
      { userId: "icloud-test", credentialId: "icloud-test", scopes: ["mail.read"] },
      ["mail.read"],
    )).toEqual({ userId: "icloud-test", credentialId: "icloud-test", scopes: ["mail.read"] });
  });

  it("renders a generic create/manage page with requested scopes and no credentials", async () => {
    const oauthKv = new MemoryKv();
    const response = await authFetchFor()(new Request("https://mcp.example/authorize"), oauthEnv({ oauthKv }), context);
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).toContain("Email MCP");
    expect(body).toContain("Create a new profile");
    expect(body).toContain("Manage an existing profile");
    expect(body).toContain("mail.read");
    expect(body).not.toContain("calendar.read");
    expect(body).not.toContain("app-password");
    expect(response.headers.get("Set-Cookie")).toContain("HttpOnly");
    expect(response.headers.get("Set-Cookie")).toContain("Path=/authorize");
    expect(oauthKv.values.size).toBe(1);
  });

  it("rejects an unbound cross-site POST but accepts the same-origin cookie fallback", async () => {
    const oauthKv = new MemoryKv();
    const environment = oauthEnv({ oauthKv });
    const verify = vi.fn(async () => account());
    const authFetch = authFetchFor({ verifyAccountSubmission: verify });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state } = stateAndCookie(authorize);

    const sameOrigin = initialAccountForm(state, undefined);
    sameOrigin.headers.set("Origin", "https://mcp.example");
    expect((await authFetch(sameOrigin, environment, context)).status).toBe(200);

    const second = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const secondState = stateAndCookie(second).state;
    const crossSite = initialAccountForm(secondState, undefined);
    crossSite.headers.set("Origin", "https://attacker.example");
    expect((await authFetch(crossSite, environment, context)).status).toBe(400);
  });

  it("creates an encrypted draft, commits it on Continue, and issues opaque v2 props", async () => {
    const oauthKv = new MemoryKv();
    const credentialsKv = new MemoryKv();
    const complete = vi.fn(async (_options: CompleteAuthorizationOptions) => ({ redirectTo: "https://client.example/callback?code=issued" }));
    const environment = oauthEnv({ oauthKv, credentialsKv, complete });
    const authFetch = authFetchFor({ verifyAccountSubmission: vi.fn(async () => account()) });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);

    const verified = await authFetch(initialAccountForm(state, cookie), environment, context);
    expect(verified.status).toBe(200);
    expect(await verified.text()).toContain("Review the profile");
    expect([...credentialsKv.values.values()].join("\n")).not.toContain("app-password");

    const response = await authFetch(post(state, cookie, { action: "continue", mode: "manage" }, ["mail.read", "offline_access"]), environment, context);
    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toContain("code=issued");
    expect(response.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect(complete).toHaveBeenCalledOnce();
    const options = complete.mock.calls[0][0];
    expect(options.userId).toMatch(/^usr_/u);
    expect(options.scope).toEqual(["mail.read", "offline_access"]);
    expect(options.props).toEqual({ userId: options.userId, scopes: ["mail.read"] });
    expect(JSON.stringify(options.props)).not.toContain("icloud.com");
    expect(oauthKv.values.size).toBe(0);
  });

  it("unlocks an existing profile by verifying any configured live account", async () => {
    const oauthKv = new MemoryKv();
    const credentialsKv = new MemoryKv();
    const environment = oauthEnv({ oauthKv, credentialsKv });
    const vault = await commitAccountDraft(environment, newAccountDraft(account()));
    const verifiedAccount = { ...account(), accountId: "acct_zzzzzzzzzzzzzzzzzzzzzz" };
    const authFetch = authFetchFor({ verifyAccountSubmission: vi.fn(async () => verifiedAccount) });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    const response = await authFetch(initialAccountForm(state, cookie, "manage"), environment, context);
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).toContain("Personal");
    expect(body).toContain("Manage Email MCP accounts");
    expect(body).not.toContain(vault.userId);
  });

  it("returns a generic verification error and enforces the five-attempt limit", async () => {
    const environment = oauthEnv();
    const authFetch = authFetchFor({
      verifyAccountSubmission: vi.fn(async () => { throw new MailCredentialError("specific upstream failure"); }),
    });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      const response = await authFetch(initialAccountForm(state, cookie), environment, context);
      expect(response.status).toBe(401);
      expect(await response.text()).toContain("could not be verified");
    }
    const final = await authFetch(initialAccountForm(state, cookie), environment, context);
    expect(final.status).toBe(401);
    expect(await final.json()).toEqual({ error: "Account verification failed too many times" });
    expect(final.headers.get("Set-Cookie")).toContain("Max-Age=0");
  });

  it("denies authorization and deletes OAuth state and account drafts", async () => {
    const oauthKv = new MemoryKv();
    const credentialsKv = new MemoryKv();
    const environment = oauthEnv({ oauthKv, credentialsKv });
    const authFetch = authFetchFor({ verifyAccountSubmission: vi.fn(async () => account()) });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    await authFetch(initialAccountForm(state, cookie), environment, context);
    const denied = await authFetch(post(state, cookie, { decision: "deny", mode: "manage" }, []), environment, context);
    expect(denied.status).toBe(302);
    expect(denied.headers.get("Location")).toContain("error=access_denied");
    expect(oauthKv.values.size).toBe(0);
    expect([...credentialsKv.values.keys()].some((key) => key.includes("draft"))).toBe(false);
  });

  it("returns a configuration error when the encryption secret is invalid", async () => {
    const response = await authFetchFor()(new Request("https://mcp.example/authorize"), oauthEnv({ encryptionKey: "short" }), context);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "Mail credential storage is not configured" });
  });
});
