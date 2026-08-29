import type { AuthRequest, CompleteAuthorizationOptions, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { describe, expect, it, vi } from "vitest";
import { AccountVaultError, commitAccountDraft, newAccountDraft, type AccountSubmission } from "../src/accounts";
import { createCredentialAuthHandler, type CredentialAuthDependencies } from "../src/auth";
import { decodeAuthPageModel, decodeUiPageModel, type AuthPageModel } from "../src/auth-ui";
import { MailCredentialError } from "../src/credentials";
import type { DiscoveredAccountSettings } from "../src/discovery/types";
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
    redirectUri: "http://127.0.0.1:6274/oauth/callback?tenant=one",
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
  kv?: MemoryKv;
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
    completeAuthorization: options.complete ?? (async () => ({ redirectTo: "http://127.0.0.1:6274/oauth/callback?code=local" })),
  } as unknown as OAuthHelpers;
  return {
    OAUTH_KV: (options.kv ?? new MemoryKv()) as unknown as KVNamespace,
    OAUTH_PROVIDER: helpers,
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

async function pageModel(response: Response): Promise<AuthPageModel> {
  const body = await response.text();
  const encoded = /data-page="([A-Za-z0-9_-]+)"/u.exec(body)?.[1];
  expect(encoded).toBeTruthy();
  return decodeAuthPageModel(encoded ?? "");
}

function post(state: string, cookie: string | undefined, values: Record<string, string>, scopes: string[] = []): Request {
  const body = new URLSearchParams({ authorization_state: state, ...values });
  if (scopes.length) {
    body.set("scope_form", "1");
    for (const scope of scopes) body.append("scope", scope);
  }
  return new Request("https://mcp.example/authorize", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...(cookie ? { Cookie: cookie } : {}),
    },
    body,
  });
}

function initialAccountForm(state: string, cookie: string | undefined): Request {
  return post(state, cookie, {
    action: "verify",
    target: "start",
    preset: "icloud",
    label: "Personal",
    address: "primary@icloud.com",
    app_password: "app-password",
    service_options_present: "1",
    enable_mail: "1",
  });
}

function lookupForm(state: string, cookie: string | undefined, address = "primary@icloud.com", target = "start"): Request {
  return post(state, cookie, { action: "lookup", target, address });
}

function unlockForm(state: string, cookie: string | undefined, accountId: string, password = "app-password"): Request {
  return post(state, cookie, {
    action: "unlock",
    target: "start",
    account_id: accountId,
    account_password: password,
  });
}

function discoverForm(state: string, cookie: string | undefined, address = "person@example.com", password = "account-password", target = "start"): Request {
  return post(state, cookie, {
    action: "discover",
    target,
    address,
    new_account_password: password,
  });
}

function discoveredSettings(address = "person@example.com"): DiscoveredAccountSettings {
  return {
    providerName: "Example Mail",
    mail: {
      imapHost: "imap.example.com",
      imapPort: 993,
      imapTlsMode: "implicit",
      imapUser: address,
      smtpHost: "smtp.example.com",
      smtpPort: 587,
      smtpTlsMode: "starttls",
      smtpUser: address,
    },
    caldavUrl: "https://dav.example.com/",
    carddavUrl: "https://dav.example.com/",
    davUser: address,
    sources: ["provider_autoconfig", "well_known"],
  };
}

const context = {} as ExecutionContext;

describe("public onboarding routes", () => {
  it("renders a landing page with origin-specific setup URLs", async () => {
    const response = await authFetchFor()(new Request("https://self-host.example:8443/"), oauthEnv(), context);
    const body = await response.text();
    const encoded = /data-page="([A-Za-z0-9_-]+)"/u.exec(body)?.[1] ?? "";
    const model = decodeUiPageModel(encoded);

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Content-Security-Policy")).toContain("script-src 'self'");
    expect(model).toEqual({
      version: 1,
      kind: "landing",
      origin: "https://self-host.example:8443",
      mcpUrl: "https://self-host.example:8443/mcp",
      agentSetupUrl: "https://self-host.example:8443/agent-setup/prompt.md",
    });

    const head = await authFetchFor()(new Request("https://self-host.example:8443/", { method: "HEAD" }), oauthEnv(), context);
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
    expect(head.headers.get("Content-Type")).toBe(response.headers.get("Content-Type"));
    expect(head.headers.get("Content-Security-Policy")).toBe(response.headers.get("Content-Security-Policy"));
  });

  it("serves dynamic onboarding instructions and a bodyless HEAD response", async () => {
    const authFetch = authFetchFor();
    const get = await authFetch(new Request("https://hosted.example/agent-setup/prompt.md"), oauthEnv(), context);
    const prompt = await get.text();
    expect(get.status).toBe(200);
    expect(get.headers.get("Content-Type")).toBe("text/markdown; charset=utf-8");
    expect(get.headers.get("Cache-Control")).toBe("no-store");
    expect(get.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(prompt).toContain("https://hosted.example/mcp");
    expect(prompt).toContain("codex mcp add mailboxer --url https://hosted.example/mcp");
    expect(prompt).toContain("codex mcp login mailboxer");
    expect(prompt).toContain("claude mcp add --transport http --scope user mailboxer https://hosted.example/mcp");
    expect(prompt).toContain("Do not ask the user for a mailbox password");
    expect(prompt).toContain("https://help.openai.com/en/articles/12584461-developer-mode-apps-and-full-mcp-connectors-in-chatgpt-beta");
    expect(prompt).toContain("https://support.anthropic.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp");

    const head = await authFetch(new Request("https://hosted.example/agent-setup/prompt.md", { method: "HEAD" }), oauthEnv(), context);
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
    expect(head.headers.get("Content-Type")).toBe(get.headers.get("Content-Type"));
    expect(head.headers.get("Cache-Control")).toBe(get.headers.get("Cache-Control"));
    expect(head.headers.get("Content-Security-Policy")).toBe(get.headers.get("Content-Security-Policy"));
  });

  it("moves the legacy health JSON response to /health", async () => {
    const authFetch = authFetchFor();
    const get = await authFetch(new Request("https://hosted.example/health"), oauthEnv(), context);
    expect(get.status).toBe(200);
    expect(get.headers.get("Content-Type")).toBe("application/json");
    expect(await get.json()).toEqual({ name: "email-mcp", endpoint: "/mcp", status: "ok" });

    const head = await authFetch(new Request("https://hosted.example/health", { method: "HEAD" }), oauthEnv(), context);
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });

  it("returns method errors for public routes without changing the unknown-route contract", async () => {
    const authFetch = authFetchFor();
    for (const path of ["/", "/agent-setup/prompt.md", "/health"]) {
      const response = await authFetch(new Request(`https://hosted.example${path}`, { method: "POST" }), oauthEnv(), context);
      expect(response.status).toBe(405);
      expect(response.headers.get("Allow")).toBe("GET, HEAD");
      expect(await response.text()).toBe("Method not allowed");
    }

    const missing = await authFetch(new Request("https://hosted.example/missing"), oauthEnv(), context);
    expect(missing.status).toBe(404);
    expect(await missing.text()).toBe("Not found");
  });
});

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

  it("renders the React authorization shell without permissions or credentials", async () => {
    const kv = new MemoryKv();
    const response = await authFetchFor()(new Request("https://mcp.example/authorize"), oauthEnv({ kv }), context);
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).toContain("/auth.js");
    expect(body).toContain("/style.css");
    expect(body).not.toContain("mail.read");
    expect(body).not.toContain("Permissions");
    expect(body).not.toContain("app-password");
    const encoded = /data-page="([A-Za-z0-9_-]+)"/u.exec(body)?.[1] ?? "";
    const model = decodeAuthPageModel(encoded);
    expect(model.kind).toBe("account-form");
    if (model.kind === "account-form") {
      expect(model.step).toBe("email");
      expect(model.account.preset).toBe("icloud");
      expect(model.account.address).toBe("");
    }
    expect(response.headers.get("Content-Security-Policy")).toContain("script-src 'self'");
    const initialCsp = response.headers.get("Content-Security-Policy") ?? "";
    expect(initialCsp).toContain("img-src 'self'");
    expect(initialCsp).toContain("form-action 'self' http://127.0.0.1:6274");
    expect(initialCsp).not.toContain("/callback");
    expect(initialCsp).not.toContain("tenant=one");
    expect(response.headers.get("Set-Cookie")).toContain("HttpOnly");
    expect(response.headers.get("Set-Cookie")).toContain("Path=/authorize");
    expect(kv.values.size).toBe(1);
  });

  it("omits CSP only for local HTTP development origins", async () => {
    const authFetch = authFetchFor();
    const local = await authFetch(new Request("http://localhost:8787/authorize"), oauthEnv(), context);
    expect(local.headers.get("Content-Security-Policy")).toBeNull();

    for (const url of ["https://localhost/authorize", "http://localhost.example/authorize", "https://mcp.example/authorize"]) {
      const response = await authFetch(new Request(url), oauthEnv(), context);
      expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
      expect(response.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    }
  });

  it("rejects an unbound cross-site POST but accepts the same-origin cookie fallback", async () => {
    const kv = new MemoryKv();
    const environment = oauthEnv({ kv });
    const verify = vi.fn(async (_env: AppEnv, _submission: AccountSubmission) => account());
    const authFetch = authFetchFor({ verifyAccountSubmission: verify });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state } = stateAndCookie(authorize);

    const sameOrigin = lookupForm(state, undefined);
    sameOrigin.headers.set("Origin", "https://mcp.example");
    expect((await authFetch(sameOrigin, environment, context)).status).toBe(200);

    const second = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const secondState = stateAndCookie(second).state;
    const crossSite = lookupForm(secondState, undefined);
    crossSite.headers.set("Origin", "https://attacker.example");
    expect((await authFetch(crossSite, environment, context)).status).toBe(400);
  });

  it("asks only for a password after checking a new email and detects its provider", async () => {
    const environment = oauthEnv();
    const authFetch = authFetchFor();
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);

    const response = await authFetch(lookupForm(state, cookie, "person@example.com"), environment, context);
    const model = await pageModel(response);
    expect(model.kind).toBe("account-form");
    if (model.kind === "account-form") {
      expect(model.step).toBe("new-password");
      expect(model.account.address).toBe("person@example.com");
      expect(model.account.preset).toBe("custom");
      expect(model.account.dav).toEqual({ calendarUrl: "", contactsUrl: "", user: "person@example.com" });
      expect(JSON.stringify(model)).not.toContain("imap.example.com");
    }
  });

  it("passes custom calendar and contacts server addresses to account verification", async () => {
    const verify = vi.fn(async (_env: AppEnv, _submission: AccountSubmission) => account());
    const environment = oauthEnv();
    const authFetch = authFetchFor({ verifyAccountSubmission: verify });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    await authFetch(lookupForm(state, cookie, "person@example.com"), environment, context);

    const response = await authFetch(post(state, cookie, {
      action: "verify",
      target: "start",
      preset: "custom",
      label: "Other provider",
      address: "person@example.com",
      service_options_present: "1",
      enable_calendar: "1",
      enable_contacts: "1",
      custom_fields_present: "1",
      imap_host: "imap.example.com",
      imap_port: "993",
      imap_tls_mode: "implicit",
      imap_user: "person",
      imap_password: "password",
      smtp_host: "smtp.example.com",
      smtp_port: "587",
      smtp_tls_mode: "starttls",
      same_smtp_credentials: "1",
      caldav_url: "https://dav.example.com/calendar/",
      carddav_url: "https://dav.example.com/contacts/",
    }), environment, context);

    expect(response.status).toBe(200);
    expect(verify.mock.calls[0]?.[1]).toMatchObject({
      enableCalendar: true,
      enableContacts: true,
      caldavUrl: "https://dav.example.com/calendar/",
      carddavUrl: "https://dav.example.com/contacts/",
    });
  });

  it("discovers and verifies every available service before opening the account list", async () => {
    const discover = vi.fn(async (address: string) => discoveredSettings(address));
    const verify = vi.fn(async (_env: AppEnv, submission: AccountSubmission) => ({
      ...account(),
      preset: "custom" as const,
      label: submission.label,
      address: submission.address,
      capabilities: {
        mail: submission.enableMail === true,
        calendar: submission.enableCalendar === true,
        contacts: submission.enableContacts === true,
      },
    }));
    const environment = oauthEnv();
    const authFetch = authFetchFor({ discoverAccountSettings: discover, verifyAccountSubmission: verify });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    await authFetch(lookupForm(state, cookie, "person@example.com"), environment, context);

    const response = await authFetch(discoverForm(state, cookie), environment, context);
    const model = await pageModel(response);
    expect(response.status).toBe(200);
    expect(model.kind).toBe("management");
    expect(discover).toHaveBeenCalledWith("person@example.com");
    expect(verify.mock.calls[0]?.[1]).toMatchObject({
      preset: "custom",
      label: "Example Mail",
      address: "person@example.com",
      enableMail: true,
      enableCalendar: true,
      enableContacts: true,
      imapHost: "imap.example.com",
      imapPassword: "account-password",
      smtpHost: "smtp.example.com",
      sameSmtpCredentials: true,
      caldavUrl: "https://dav.example.com/",
      carddavUrl: "https://dav.example.com/",
      davUser: "person@example.com",
    });
  });

  it("shows discovered settings after verification fails without returning the password", async () => {
    const environment = oauthEnv();
    const authFetch = authFetchFor({
      discoverAccountSettings: vi.fn(async (address: string) => discoveredSettings(address)),
      verifyAccountSubmission: vi.fn(async () => { throw new AccountVaultError("We couldn't connect calendar"); }),
    });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    await authFetch(lookupForm(state, cookie, "person@example.com"), environment, context);

    const response = await authFetch(discoverForm(state, cookie), environment, context);
    const body = await response.clone().text();
    const model = await pageModel(response);
    expect(response.status).toBe(401);
    expect(model.kind).toBe("account-form");
    if (model.kind === "account-form") {
      expect(model.step).toBe("config");
      expect(model.account.imap.host).toBe("imap.example.com");
      expect(model.account.smtp.host).toBe("smtp.example.com");
      expect(model.account.dav).toEqual({
        calendarUrl: "https://dav.example.com/",
        contactsUrl: "https://dav.example.com/",
        user: "person@example.com",
      });
      expect(model.message?.text).toContain("calendar");
    }
    expect(JSON.stringify(model)).not.toContain("account-password");
    expect(body).not.toContain("account-password");
  });

  it("creates an encrypted draft, commits it on Continue, and issues opaque v2 props", async () => {
    const kv = new MemoryKv();
    const complete = vi.fn(async (_options: CompleteAuthorizationOptions) => ({ redirectTo: "http://127.0.0.1:6274/oauth/callback?code=issued" }));
    const environment = oauthEnv({ kv, complete });
    const authFetch = authFetchFor({ verifyAccountSubmission: vi.fn(async () => account()) });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);

    const details = await authFetch(lookupForm(state, cookie), environment, context);
    const detailsPage = await pageModel(details);
    expect(detailsPage.kind).toBe("account-form");
    if (detailsPage.kind === "account-form") expect(detailsPage.step).toBe("new-password");

    const verified = await authFetch(initialAccountForm(state, cookie), environment, context);
    expect(verified.status).toBe(200);
    const managementCsp = verified.headers.get("Content-Security-Policy") ?? "";
    expect(managementCsp).toContain("form-action 'self' http://127.0.0.1:6274");
    expect(managementCsp).not.toContain("/callback");
    expect(managementCsp).not.toContain("tenant=one");
    const verifiedPage = await pageModel(verified);
    expect(verifiedPage.kind).toBe("management");
    expect(verifiedPage.message?.text).toContain("Account added");
    expect([...kv.values.values()].join("\n")).not.toContain("app-password");
    expect([...kv.values.keys()]).toEqual(expect.arrayContaining([
      `mail-oauth:state:${state}`,
      `mail:account-draft:v2:${state}`,
    ]));

    const response = await authFetch(post(state, cookie, { action: "continue" }, ["mail.read", "offline_access"]), environment, context);
    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toContain("code=issued");
    expect(response.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect(complete).toHaveBeenCalledOnce();
    const options = complete.mock.calls[0][0];
    expect(options.userId).toMatch(/^usr_/u);
    expect(options.scope).toEqual(["mail.read", "mail.write", "offline_access"]);
    expect(options.props).toEqual({ userId: options.userId, scopes: ["mail.read", "mail.write"] });
    expect(JSON.stringify(options.props)).not.toContain("icloud.com");
    expect([...kv.values.keys()].some((key) => key.startsWith("mail-oauth:state:"))).toBe(false);
    expect([...kv.values.keys()].some((key) => key.startsWith("mail:account-draft:v2:"))).toBe(false);
    expect([...kv.values.keys()].some((key) => key.startsWith("mail:account-vault:v2:"))).toBe(true);
    expect([...kv.values.keys()].some((key) => key.startsWith("mail:account-index:v2:"))).toBe(true);
    expect([...kv.values.keys()].some((key) => key.startsWith("mail:account-email-index:v2:"))).toBe(true);
  });

  it("unlocks an existing profile by matching the saved password without live verification", async () => {
    const kv = new MemoryKv();
    const environment = oauthEnv({ kv });
    const vault = await commitAccountDraft(environment, newAccountDraft(account()));
    const verify = vi.fn(async () => account());
    const authFetch = authFetchFor({ verifyAccountSubmission: verify });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    const passwordResponse = await authFetch(lookupForm(state, cookie), environment, context);
    const passwordPage = await pageModel(passwordResponse);
    expect(passwordPage.kind).toBe("account-form");
    if (passwordPage.kind === "account-form") {
      expect(passwordPage.step).toBe("password");
      expect(passwordPage.accountId).toBe(vault.defaultAccountId);
      expect(passwordPage.account.address).toBe("primary@icloud.com");
      expect(JSON.stringify(passwordPage)).not.toContain("imap.mail.me.com");
      expect(JSON.stringify(passwordPage)).not.toContain("smtp.mail.me.com");
      expect(JSON.stringify(passwordPage)).not.toContain("app-password");
    }
    expect(verify).not.toHaveBeenCalled();

    const response = await authFetch(unlockForm(state, cookie, vault.defaultAccountId), environment, context);
    const model = await pageModel(response);
    expect(response.status).toBe(200);
    expect(model.kind).toBe("management");
    if (model.kind === "management") expect(model.accounts[0]?.label).toBe("Personal");
    expect(model.message?.text).toContain("signed in");
    expect(model.title).toBe("Your accounts");
    expect(verify).not.toHaveBeenCalled();
    expect(JSON.stringify(model)).not.toContain(vault.userId);
  });

  it("rejects a wrong saved password without live verification", async () => {
    const kv = new MemoryKv();
    const environment = oauthEnv({ kv });
    const vault = await commitAccountDraft(environment, newAccountDraft(account()));
    const verify = vi.fn(async () => account());
    const authFetch = authFetchFor({ verifyAccountSubmission: verify });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    await authFetch(lookupForm(state, cookie), environment, context);

    const response = await authFetch(unlockForm(state, cookie, vault.defaultAccountId, "wrong-password"), environment, context);
    expect(response.status).toBe(401);
    expect((await pageModel(response)).message?.text).toContain("password didn't work");
    expect(verify).not.toHaveBeenCalled();
  });

  it("reuses the saved iCloud password while live-verifying an account edit", async () => {
    const kv = new MemoryKv();
    const environment = oauthEnv({ kv });
    const vault = await commitAccountDraft(environment, newAccountDraft(account()));
    const verify = vi.fn(async (_env, submission) => ({
      ...account(),
      accountId: vault.defaultAccountId,
      label: submission.label,
    }));
    const authFetch = authFetchFor({ verifyAccountSubmission: verify });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    await authFetch(lookupForm(state, cookie), environment, context);
    await authFetch(unlockForm(state, cookie, vault.defaultAccountId), environment, context);
    await authFetch(post(state, cookie, { action: "edit", account_id: vault.defaultAccountId }), environment, context);

    const response = await authFetch(post(state, cookie, {
      action: "verify",
      target: "edit",
      account_id: vault.defaultAccountId,
      preset: "icloud",
      label: "Renamed",
      address: "primary@icloud.com",
      service_options_present: "1",
      enable_mail: "1",
    }), environment, context);

    expect(response.status).toBe(200);
    expect(verify).toHaveBeenCalledOnce();
    expect(verify.mock.calls[0]?.[1].appPassword).toBe("app-password");
    const model = await pageModel(response);
    expect(model.kind).toBe("management");
    if (model.kind === "management") expect(model.accounts[0]?.label).toBe("Renamed");
  });

  it("returns a generic verification error and enforces the five-attempt limit", async () => {
    const environment = oauthEnv();
    const authFetch = authFetchFor({
      verifyAccountSubmission: vi.fn(async () => { throw new MailCredentialError("specific upstream failure"); }),
    });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    await authFetch(lookupForm(state, cookie), environment, context);
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      const response = await authFetch(initialAccountForm(state, cookie), environment, context);
      expect(response.status).toBe(401);
      expect((await pageModel(response)).message?.text).toContain("couldn't sign in");
    }
    const final = await authFetch(initialAccountForm(state, cookie), environment, context);
    expect(final.status).toBe(401);
    expect(await final.json()).toEqual({ error: "Account verification failed too many times" });
    expect(final.headers.get("Set-Cookie")).toContain("Max-Age=0");
  });

  it("denies authorization and deletes OAuth state and account drafts", async () => {
    const kv = new MemoryKv();
    await kv.put("mail:credentials:v1:sentinel", "keep");
    const environment = oauthEnv({ kv });
    const authFetch = authFetchFor({ verifyAccountSubmission: vi.fn(async () => account()) });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), environment, context);
    const { state, cookie } = stateAndCookie(authorize);
    await authFetch(lookupForm(state, cookie), environment, context);
    await authFetch(initialAccountForm(state, cookie), environment, context);
    const denied = await authFetch(post(state, cookie, { decision: "deny" }, []), environment, context);
    expect(denied.status).toBe(302);
    expect(denied.headers.get("Location")).toContain("error=access_denied");
    expect(kv.values.has("mail:credentials:v1:sentinel")).toBe(true);
    expect([...kv.values.keys()].some((key) => key.startsWith("mail-oauth:state:"))).toBe(false);
    expect([...kv.values.keys()].some((key) => key.startsWith("mail:account-draft:v2:"))).toBe(false);
  });

  it("returns a configuration error when the encryption secret is invalid", async () => {
    const response = await authFetchFor()(new Request("https://mcp.example/authorize"), oauthEnv({ encryptionKey: "short" }), context);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "Mail credential storage is not configured" });
  });
});
