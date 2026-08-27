import { describe, expect, it, vi } from "vitest";
import type {
  AuthRequest,
  CompleteAuthorizationOptions,
  OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import {
  createCredentialAuthHandler,
  type CredentialAuthDependencies,
} from "../src/auth";
import { MailCredentialError } from "../src/credentials";
import { restrictMailPropsToTokenScope, type AppEnv, type MailCredentials } from "../src/types";

class MemoryKv {
  private readonly values = new Map<string, string>();

  async put(key: string, value: string, _options?: unknown): Promise<void> {
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

  keys(): string[] {
    return [...this.values.keys()];
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

function oauthEnv(
  kv: MemoryKv,
  completeAuthorization?: OAuthHelpers["completeAuthorization"],
  encryptionKey = "a-secure-test-encryption-key-with-32-chars",
): AppEnv {
  const request = oauthRequest();
  const helpers = {
    parseAuthRequest: async () => request,
    lookupClient: async () => ({
      clientId: request.clientId,
      redirectUris: [request.redirectUri],
      tokenEndpointAuthMethod: "none",
      clientName: "Test <client>",
    }),
    completeAuthorization: completeAuthorization ?? (async () => ({ redirectTo: "https://client.example/callback?code=local" })),
  } as unknown as OAuthHelpers;
  return {
    OAUTH_KV: kv as unknown as KVNamespace,
    MAIL_CREDENTIALS_KV: new MemoryKv() as unknown as KVNamespace,
    OAUTH_PROVIDER: helpers,
    IMAP_HOST: "imap.mail.me.com",
    IMAP_PORT: "993",
    SMTP_HOST: "smtp.mail.me.com",
    SMTP_PORT: "587",
    MAIL_CREDENTIALS_ENCRYPTION_KEY: encryptionKey,
  };
}

function authFetchFor(dependencies?: CredentialAuthDependencies) {
  return createCredentialAuthHandler(dependencies).fetch as unknown as (
    request: Request,
    env: AppEnv,
    ctx: ExecutionContext,
  ) => Promise<Response>;
}

function context(): ExecutionContext {
  return {} as unknown as ExecutionContext;
}

function stateAndCookie(response: Response): { state: string; cookie: string } {
  const setCookie = response.headers.get("Set-Cookie") ?? "";
  const cookie = setCookie.split(";", 1)[0];
  const value = cookie.slice("mcp_oauth_state=".length);
  const [state] = value.split(".");
  return { state, cookie };
}

function authorizationForm(
  state: string,
  email = "owner@icloud.com",
  appPassword = "app-password",
  decision = "approve",
  scopes = ["mail.read"],
): Request {
  const body = new URLSearchParams({
    authorization_state: state,
    icloud_email: email,
    icloud_app_password: appPassword,
    decision,
  });
  for (const scope of scopes) body.append("scope", scope);
  return new Request("https://mcp.example/authorize", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
}

describe("iCloud credential OAuth authorization", () => {
  it("restricts handler props to the scopes on each access token", () => {
    expect(restrictMailPropsToTokenScope(
      { userId: "icloud-test-id", credentialId: "icloud-test-id", scopes: ["mail.read", "mail.write"] },
      ["mail.read", "offline_access"],
    )).toEqual({ userId: "icloud-test-id", credentialId: "icloud-test-id", scopes: ["mail.read"] });
  });

  it("renders a credential form with a signed, one-time state and no password", async () => {
    const kv = new MemoryKv();
    const response = await authFetchFor()(new Request("https://mcp.example/authorize"), oauthEnv(kv), context());
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Test &lt;client&gt;");
    expect(body).toContain('name="icloud_email"');
    expect(body).toContain('name="icloud_app_password"');
    expect(body).not.toContain("app-password");
    expect(body).not.toContain("MCP_LOGIN_SECRET");
    expect(response.headers.get("Set-Cookie")).toContain("HttpOnly");
    expect(response.headers.get("Set-Cookie")).toContain("Path=/authorize");
    expect(kv.keys()).toHaveLength(1);
  });

  it("rejects authorization POSTs without the bound state cookie", async () => {
    const kv = new MemoryKv();
    const response = await authFetchFor()(authorizationForm("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), oauthEnv(kv), context());
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid authorization state" });
  });

  it("does not issue a grant when iCloud credential verification fails", async () => {
    const kv = new MemoryKv();
    const verifyCredentials = vi.fn(async () => {
      throw new MailCredentialError("invalid credentials");
    });
    const storeCredentials = vi.fn(async () => "icloud-test-id");
    const env = oauthEnv(kv);
    const authFetch = authFetchFor({ verifyCredentials, storeCredentials });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), env, context());
    const { state, cookie } = stateAndCookie(authorize);
    const form = authorizationForm(state);
    form.headers.set("Cookie", cookie);

    const response = await authFetch(form, env, context());
    expect(response.status).toBe(401);
    expect(await response.text()).toContain("could not be verified");
    expect(verifyCredentials).toHaveBeenCalledWith(env, { email: "owner@icloud.com", appPassword: "app-password" });
    expect(storeCredentials).not.toHaveBeenCalled();
    expect(kv.keys()).toHaveLength(1);
  });

  it("stores credentials separately and issues a PKCE authorization code with opaque props", async () => {
    const kv = new MemoryKv();
    const complete = vi.fn(async (_options: CompleteAuthorizationOptions) => ({ redirectTo: "https://client.example/callback?code=issued" }));
    const credentials: MailCredentials = {
      email: "owner@icloud.com",
      imapUser: "owner",
      appPassword: "app-password",
    };
    const verifyCredentials = vi.fn(async () => credentials);
    const storeCredentials = vi.fn(async (_env: AppEnv, value: MailCredentials) => {
      expect(value).toEqual(credentials);
      return "icloud-test-id";
    });
    const env = oauthEnv(kv, complete);
    const authFetch = authFetchFor({ verifyCredentials, storeCredentials });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), env, context());
    const { state, cookie } = stateAndCookie(authorize);
    const form = authorizationForm(state, "owner@icloud.com", "app-password", "approve", ["mail.read", "offline_access"]);
    form.headers.set("Cookie", cookie);

    const response = await authFetch(form, env, context());
    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toBe("https://client.example/callback?code=issued");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect(kv.keys()).toHaveLength(0);
    expect(complete).toHaveBeenCalledOnce();

    const options = complete.mock.calls[0][0];
    expect(options.userId).toBe("icloud-test-id");
    expect(options.scope).toEqual(["mail.read", "offline_access"]);
    expect(options.props).toEqual({ userId: "icloud-test-id", credentialId: "icloud-test-id", scopes: ["mail.read"] });
    expect(JSON.stringify(options.props)).not.toContain("owner@icloud.com");
    expect(JSON.stringify(options.props)).not.toContain("app-password");
  });

  it("returns an OAuth denial and consumes the state when the user cancels", async () => {
    const kv = new MemoryKv();
    const verifyCredentials = vi.fn(async () => ({ email: "owner@icloud.com", imapUser: "owner", appPassword: "app-password" }));
    const env = oauthEnv(kv);
    const authFetch = authFetchFor({ verifyCredentials });
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), env, context());
    const { state, cookie } = stateAndCookie(authorize);
    const form = authorizationForm(state, "", "", "deny", []);
    form.headers.set("Cookie", cookie);

    const response = await authFetch(form, env, context());
    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toContain("error=access_denied");
    expect(response.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect(verifyCredentials).not.toHaveBeenCalled();
    expect(kv.keys()).toHaveLength(0);
  });

  it("returns a configuration error instead of throwing when encryption is not configured", async () => {
    const kv = new MemoryKv();
    const response = await authFetchFor()(new Request("https://mcp.example/authorize"), oauthEnv(kv, undefined, "short"), context());
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "Mail credential storage is not configured" });
  });
});
