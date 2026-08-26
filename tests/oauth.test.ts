import { describe, expect, it, vi } from "vitest";
import type {
  AuthRequest,
  CompleteAuthorizationOptions,
  OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import { ownerAuthHandler } from "../src/auth";
import { restrictMailPropsToTokenScope, type AppEnv } from "../src/types";

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
  loginSecret = "a-secure-test-login-secret-with-32-chars",
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
    OAUTH_PROVIDER: helpers,
    IMAP_HOST: "imap.mail.me.com",
    IMAP_PORT: "993",
    SMTP_HOST: "smtp.mail.me.com",
    SMTP_PORT: "587",
    MCP_LOGIN_SECRET: loginSecret,
    ICLOUD_EMAIL: "owner@icloud.com",
    ICLOUD_IMAP_USER: "owner",
    ICLOUD_APP_PASSWORD: "app-password",
  };
}

const authFetch = ownerAuthHandler.fetch as unknown as (
  request: Request,
  env: AppEnv,
  ctx: ExecutionContext,
) => Promise<Response>;

function context(): ExecutionContext {
  return {} as unknown as ExecutionContext;
}

function stateAndCookie(response: Response): { state: string; cookie: string } {
  const setCookie = response.headers.get("Set-Cookie") ?? "";
  const cookie = setCookie.split(";", 1)[0];
  const value = cookie.slice("mcp_owner_state=".length);
  const [state] = value.split(".");
  return { state, cookie };
}

function authorizationForm(state: string, loginSecret: string, decision = "approve", scopes = ["mail.read"]): Request {
  const body = new URLSearchParams({
    authorization_state: state,
    login_secret: loginSecret,
    decision,
  });
  for (const scope of scopes) body.append("scope", scope);
  return new Request("https://mcp.example/authorize", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
}

describe("owner OAuth authorization", () => {
  it("restricts handler props to the scopes on each access token", () => {
    expect(restrictMailPropsToTokenScope(
      { userId: "owner", scopes: ["mail.read", "mail.write"] },
      ["mail.read", "offline_access"],
    )).toEqual({ userId: "owner", scopes: ["mail.read"] });
  });

  it("renders a local consent form with a signed, one-time state", async () => {
    const kv = new MemoryKv();
    const response = await authFetch(new Request("https://mcp.example/authorize"), oauthEnv(kv), context());
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain("Test &lt;client&gt;");
    expect(body).not.toContain("app-password");
    expect(response.headers.get("Set-Cookie")).toContain("HttpOnly");
    expect(response.headers.get("Set-Cookie")).toContain("Path=/authorize");
    expect(kv.keys()).toHaveLength(1);
  });

  it("rejects authorization POSTs without the bound state cookie", async () => {
    const kv = new MemoryKv();
    const response = await authFetch(
      authorizationForm("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "a-secure-test-login-secret-with-32-chars"),
      oauthEnv(kv),
      context(),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid authorization state" });
  });

  it("does not issue a grant when the deployment secret is wrong", async () => {
    const kv = new MemoryKv();
    const env = oauthEnv(kv);
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), env, context());
    const { state, cookie } = stateAndCookie(authorize);
    const form = authorizationForm(state, "wrong-deployment-secret");
    form.headers.set("Cookie", cookie);

    const response = await authFetch(form, env, context());
    expect(response.status).toBe(401);
    expect(await response.text()).toContain("incorrect");
    expect(kv.keys()).toHaveLength(1);
  });

  it("issues a PKCE authorization code without storing identity or iCloud credentials", async () => {
    const kv = new MemoryKv();
    const complete = vi.fn(async (_options: CompleteAuthorizationOptions) => ({ redirectTo: "https://client.example/callback?code=issued" }));
    const env = oauthEnv(kv, complete);
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), env, context());
    const { state, cookie } = stateAndCookie(authorize);
    const form = authorizationForm(state, "a-secure-test-login-secret-with-32-chars", "approve", ["mail.read", "offline_access"]);
    form.headers.set("Cookie", cookie);

    const response = await authFetch(form, env, context());
    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toBe("https://client.example/callback?code=issued");
    expect(response.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect(kv.keys()).toHaveLength(0);
    expect(complete).toHaveBeenCalledOnce();

    const options = complete.mock.calls[0][0];
    expect(options.userId).toBe("owner");
    expect(options.scope).toEqual(["mail.read", "offline_access"]);
    expect(options.props).toEqual({ userId: "owner", scopes: ["mail.read"] });
    expect(options.props).not.toHaveProperty("email");
    expect(options.props).not.toHaveProperty("appPassword");
  });

  it("returns an OAuth denial and consumes the state when the owner cancels", async () => {
    const kv = new MemoryKv();
    const env = oauthEnv(kv);
    const authorize = await authFetch(new Request("https://mcp.example/authorize"), env, context());
    const { state, cookie } = stateAndCookie(authorize);
    const form = authorizationForm(state, "", "deny");
    form.headers.set("Cookie", cookie);

    const response = await authFetch(form, env, context());
    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toContain("error=access_denied");
    expect(kv.keys()).toHaveLength(0);
  });

  it("refuses to start when the deployment login secret is missing or weak", async () => {
    const kv = new MemoryKv();
    const response = await authFetch(new Request("https://mcp.example/authorize"), oauthEnv(kv, undefined, "short"), context());
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "Owner login is not configured" });
  });
});
