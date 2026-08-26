import { describe, expect, it, vi } from "vitest";
import type { AuthRequest, CompleteAuthorizationOptions, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { accessHandler } from "../src/access";
import { restrictMailPropsToTokenScope, type AppEnv } from "../src/types";

class MemoryKv {
  private readonly values = new Map<string, string>();

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

  keys(): string[] {
    return [...this.values.keys()];
  }
}

function oauthRequest(): AuthRequest {
  return {
    responseType: "code",
    clientId: "client-1",
    redirectUri: "https://client.example/callback",
    scope: ["mail.read", "offline_access"],
    state: "client-state",
    codeChallenge: "client-challenge",
    codeChallengeMethod: "S256",
  };
}

function oauthEnv(kv: MemoryKv, completeAuthorization?: OAuthHelpers["completeAuthorization"]): AppEnv {
  const request = oauthRequest();
  const helpers = {
    parseAuthRequest: async () => request,
    lookupClient: async () => ({
      clientId: request.clientId,
      redirectUris: [request.redirectUri],
      tokenEndpointAuthMethod: "none",
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
    ACCESS_CLIENT_ID: "access-client",
    ACCESS_CLIENT_SECRET: "access-secret",
    ACCESS_TOKEN_URL: "https://access.example/token",
    ACCESS_AUTHORIZATION_URL: "https://access.example/authorize",
    ACCESS_JWKS_URL: "https://access.example/jwks",
    COOKIE_ENCRYPTION_KEY: "test-cookie-key",
    MCP_ALLOWED_EMAIL: "owner@icloud.com",
    ICLOUD_EMAIL: "owner@icloud.com",
    ICLOUD_IMAP_USER: "owner",
    ICLOUD_APP_PASSWORD: "app-password",
  };
}

const accessFetch = accessHandler.fetch as unknown as (
  request: Request,
  env: AppEnv,
  ctx: ExecutionContext,
) => Promise<Response>;

describe("Cloudflare Access OAuth bridge", () => {
  it("restricts handler props to the scopes on each access token", () => {
    expect(restrictMailPropsToTokenScope(
      { userId: "access-subject", email: "owner@icloud.com", scopes: ["mail.read", "mail.write"] },
      ["mail.read", "offline_access"],
    )).toEqual({ userId: "access-subject", email: "owner@icloud.com", scopes: ["mail.read"] });
  });

  it("uses PKCE and one-time KV state without exposing iCloud credentials", async () => {
    const kv = new MemoryKv();
    const env = oauthEnv(kv);
    const response = await accessFetch(
      new Request("https://mcp.example/authorize?response_type=code&client_id=client-1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=mail.read%20offline_access&state=client-state&code_challenge=client-challenge&code_challenge_method=S256"),
      env,
      {} as unknown as ExecutionContext,
    );
    expect(response.status).toBe(302);
    const location = response.headers.get("Location");
    expect(location).toContain("code_challenge_method=S256");
    expect(location).toContain("login_hint=owner%40icloud.com");
    expect(response.headers.get("Set-Cookie")).toContain("HttpOnly");
    expect(kv.keys()).toHaveLength(1);
    expect(await response.text()).not.toContain("app-password");
  });

  it("rejects callback state without the bound cookie", async () => {
    const kv = new MemoryKv();
    const response = await accessFetch(
      new Request("https://mcp.example/callback?state=untrusted"),
      oauthEnv(kv),
      {} as unknown as ExecutionContext,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid OAuth state" });
  });

  it("verifies the Access ID token, enforces the email allowlist, and grants requested scopes", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const kv = new MemoryKv();
    const complete = vi.fn(async (_options: CompleteAuthorizationOptions) => ({ redirectTo: "https://client.example/callback?code=issued" }));
    const env = oauthEnv(kv, complete);
    const authorizeResponse = await accessFetch(
      new Request("https://mcp.example/authorize"),
      env,
      {} as unknown as ExecutionContext,
    );
    const authorizeLocation = new URL(authorizeResponse.headers.get("Location") ?? "https://invalid");
    const state = authorizeLocation.searchParams.get("state");
    const nonce = authorizeLocation.searchParams.get("nonce");
    const cookie = (authorizeResponse.headers.get("Set-Cookie") ?? "").split(";", 1)[0];
    expect(state).toBeTruthy();
    expect(nonce).toBeTruthy();
    const header = base64Url(JSON.stringify({ alg: "RS256", kid: "test-key" }));
    const payload = base64Url(JSON.stringify({
      sub: "access-subject",
      email: "owner@icloud.com",
      iss: "https://access.example",
      aud: "access-client",
      exp: Math.floor(Date.now() / 1000) + 300,
      nonce,
    }));
    const signingInput = `${header}.${payload}`;
    const signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      keyPair.privateKey,
      new TextEncoder().encode(signingInput),
    );
    const idToken = `${signingInput}.${base64Url(new Uint8Array(signature))}`;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === env.ACCESS_TOKEN_URL) return Response.json({ id_token: idToken });
      if (url === env.ACCESS_JWKS_URL) return Response.json({ keys: [{ ...publicJwk, kid: "test-key", alg: "RS256", use: "sig" }] });
      throw new Error("unexpected fetch");
    });
    try {
      const callback = await accessFetch(
        new Request(`https://mcp.example/callback?state=${encodeURIComponent(state ?? "")}&code=access-code`, { headers: { Cookie: cookie } }),
        env,
        {} as unknown as ExecutionContext,
      );
      expect(callback.status).toBe(302);
      expect(callback.headers.get("Location")).toBe("https://client.example/callback?code=issued");
      expect(complete).toHaveBeenCalledOnce();
      const options = complete.mock.calls[0][0];
      expect(options.scope).toEqual(["mail.read", "offline_access"]);
      expect(options.props).toMatchObject({ userId: "access-subject", email: "owner@icloud.com" });
      expect(options.props).not.toHaveProperty("accessToken");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

function base64Url(value: string | Uint8Array): string {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}
