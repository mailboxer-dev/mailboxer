import {
  AuthorizationError,
  type AuthRequest,
} from "@cloudflare/workers-oauth-provider";
import { z } from "zod";
import { assertAllowedEmail } from "./config";
import { MAIL_SCOPES, type MailAuthProps, type OAuthEnv } from "./types";

const ACCESS_STATE_TTL_SECONDS = 600;
const ACCESS_SCOPE = "openid email profile";

interface StoredAccessState {
  request: AuthRequest;
  codeVerifier: string;
  nonce: string;
}

const authRequestSchema = z.object({
  responseType: z.string(),
  clientId: z.string(),
  redirectUri: z.string(),
  scope: z.array(z.string()),
  state: z.string(),
  codeChallenge: z.string().optional(),
  codeChallengeMethod: z.string().optional(),
  resource: z.union([z.string(), z.array(z.string())]).optional(),
  issuer: z.string().optional(),
});

const accessTokenResponseSchema = z.object({
  id_token: z.string().min(1),
});

const jwkSchema = z.object({
  kty: z.literal("RSA"),
  kid: z.string().min(1),
  n: z.string().min(1),
  e: z.string().min(1),
  alg: z.string().optional(),
  use: z.string().optional(),
});

const jwksSchema = z.object({ keys: z.array(jwkSchema) });

const accessClaimsSchema = z.object({
  sub: z.string().min(1),
  email: z.string().optional(),
  preferred_username: z.string().optional(),
  name: z.string().optional(),
  iss: z.string().min(1),
  aud: z.union([z.string(), z.array(z.string())]),
  exp: z.number().int().positive(),
  nonce: z.string().optional(),
});

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function randomToken(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function createCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

async function signState(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(signature));
}

async function verifyState(value: string, signature: string, secret: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      "HMAC",
      key,
      asArrayBuffer(base64UrlDecode(signature)),
      new TextEncoder().encode(value),
    );
  } catch {
    return false;
  }
}

function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("Cookie") ?? "";
  for (const item of cookie.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === name) return rest.join("=") || null;
  }
  return null;
}

function stateCookie(state: string, signature: string): string {
  return `mcp_access_state=${state}.${signature}; Max-Age=${ACCESS_STATE_TTL_SECONDS}; Path=/callback; HttpOnly; Secure; SameSite=Lax`;
}

function clearStateCookie(): string {
  return "mcp_access_state=; Max-Age=0; Path=/callback; HttpOnly; Secure; SameSite=Lax";
}

function redirectWithCookie(url: string, cookie: string): Response {
  return new Response(null, {
    status: 302,
    headers: {
      Location: url,
      "Cache-Control": "no-store",
      "Set-Cookie": cookie,
    },
  });
}

function errorRedirect(request: AuthRequest, code: string, description: string): Response {
  const redirect = new URL(request.redirectUri);
  redirect.searchParams.set("error", code);
  redirect.searchParams.set("error_description", description);
  if (request.state) redirect.searchParams.set("state", request.state);
  if (request.issuer) redirect.searchParams.set("iss", request.issuer);
  return new Response(null, {
    status: 302,
    headers: { Location: redirect.toString(), "Cache-Control": "no-store" },
  });
}

function jsonError(message: string, status: number): Response {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

function asStoredState(value: unknown): StoredAccessState | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const parsedRequest = authRequestSchema.safeParse(record.request);
  if (!parsedRequest.success || typeof record.codeVerifier !== "string" || typeof record.nonce !== "string") {
    return null;
  }
  return {
    request: parsedRequest.data,
    codeVerifier: record.codeVerifier,
    nonce: record.nonce,
  };
}

async function beginAccessAuthorization(request: Request, env: OAuthEnv): Promise<Response> {
  let oauthRequest: AuthRequest;
  try {
    oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  } catch (error) {
    if (!(error instanceof AuthorizationError)) throw error;
    if (!error.redirectUri) return jsonError(error.description, 400);
    return errorRedirect(
      {
        responseType: "code",
        clientId: "",
        redirectUri: error.redirectUri,
        scope: [],
        state: error.state ?? "",
        issuer: error.issuer,
      },
      error.code,
      error.description,
    );
  }

  const client = await env.OAUTH_PROVIDER.lookupClient(oauthRequest.clientId);
  if (!client) return jsonError("Unknown OAuth client", 400);
  if (oauthRequest.responseType !== "code") return jsonError("Only authorization code flow is supported", 400);
  if (oauthRequest.codeChallengeMethod !== "S256" || !oauthRequest.codeChallenge) {
    return errorRedirect(oauthRequest, "invalid_request", "PKCE S256 is required");
  }

  const codeVerifier = randomToken(48);
  const nonce = randomToken(32);
  const state = randomToken(32);
  const stateSignature = await signState(state, env.COOKIE_ENCRYPTION_KEY);
  const stored: StoredAccessState = { request: oauthRequest, codeVerifier, nonce };
  await env.OAUTH_KV.put(`access:state:${state}`, JSON.stringify(stored), {
    expirationTtl: ACCESS_STATE_TTL_SECONDS,
  });

  const authorization = new URL(env.ACCESS_AUTHORIZATION_URL);
  authorization.searchParams.set("response_type", "code");
  authorization.searchParams.set("client_id", env.ACCESS_CLIENT_ID);
  authorization.searchParams.set("redirect_uri", new URL("/callback", request.url).toString());
  authorization.searchParams.set("scope", ACCESS_SCOPE);
  authorization.searchParams.set("state", state);
  authorization.searchParams.set("code_challenge", await createCodeChallenge(codeVerifier));
  authorization.searchParams.set("code_challenge_method", "S256");
  authorization.searchParams.set("nonce", nonce);
  authorization.searchParams.set("login_hint", env.MCP_ALLOWED_EMAIL);
  return redirectWithCookie(authorization.toString(), stateCookie(state, stateSignature));
}

async function exchangeAccessCode(
  request: Request,
  env: OAuthEnv,
  code: string,
  state: StoredAccessState,
): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: env.ACCESS_CLIENT_ID,
    client_secret: env.ACCESS_CLIENT_SECRET,
    redirect_uri: new URL("/callback", request.url).toString(),
    code_verifier: state.codeVerifier,
  });
  const response = await fetch(env.ACCESS_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body,
  });
  if (!response.ok) throw new Error("Access authorization code exchange failed");
  const parsed = accessTokenResponseSchema.safeParse(await response.json());
  if (!parsed.success) throw new Error("Access did not return an OIDC ID token");
  return parsed.data.id_token;
}

function accessIssuer(env: OAuthEnv): string {
  const tokenEndpoint = new URL(env.ACCESS_TOKEN_URL);
  if (tokenEndpoint.protocol !== "https:" || !/\/token\/?$/u.test(tokenEndpoint.pathname)) {
    throw new Error("Access token endpoint must be an HTTPS OIDC token URL");
  }
  const issuerPath = tokenEndpoint.pathname.replace(/\/token\/?$/u, "").replace(/\/$/u, "");
  return `${tokenEndpoint.origin}${issuerPath}`;
}

async function verifyAccessIdToken(idToken: string, env: OAuthEnv, expectedNonce: string): Promise<MailAuthProps> {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Malformed Access ID token");
  const headerValue = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0]))) as unknown;
  const payloadValue = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1]))) as unknown;
  const header = z.object({ alg: z.literal("RS256"), kid: z.string().min(1) }).parse(headerValue);
  const claims = accessClaimsSchema.parse(payloadValue);
  if (claims.exp !== undefined && claims.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error("Access ID token is expired");
  }
  if (claims.iss !== accessIssuer(env)) throw new Error("Access ID token issuer mismatch");
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(env.ACCESS_CLIENT_ID)) throw new Error("Access ID token audience mismatch");
  if (claims.nonce !== expectedNonce) throw new Error("Access ID token nonce mismatch");
  const jwksResponse = await fetch(env.ACCESS_JWKS_URL, { headers: { Accept: "application/json" } });
  if (!jwksResponse.ok) throw new Error("Unable to load Access signing keys");
  const jwks = jwksSchema.parse(await jwksResponse.json());
  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
  if (!jwk) throw new Error("Access signing key was not found");
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    asArrayBuffer(base64UrlDecode(parts[2])),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) throw new Error("Access ID token signature is invalid");
  const email = (claims.email ?? claims.preferred_username ?? "").trim().toLowerCase();
  if (!email) throw new Error("Access identity did not include an email address");
  assertAllowedEmail(env, email);
  return { userId: claims.sub, email, scopes: [] };
}

async function completeAccessCallback(request: Request, env: OAuthEnv): Promise<Response> {
  const url = new URL(request.url);
  const stateToken = url.searchParams.get("state");
  if (!stateToken) return jsonError("Missing OAuth state", 400);
  const cookie = cookieValue(request, "mcp_access_state");
  const [cookieState, cookieSignature] = cookie?.split(".") ?? [];
  if (cookieState !== stateToken || !cookieSignature || !(await verifyState(stateToken, cookieSignature, env.COOKIE_ENCRYPTION_KEY))) {
    return jsonError("Invalid OAuth state", 400);
  }
  const storedValue = await env.OAUTH_KV.get(`access:state:${stateToken}`, "json");
  await env.OAUTH_KV.delete(`access:state:${stateToken}`);
  const stored = asStoredState(storedValue);
  if (!stored) return jsonError("Expired OAuth state", 400);
  const upstreamError = url.searchParams.get("error");
  if (upstreamError) {
    const response = errorRedirect(stored.request, upstreamError, url.searchParams.get("error_description") ?? "Access authorization failed");
    response.headers.append("Set-Cookie", clearStateCookie());
    return response;
  }
  const code = url.searchParams.get("code");
  if (!code) return jsonError("Missing Access authorization code", 400);
  const idToken = await exchangeAccessCode(request, env, code, stored);
  const identity = await verifyAccessIdToken(idToken, env, stored.nonce);
  const grantedScopes = [...new Set(
    stored.request.scope.filter((scope) =>
      (MAIL_SCOPES as readonly string[]).includes(scope) || scope === "offline_access",
    ),
  )];
  if (!grantedScopes.some((scope) => (MAIL_SCOPES as readonly string[]).includes(scope))) {
    const response = errorRedirect(stored.request, "invalid_scope", "Request mail.read or mail.write");
    response.headers.append("Set-Cookie", clearStateCookie());
    return response;
  }
  const result = await env.OAUTH_PROVIDER.completeAuthorization({
    request: stored.request,
    userId: identity.userId,
    metadata: { email: identity.email },
    scope: grantedScopes,
    props: { ...identity, scopes: grantedScopes },
  });
  return new Response(null, {
    status: 302,
    headers: {
      Location: result.redirectTo,
      "Cache-Control": "no-store",
      "Set-Cookie": clearStateCookie(),
    },
  });
}

export const accessHandler: ExportedHandler<OAuthEnv> = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/authorize" && request.method === "GET") return beginAccessAuthorization(request, env);
    if (url.pathname === "/callback" && request.method === "GET") {
      try {
        return await completeAccessCallback(request, env);
      } catch (error) {
        console.error(JSON.stringify({ event: "oauth.callback_failed", error: error instanceof Error ? error.name : "unknown" }));
        return jsonError("OAuth callback failed", 502);
      }
    }
    if (url.pathname === "/" && (request.method === "GET" || request.method === "HEAD")) {
      return Response.json({ name: "icloud-mail-mcp", endpoint: "/mcp", status: "ok" });
    }
    return new Response("Not found", { status: 404 });
  },
};
