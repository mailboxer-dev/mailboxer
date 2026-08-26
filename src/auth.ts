import {
  AuthorizationError,
  type AuthRequest,
} from "@cloudflare/workers-oauth-provider";
import { z } from "zod";
import { getOwnerLoginSecret } from "./config";
import { MAIL_SCOPES, OWNER_USER_ID, type OAuthEnv } from "./types";

const AUTH_STATE_TTL_SECONDS = 600;
const MAX_AUTH_ATTEMPTS = 5;
const MAX_FORM_BYTES = 16 * 1024;
const STATE_KEY_PREFIX = "owner:state:";
const STATE_COOKIE_NAME = "mcp_owner_state";
const AUTH_SCOPES = [...MAIL_SCOPES, "offline_access"] as const;

interface StoredOwnerAuthState {
  request: AuthRequest;
  clientName: string;
  attempts: number;
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

const storedStateSchema = z.object({
  request: authRequestSchema,
  clientName: z.string().max(256),
  attempts: z.number().int().min(0).max(MAX_AUTH_ATTEMPTS),
});

interface CloudflareSubtleCrypto extends SubtleCrypto {
  timingSafeEqual(a: ArrayBuffer | ArrayBufferView, b: ArrayBuffer | ArrayBufferView): boolean;
}

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

async function secretsMatch(candidate: string, expected: string): Promise<boolean> {
  const [candidateDigest, expectedDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(candidate)),
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(expected)),
  ]);
  const subtle = crypto.subtle as CloudflareSubtleCrypto;
  if (typeof subtle.timingSafeEqual === "function") return subtle.timingSafeEqual(candidateDigest, expectedDigest);
  const left = new Uint8Array(candidateDigest);
  const right = new Uint8Array(expectedDigest);
  let difference = left.length ^ right.length;
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get("Cookie") ?? "";
  for (const item of cookie.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === name) return rest.join("=") || null;
  }
  return null;
}

function secureCookieAttribute(request: Request): string {
  return new URL(request.url).protocol === "https:" ? "; Secure" : "";
}

function stateCookie(request: Request, state: string, signature: string): string {
  return `${STATE_COOKIE_NAME}=${state}.${signature}; Max-Age=${AUTH_STATE_TTL_SECONDS}; Path=/authorize; HttpOnly; SameSite=Lax${secureCookieAttribute(request)}`;
}

function clearStateCookie(request: Request): string {
  return `${STATE_COOKIE_NAME}=; Max-Age=0; Path=/authorize; HttpOnly; SameSite=Lax${secureCookieAttribute(request)}`;
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

function htmlResponse(body: string, status = 200, cookie?: string): Response {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "Content-Type": "text/html; charset=utf-8",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(body, { status, headers });
}

function escapeHtml(value: string): string {
  const entities: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return value.replace(/[&<>"']/gu, (character) => entities[character]);
}

function asStoredState(value: unknown): StoredOwnerAuthState | null {
  const parsed = storedStateSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function requestedScopes(request: AuthRequest): Array<(typeof AUTH_SCOPES)[number]> {
  return AUTH_SCOPES.filter((scope) => request.scope.includes(scope));
}

function scopeLabel(scope: (typeof AUTH_SCOPES)[number]): string {
  if (scope === "mail.read") return "Read and search mail, messages, and attachments";
  if (scope === "mail.write") return "Change flags, move/delete messages, and send mail";
  return "Keep the connection active with refresh tokens";
}

function renderLoginPage(
  state: string,
  stored: StoredOwnerAuthState,
  errorMessage?: string,
): string {
  const scopes = requestedScopes(stored.request);
  const scopeInputs = scopes.map((scope) => `
        <label class="scope">
          <input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked>
          <span><strong>${escapeHtml(scope)}</strong><br>${escapeHtml(scopeLabel(scope))}</span>
        </label>`).join("");
  const error = errorMessage ? `<p class="error" role="alert">${escapeHtml(errorMessage)}</p>` : "";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Authorize iCloud Mail MCP</title>
    <style>
      :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f6f8; color: #172033; }
      main { width: min(36rem, calc(100% - 2rem)); box-sizing: border-box; padding: 2rem; border: 1px solid #d9dde7; border-radius: 1rem; background: white; box-shadow: 0 1rem 3rem #17203318; }
      h1 { margin-top: 0; font-size: 1.5rem; }
      p { line-height: 1.5; }
      .scope { display: flex; gap: .75rem; align-items: flex-start; padding: .75rem; margin: .5rem 0; border: 1px solid #d9dde7; border-radius: .6rem; }
      .scope input { margin-top: .25rem; }
      label[for="secret"] { display: block; margin-top: 1.25rem; font-weight: 600; }
      input[type="password"] { box-sizing: border-box; width: 100%; margin-top: .5rem; padding: .7rem; border: 1px solid #aeb5c5; border-radius: .5rem; font: inherit; }
      .actions { display: flex; gap: .75rem; margin-top: 1.5rem; }
      button { flex: 1; padding: .7rem 1rem; border: 0; border-radius: .5rem; font: inherit; cursor: pointer; }
      button[value="approve"] { background: #2563eb; color: white; }
      button[value="deny"] { background: #e7eaf0; color: #172033; }
      .error { padding: .75rem; border-radius: .5rem; background: #fee2e2; color: #991b1b; }
      @media (prefers-color-scheme: dark) { body { background: #111827; color: #eef2ff; } main { background: #1f2937; border-color: #4b5563; } .scope { border-color: #4b5563; } input[type="password"] { background: #111827; color: #eef2ff; border-color: #6b7280; } button[value="deny"] { background: #374151; color: #eef2ff; } .error { background: #451a1a; color: #fecaca; } }
    </style>
  </head>
  <body>
    <main>
      <h1>Authorize iCloud Mail MCP</h1>
      <p><strong>${escapeHtml(stored.clientName || "MCP client")}</strong> is requesting access to this Worker.</p>
      ${error}
      <form method="post" action="/authorize">
        <input type="hidden" name="authorization_state" value="${escapeHtml(state)}">
        <p>Choose the permissions to grant:</p>
        ${scopeInputs}
        <label for="secret">Deployment login secret</label>
        <input id="secret" name="login_secret" type="password" autocomplete="current-password" required maxlength="256">
        <div class="actions">
          <button type="submit" name="decision" value="deny">Cancel</button>
          <button type="submit" name="decision" value="approve">Authorize</button>
        </div>
      </form>
    </main>
  </body>
</html>`;
}

async function readBoundedBody(request: Request): Promise<Uint8Array> {
  const declaredLength = Number(request.headers.get("Content-Length") ?? "");
  if (Number.isFinite(declaredLength) && declaredLength > MAX_FORM_BYTES) {
    throw new Error("Authorization form is too large");
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > MAX_FORM_BYTES) {
      await reader.cancel();
      throw new Error("Authorization form is too large");
    }
    chunks.push(value);
  }
  reader.releaseLock();
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function readForm(request: Request): Promise<URLSearchParams> {
  const contentType = (request.headers.get("Content-Type") ?? "").split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/x-www-form-urlencoded") {
    throw new Error("Authorization form must use urlencoded data");
  }
  return new URLSearchParams(new TextDecoder().decode(await readBoundedBody(request)));
}

async function beginOwnerAuthorization(request: Request, env: OAuthEnv): Promise<Response> {
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
  if (!requestedScopes(oauthRequest).some((scope) => (MAIL_SCOPES as readonly string[]).includes(scope))) {
    return errorRedirect(oauthRequest, "invalid_scope", "Request mail.read or mail.write");
  }

  const secret = getOwnerLoginSecret(env);
  const state = randomToken(32);
  const signature = await signState(state, secret);
  const stored: StoredOwnerAuthState = {
    request: oauthRequest,
    clientName: client.clientName?.slice(0, 256) || "MCP client",
    attempts: 0,
  };
  await env.OAUTH_KV.put(`${STATE_KEY_PREFIX}${state}`, JSON.stringify(stored), {
    expirationTtl: AUTH_STATE_TTL_SECONDS,
  });
  return htmlResponse(renderLoginPage(state, stored), 200, stateCookie(request, state, signature));
}

async function completeOwnerAuthorization(request: Request, env: OAuthEnv): Promise<Response> {
  const form = await readForm(request);
  const stateToken = form.get("authorization_state")?.trim() ?? "";
  if (!stateToken || !/^[A-Za-z0-9_-]{32,128}$/u.test(stateToken)) return jsonError("Invalid authorization state", 400);

  const secret = getOwnerLoginSecret(env);
  const cookie = cookieValue(request, STATE_COOKIE_NAME);
  const [cookieState, cookieSignature] = cookie?.split(".") ?? [];
  if (cookieState !== stateToken || !cookieSignature || !(await verifyState(stateToken, cookieSignature, secret))) {
    return jsonError("Invalid authorization state", 400);
  }

  const stored = asStoredState(await env.OAUTH_KV.get(`${STATE_KEY_PREFIX}${stateToken}`, "json"));
  if (!stored) return jsonError("Expired authorization state", 400);

  if (form.get("decision") !== "approve") {
    await env.OAUTH_KV.delete(`${STATE_KEY_PREFIX}${stateToken}`);
    return redirectWithCookie(
      errorRedirect(stored.request, "access_denied", "Authorization was denied").headers.get("Location") ?? stored.request.redirectUri,
      clearStateCookie(request),
    );
  }

  const loginSecret = form.get("login_secret") ?? "";
  if (loginSecret.length > 256 || !(await secretsMatch(loginSecret, secret))) {
    const attempts = stored.attempts + 1;
    if (attempts >= MAX_AUTH_ATTEMPTS) {
      await env.OAUTH_KV.delete(`${STATE_KEY_PREFIX}${stateToken}`);
      const response = jsonError("Owner authentication failed", 401);
      response.headers.set("Set-Cookie", clearStateCookie(request));
      return response;
    }
    const nextState = { ...stored, attempts };
    await env.OAUTH_KV.put(`${STATE_KEY_PREFIX}${stateToken}`, JSON.stringify(nextState), {
      expirationTtl: AUTH_STATE_TTL_SECONDS,
    });
    return htmlResponse(
      renderLoginPage(stateToken, nextState, "The deployment login secret is incorrect."),
      401,
      stateCookie(request, stateToken, cookieSignature),
    );
  }

  const selectedScopes = new Set(form.getAll("scope"));
  const grantedScopes = requestedScopes(stored.request).filter((scope) => selectedScopes.has(scope));
  if (!grantedScopes.some((scope) => (MAIL_SCOPES as readonly string[]).includes(scope))) {
    return htmlResponse(renderLoginPage(stateToken, stored, "Select at least one mail permission."), 400, stateCookie(request, stateToken, cookieSignature));
  }

  await env.OAUTH_KV.delete(`${STATE_KEY_PREFIX}${stateToken}`);
  const result = await env.OAUTH_PROVIDER.completeAuthorization({
    request: stored.request,
    userId: OWNER_USER_ID,
    metadata: { clientName: stored.clientName },
    scope: grantedScopes,
    props: {
      userId: OWNER_USER_ID,
      scopes: grantedScopes.filter((scope) => (MAIL_SCOPES as readonly string[]).includes(scope)),
    },
  });
  return redirectWithCookie(result.redirectTo, clearStateCookie(request));
}

function isLoginConfigurationError(error: unknown): boolean {
  return error instanceof Error && (
    error.message.startsWith("Missing Worker secret") ||
    error.message.startsWith("MCP_LOGIN_SECRET must")
  );
}

export const ownerAuthHandler: ExportedHandler<OAuthEnv> = {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/authorize") {
        if (request.method === "GET") return await beginOwnerAuthorization(request, env);
        if (request.method === "POST") return await completeOwnerAuthorization(request, env);
        return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
      }
      if (url.pathname === "/" && (request.method === "GET" || request.method === "HEAD")) {
        return Response.json({ name: "icloud-mail-mcp", endpoint: "/mcp", status: "ok" });
      }
      return new Response("Not found", { status: 404 });
    } catch (error) {
      if (isLoginConfigurationError(error)) return jsonError("Owner login is not configured", 503);
      console.error(JSON.stringify({ event: "oauth.authorization_failed", error: error instanceof Error ? error.name : "unknown" }));
      return jsonError("OAuth authorization failed", 502);
    }
  },
};
