import {
  AuthorizationError,
  type AuthRequest,
} from "@cloudflare/workers-oauth-provider";
import { z } from "zod";
import { getCredentialsEncryptionSecret } from "./config";
import {
  MailCredentialError,
  storeMailCredentials,
  verifyMailCredentials,
} from "./credentials";
import { RESOURCE_SCOPES, type MailCredentials, type OAuthEnv } from "./types";

const AUTH_STATE_TTL_SECONDS = 600;
const MAX_AUTH_ATTEMPTS = 5;
const MAX_FORM_BYTES = 16 * 1024;
const STATE_KEY_PREFIX = "mail-oauth:state:";
const STATE_COOKIE_NAME = "mcp_oauth_state";
const AUTH_SCOPES = [...RESOURCE_SCOPES, "offline_access"] as const;

interface StoredAuthState {
  request: AuthRequest;
  clientName: string;
  attempts: number;
}

export interface CredentialAuthDependencies {
  verifyCredentials?: (env: OAuthEnv, input: unknown, scopes: readonly string[]) => Promise<MailCredentials>;
  storeCredentials?: (env: OAuthEnv, credentials: MailCredentials) => Promise<string>;
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
  const encodedSecret = new TextEncoder().encode(secret);
  const key = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(encodedSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(signature));
}

async function verifyState(value: string, signature: string, secret: string): Promise<boolean> {
  try {
    const encodedSecret = new TextEncoder().encode(secret);
    const key = await crypto.subtle.importKey(
      "raw",
      asArrayBuffer(encodedSecret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
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

function sameOriginFormSubmission(request: Request): boolean {
  const origin = request.headers.get("Origin");
  const requestOrigin = new URL(request.url).origin;
  if (origin) return origin === requestOrigin;
  const referer = request.headers.get("Referer");
  if (!referer) return false;
  try {
    return new URL(referer).origin === requestOrigin;
  } catch {
    return false;
  }
}

function secureCookieAttribute(request: Request): string {
  return new URL(request.url).protocol === "https:" ? "; Secure" : "";
}

function stateCookieName(state: string): string {
  return `${STATE_COOKIE_NAME}_${state}`;
}

function sameSiteCookieAttribute(request: Request): string {
  return new URL(request.url).protocol === "https:" ? "; SameSite=None" : "; SameSite=Lax";
}

function stateCookie(request: Request, state: string, signature: string): string {
  return `${stateCookieName(state)}=${state}.${signature}; Max-Age=${AUTH_STATE_TTL_SECONDS}; Path=/authorize; HttpOnly${sameSiteCookieAttribute(request)}${secureCookieAttribute(request)}`;
}

function clearStateCookie(request: Request, state: string): string {
  return `${stateCookieName(state)}=; Max-Age=0; Path=/authorize; HttpOnly${sameSiteCookieAttribute(request)}${secureCookieAttribute(request)}`;
}

function redirectWithCookie(url: string, cookie: string): Response {
  const redirect = Response.redirect(url, 302);
  const headers = new Headers(redirect.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("Set-Cookie", cookie);
  return new Response(null, { status: redirect.status, headers });
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

function asStoredState(value: unknown): StoredAuthState | null {
  const parsed = storedStateSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function requestedScopes(request: AuthRequest): Array<(typeof AUTH_SCOPES)[number]> {
  return AUTH_SCOPES.filter((scope) => request.scope.includes(scope));
}

function resourceScopes(scopes: readonly string[]): string[] {
  return scopes.filter((scope) => (RESOURCE_SCOPES as readonly string[]).includes(scope));
}

function scopeLabel(scope: (typeof AUTH_SCOPES)[number]): string {
  if (scope === "mail.read") return "Read and search mail, messages, and attachments";
  if (scope === "mail.write") return "Change flags, move/delete messages, and send mail";
  if (scope === "calendar.read") return "Read calendars, events, and reminders";
  if (scope === "calendar.write") return "Create, update, and delete calendar events and reminders";
  if (scope === "contacts.read") return "Read contacts and address books";
  if (scope === "contacts.write") return "Create, update, and delete contacts";
  return "Keep the connection active with refresh tokens";
}

function renderLoginPage(
  state: string,
  stored: StoredAuthState,
  errorMessage?: string,
  emailValue = "",
): string {
  const requested = new Set(requestedScopes(stored.request));
  const scopeInputs = AUTH_SCOPES.map((scope) => {
    const isRequested = requested.has(scope);
    const unavailable = isRequested ? "" : " disabled";
    const availability = isRequested ? "" : " <small class=\"hint\">Not requested by this client</small>";
    return `
        <label class="scope">
          <input type="checkbox" name="scope" value="${escapeHtml(scope)}"${isRequested ? " checked" : ""}${unavailable}>
          <span><strong>${escapeHtml(scope)}</strong>${availability}<br>${escapeHtml(scopeLabel(scope))}</span>
        </label>`;
  }).join("");
  const error = errorMessage ? `<p class="error" role="alert">${escapeHtml(errorMessage)}</p>` : "";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Authorize iCloud MCP</title>
    <style>
      :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f6f8; color: #172033; }
      main { width: min(36rem, calc(100% - 2rem)); box-sizing: border-box; padding: 2rem; border: 1px solid #d9dde7; border-radius: 1rem; background: white; box-shadow: 0 1rem 3rem #17203318; }
      h1 { margin-top: 0; font-size: 1.5rem; }
      p { line-height: 1.5; }
      .scope { display: flex; gap: .75rem; align-items: flex-start; padding: .75rem; margin: .5rem 0; border: 1px solid #d9dde7; border-radius: .6rem; }
      .scope input { margin-top: .25rem; }
      label[for="icloud_email"], label[for="icloud_app_password"] { display: block; margin-top: 1.25rem; font-weight: 600; }
      input[type="email"], input[type="password"] { box-sizing: border-box; width: 100%; margin-top: .5rem; padding: .7rem; border: 1px solid #aeb5c5; border-radius: .5rem; font: inherit; }
      .hint { color: #526078; font-size: .92rem; }
      .actions { display: flex; gap: .75rem; margin-top: 1.5rem; }
      button { flex: 1; padding: .7rem 1rem; border: 0; border-radius: .5rem; font: inherit; cursor: pointer; }
      button[value="approve"] { background: #2563eb; color: white; }
      button[value="deny"] { background: #e7eaf0; color: #172033; }
      .error { padding: .75rem; border-radius: .5rem; background: #fee2e2; color: #991b1b; }
      @media (prefers-color-scheme: dark) { body { background: #111827; color: #eef2ff; } main { background: #1f2937; border-color: #4b5563; } .scope { border-color: #4b5563; } input[type="email"], input[type="password"] { background: #111827; color: #eef2ff; border-color: #6b7280; } button[value="deny"] { background: #374151; color: #eef2ff; } .error { background: #451a1a; color: #fecaca; } .hint { color: #c0c9da; } }
    </style>
  </head>
  <body>
    <main>
      <h1>Authorize iCloud MCP</h1>
      <p><strong>${escapeHtml(stored.clientName || "MCP client")}</strong> is requesting access to this Worker.</p>
      ${error}
      <form method="post" action="/authorize">
        <input type="hidden" name="authorization_state" value="${escapeHtml(state)}">
        <p>Choose the permissions to grant. Disabled permissions were not requested by this MCP client; reconnect it after refreshing its OAuth configuration to request them.</p>
        ${scopeInputs}
        <label for="icloud_email">iCloud email address</label>
        <input id="icloud_email" name="icloud_email" type="email" autocomplete="username" maxlength="320" value="${escapeHtml(emailValue.slice(0, 320))}" required>
        <label for="icloud_app_password">Apple app-specific password</label>
        <input id="icloud_app_password" name="icloud_app_password" type="password" autocomplete="current-password" maxlength="256" required>
        <p class="hint">Use an Apple app-specific password, not your normal Apple Account password. The Worker verifies the requested iCloud services and stores the credentials encrypted.</p>
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

function assertCredentialConfiguration(env: OAuthEnv): void {
  getCredentialsEncryptionSecret(env);
  if (!env.MAIL_CREDENTIALS_KV) throw new Error("MAIL_CREDENTIALS_KV binding is not configured");
}

async function beginCredentialAuthorization(request: Request, env: OAuthEnv): Promise<Response> {
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
  if (!resourceScopes(requestedScopes(oauthRequest)).length) {
    return errorRedirect(oauthRequest, "invalid_scope", "Request at least one supported iCloud permission");
  }

  assertCredentialConfiguration(env);
  const secret = getCredentialsEncryptionSecret(env);
  const state = randomToken(32);
  const signature = await signState(state, secret);
  const stored: StoredAuthState = {
    request: oauthRequest,
    clientName: client.clientName?.slice(0, 256) || "MCP client",
    attempts: 0,
  };
  await env.OAUTH_KV.put(`${STATE_KEY_PREFIX}${state}`, JSON.stringify(stored), {
    expirationTtl: AUTH_STATE_TTL_SECONDS,
  });
  return htmlResponse(renderLoginPage(state, stored), 200, stateCookie(request, state, signature));
}

async function completeCredentialAuthorization(
  request: Request,
  env: OAuthEnv,
  dependencies: Required<CredentialAuthDependencies>,
): Promise<Response> {
  assertCredentialConfiguration(env);
  const form = await readForm(request);
  const stateToken = form.get("authorization_state")?.trim() ?? "";
  if (!stateToken || !/^[A-Za-z0-9_-]{32,128}$/u.test(stateToken)) return jsonError("Invalid authorization state", 400);

  const secret = getCredentialsEncryptionSecret(env);
  const cookie = cookieValue(request, stateCookieName(stateToken));
  const [cookieState, cookieSignature] = cookie?.split(".") ?? [];
  const cookieValid = cookieState === stateToken && Boolean(cookieSignature) && await verifyState(stateToken, cookieSignature, secret);
  if (!cookieValid && !sameOriginFormSubmission(request)) {
    return jsonError("Invalid authorization state", 400);
  }

  const stored = asStoredState(await env.OAUTH_KV.get(`${STATE_KEY_PREFIX}${stateToken}`, "json"));
  if (!stored) return jsonError("Expired authorization state", 400);

  if (form.get("decision") !== "approve") {
    await env.OAUTH_KV.delete(`${STATE_KEY_PREFIX}${stateToken}`);
    const denial = errorRedirect(stored.request, "access_denied", "Authorization was denied");
    return redirectWithCookie(
      denial.headers.get("Location") ?? stored.request.redirectUri,
      clearStateCookie(request, stateToken),
    );
  }

  const selectedScopes = new Set(form.getAll("scope"));
  const grantedScopes = requestedScopes(stored.request).filter((scope) => selectedScopes.has(scope));
  const grantedResourceScopes = resourceScopes(grantedScopes);
  if (!grantedResourceScopes.length) {
    return htmlResponse(
      renderLoginPage(stateToken, stored, "Select at least one iCloud permission.", form.get("icloud_email") ?? ""),
      400,
      stateCookie(request, stateToken, cookieSignature),
    );
  }

  const email = form.get("icloud_email") ?? "";
  const appPassword = form.get("icloud_app_password") ?? "";
  let credentials: MailCredentials;
  try {
    credentials = await dependencies.verifyCredentials(env, { email, appPassword }, grantedResourceScopes);
  } catch (error) {
    if (!(error instanceof MailCredentialError)) throw error;
    const attempts = stored.attempts + 1;
    if (attempts >= MAX_AUTH_ATTEMPTS) {
      await env.OAUTH_KV.delete(`${STATE_KEY_PREFIX}${stateToken}`);
      const response = jsonError("iCloud credential verification failed too many times", 401);
      response.headers.set("Set-Cookie", clearStateCookie(request, stateToken));
      return response;
    }
    const nextState = { ...stored, attempts };
    await env.OAUTH_KV.put(`${STATE_KEY_PREFIX}${stateToken}`, JSON.stringify(nextState), {
      expirationTtl: AUTH_STATE_TTL_SECONDS,
    });
    return htmlResponse(
      renderLoginPage(
        stateToken,
        nextState,
        "The iCloud credentials could not be verified. Check the email and app-specific password.",
        email,
      ),
      401,
      stateCookie(request, stateToken, cookieSignature),
    );
  }

  const credentialId = await dependencies.storeCredentials(env, credentials);
  const props = {
    userId: credentialId,
    credentialId,
    scopes: grantedResourceScopes,
  };
  const result = await env.OAUTH_PROVIDER.completeAuthorization({
    request: stored.request,
    userId: credentialId,
    metadata: { clientName: stored.clientName },
    scope: grantedScopes,
    props,
  });
  await env.OAUTH_KV.delete(`${STATE_KEY_PREFIX}${stateToken}`);
  return redirectWithCookie(result.redirectTo, clearStateCookie(request, stateToken));
}

function isCredentialConfigurationError(error: unknown): boolean {
  return error instanceof Error && (
    error.message.startsWith("Missing Worker secret or variable: MAIL_CREDENTIALS_ENCRYPTION_KEY") ||
    error.message.startsWith("MAIL_CREDENTIALS_ENCRYPTION_KEY must") ||
    error.message === "MAIL_CREDENTIALS_KV binding is not configured"
  );
}

export function createCredentialAuthHandler(dependencies: CredentialAuthDependencies = {}): ExportedHandler<OAuthEnv> {
  const resolved: Required<CredentialAuthDependencies> = {
    verifyCredentials: dependencies.verifyCredentials ?? ((env, input, scopes) => verifyMailCredentials(env, input, scopes)),
    storeCredentials: dependencies.storeCredentials ?? storeMailCredentials,
  };
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      try {
        if (url.pathname === "/authorize") {
          if (request.method === "GET") return await beginCredentialAuthorization(request, env);
          if (request.method === "POST") return await completeCredentialAuthorization(request, env, resolved);
          return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
        }
        if (url.pathname === "/" && (request.method === "GET" || request.method === "HEAD")) {
          return Response.json({ name: "icloud-mail-mcp", endpoint: "/mcp", status: "ok" });
        }
        return new Response("Not found", { status: 404 });
      } catch (error) {
        if (isCredentialConfigurationError(error)) return jsonError("Mail credential storage is not configured", 503);
        return jsonError("OAuth authorization failed", 502);
      }
    },
  };
}

export const credentialAuthHandler = createCredentialAuthHandler();
