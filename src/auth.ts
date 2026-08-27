import {
  AuthorizationError,
  type AuthRequest,
} from "@cloudflare/workers-oauth-provider";
import { z } from "zod";
import {
  AccountVaultError,
  addDraftAccount,
  commitAccountDraft,
  deleteAccountDraft,
  loadAccountDraft,
  newAccountDraft,
  removeDraftAccount,
  replaceDraftAccount,
  saveAccountDraft,
  setDraftDefault,
  unlockAccountDraft,
  verifyAccountSubmission,
  type AccountDraft,
  type AccountSubmission,
} from "./accounts";
import { getCredentialsEncryptionSecret } from "./config";
import { MailCredentialError } from "./credentials";
import { logFailure } from "./diagnostics";
import {
  RESOURCE_SCOPES,
  type AccountCapabilities,
  type OAuthEnv,
  type StoredMailAccount,
} from "./types";

const AUTH_STATE_TTL_SECONDS = 600;
const MAX_AUTH_ATTEMPTS = 5;
const MAX_FORM_BYTES = 16 * 1024;
const STATE_KEY_PREFIX = "mail-oauth:state:";
const STATE_COOKIE_NAME = "mcp_oauth_state";
const AUTH_SCOPES = [...RESOURCE_SCOPES, "offline_access"] as const;
const STATE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,128}$/u;

type WizardMode = "create" | "manage";
type AccountFormTarget = "start" | "add" | "edit";

interface StoredAuthState {
  request: AuthRequest;
  clientName: string;
  attempts: number;
  grantedScopes?: string[];
  mode?: WizardMode;
}

export interface CredentialAuthDependencies {
  verifyAccountSubmission?: typeof verifyAccountSubmission;
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
}).passthrough();

const storedStateSchema = z.object({
  request: authRequestSchema,
  clientName: z.string().max(256),
  attempts: z.number().int().min(0).max(MAX_AUTH_ATTEMPTS),
  grantedScopes: z.array(z.string()).max(AUTH_SCOPES.length).optional(),
  mode: z.enum(["create", "manage"]).optional(),
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
  return parsed.success ? parsed.data as StoredAuthState : null;
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

function scopeConsent(request: AuthRequest, selected: readonly string[]): string {
  const requested = requestedScopes(request);
  const selectedSet = new Set(selected);
  const inputs = requested.map((scope) => `
        <label class="scope">
          <input type="checkbox" name="scope" value="${escapeHtml(scope)}"${selectedSet.has(scope) ? " checked" : ""}>
          <span><strong>${escapeHtml(scope)}</strong><br>${escapeHtml(scopeLabel(scope))}</span>
        </label>`).join("");
  return `
      <fieldset>
        <legend>Permissions</legend>
        <p class="hint">Choose the permissions to grant to this Email MCP connection. Only permissions requested by the MCP client are shown.</p>
        <input type="hidden" name="scope_form" value="1">
        ${inputs}
      </fieldset>`;
}

interface AccountFormValues {
  preset: "icloud" | "custom";
  label: string;
  address: string;
  enableMail: boolean;
  enableCalendar: boolean;
  enableContacts: boolean;
  imapHost: string;
  imapPort: string;
  imapTlsMode: "implicit" | "starttls";
  imapUser: string;
  smtpHost: string;
  smtpPort: string;
  smtpTlsMode: "implicit" | "starttls";
  smtpUser: string;
  sameSmtpCredentials: boolean;
}

function firstValue(form: URLSearchParams | undefined, names: readonly string[]): string {
  if (!form) return "";
  for (const name of names) {
    const value = form.get(name);
    if (value !== null) return value;
  }
  return "";
}

function accountFormValues(form?: URLSearchParams, existing?: StoredMailAccount): AccountFormValues {
  const config = existing?.config;
  const serviceOptionsPresent = form?.get("service_options_present") === "1";
  const customFieldsPresent = form?.get("custom_fields_present") === "1";
  const presetValue = firstValue(form, ["preset"]);
  const preset = presetValue === "custom" || (!presetValue && existing?.preset === "custom") ? "custom" : "icloud";
  return {
    preset,
    label: firstValue(form, ["label", "account_label"]) || existing?.label || "",
    address: firstValue(form, ["address", "email", "icloud_email"]) || existing?.address || "",
    enableMail: serviceOptionsPresent ? Boolean(form?.get("enable_mail")) : existing?.capabilities.mail ?? true,
    enableCalendar: serviceOptionsPresent ? Boolean(form?.get("enable_calendar")) : existing?.capabilities.calendar ?? false,
    enableContacts: serviceOptionsPresent ? Boolean(form?.get("enable_contacts")) : existing?.capabilities.contacts ?? false,
    imapHost: firstValue(form, ["imap_host"]) || config?.imapHost || "",
    imapPort: firstValue(form, ["imap_port"]) || (config?.imapPort ? String(config.imapPort) : "993"),
    imapTlsMode: firstValue(form, ["imap_tls_mode"]) === "starttls" || config?.imapTlsMode === "starttls" ? "starttls" : "implicit",
    imapUser: firstValue(form, ["imap_user"]) || config?.imapUser || "",
    smtpHost: firstValue(form, ["smtp_host"]) || config?.smtpHost || "",
    smtpPort: firstValue(form, ["smtp_port"]) || (config?.smtpPort ? String(config.smtpPort) : "587"),
    smtpTlsMode: firstValue(form, ["smtp_tls_mode"]) === "implicit" || config?.smtpTlsMode === "implicit" ? "implicit" : "starttls",
    smtpUser: firstValue(form, ["smtp_user"]) || config?.smtpUser || "",
    sameSmtpCredentials: customFieldsPresent
      ? Boolean(form?.get("same_smtp_credentials"))
      : config ? config.smtpUser === config.imapUser && config.smtpPassword === config.password : true,
  };
}

function accountFields(form?: URLSearchParams, existing?: StoredMailAccount): string {
  const values = accountFormValues(form, existing);
  const checked = (value: boolean): string => value ? " checked" : "";
  const selected = (value: string, expected: string): string => value === expected ? " selected" : "";
  return `
        <label for="label">Account name</label>
        <input id="label" name="label" type="text" maxlength="80" value="${escapeHtml(values.label)}" required>
        <label for="address">Email address</label>
        <input id="address" name="address" type="email" autocomplete="username" maxlength="320" value="${escapeHtml(values.address)}" required>
        <label for="preset">Provider</label>
        <select id="preset" name="preset">
          <option value="icloud"${selected(values.preset, "icloud")}>iCloud preset</option>
          <option value="custom"${selected(values.preset, "custom")}>Custom IMAP/SMTP</option>
        </select>

        <fieldset>
          <legend>Services</legend>
          <input type="hidden" name="service_options_present" value="1">
          <label class="check"><input type="checkbox" name="enable_mail" value="1"${checked(values.enableMail)}> Mail</label>
          <label class="check"><input type="checkbox" name="enable_calendar" value="1"${checked(values.enableCalendar)}${values.preset === "custom" ? " disabled" : ""}> Calendar and reminders</label>
          <label class="check"><input type="checkbox" name="enable_contacts" value="1"${checked(values.enableContacts)}${values.preset === "custom" ? " disabled" : ""}> Contacts</label>
        </fieldset>

        <section class="provider-fields">
          <h2>iCloud preset</h2>
          <p class="hint">Uses iCloud IMAP, SMTP, CalDAV, and CardDAV endpoints. Use an Apple app-specific password.</p>
          <label for="app_password">Apple app-specific password</label>
          <input id="app_password" name="app_password" type="password" autocomplete="current-password" maxlength="256">
        </section>

        <section class="provider-fields">
          <h2>Custom IMAP/SMTP</h2>
          <input type="hidden" name="custom_fields_present" value="1">
          <label for="imap_host">IMAP hostname</label>
          <input id="imap_host" name="imap_host" type="text" maxlength="253" value="${escapeHtml(values.imapHost)}">
          <label for="imap_port">IMAP port</label>
          <input id="imap_port" name="imap_port" type="number" min="1" max="65535" value="${escapeHtml(values.imapPort)}">
          <label for="imap_tls_mode">IMAP TLS</label>
          <select id="imap_tls_mode" name="imap_tls_mode">
            <option value="implicit"${selected(values.imapTlsMode, "implicit")}>Implicit TLS (993)</option>
            <option value="starttls"${selected(values.imapTlsMode, "starttls")}>STARTTLS (143)</option>
          </select>
          <label for="imap_user">IMAP username</label>
          <input id="imap_user" name="imap_user" type="text" maxlength="320" value="${escapeHtml(values.imapUser)}">
          <label for="imap_password">IMAP password</label>
          <input id="imap_password" name="imap_password" type="password" autocomplete="current-password" maxlength="256">
          <label for="smtp_host">SMTP hostname</label>
          <input id="smtp_host" name="smtp_host" type="text" maxlength="253" value="${escapeHtml(values.smtpHost)}">
          <label for="smtp_port">SMTP port</label>
          <input id="smtp_port" name="smtp_port" type="number" min="1" max="65535" value="${escapeHtml(values.smtpPort)}">
          <label for="smtp_tls_mode">SMTP TLS</label>
          <select id="smtp_tls_mode" name="smtp_tls_mode">
            <option value="implicit"${selected(values.smtpTlsMode, "implicit")}>Implicit TLS (465)</option>
            <option value="starttls"${selected(values.smtpTlsMode, "starttls")}>STARTTLS (587 or 2525)</option>
          </select>
          <label for="smtp_user">SMTP username</label>
          <input id="smtp_user" name="smtp_user" type="text" maxlength="320" value="${escapeHtml(values.smtpUser)}">
          <label for="smtp_password">SMTP password</label>
          <input id="smtp_password" name="smtp_password" type="password" autocomplete="current-password" maxlength="256">
          <label class="check"><input type="checkbox" name="same_smtp_credentials" value="1"${checked(values.sameSmtpCredentials)}> Use the IMAP username and password for SMTP</label>
        </section>`;
}

function renderPageShell(title: string, clientName: string, content: string, errorMessage?: string): string {
  const error = errorMessage ? `<p class="error" role="alert">${escapeHtml(errorMessage)}</p>` : "";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>
      :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f6f8; color: #172033; }
      main { width: min(48rem, calc(100% - 2rem)); box-sizing: border-box; padding: 2rem; border: 1px solid #d9dde7; border-radius: 1rem; background: white; box-shadow: 0 1rem 3rem #17203318; }
      h1 { margin-top: 0; font-size: 1.5rem; } h2 { font-size: 1.05rem; margin-bottom: .5rem; }
      p { line-height: 1.5; } label { display: block; margin-top: 1rem; font-weight: 600; }
      fieldset { margin: 1.25rem 0; padding: .85rem; border: 1px solid #d9dde7; border-radius: .6rem; }
      legend { padding: 0 .35rem; font-weight: 700; } .scope { display: flex; gap: .75rem; align-items: flex-start; padding: .7rem; margin: .45rem 0; border: 1px solid #d9dde7; border-radius: .6rem; }
      .scope input, .check input { margin-top: .25rem; } .check { font-weight: 400; }
      input[type="email"], input[type="password"], input[type="text"], input[type="number"], select { box-sizing: border-box; width: 100%; margin-top: .4rem; padding: .65rem; border: 1px solid #aeb5c5; border-radius: .5rem; font: inherit; }
      .hint { color: #526078; font-size: .92rem; } .error { padding: .75rem; border-radius: .5rem; background: #fee2e2; color: #991b1b; }
      .provider-fields { border-top: 1px solid #e2e6ee; margin-top: 1.25rem; padding-top: .5rem; }
      .account { padding: .85rem; margin: .6rem 0; border: 1px solid #d9dde7; border-radius: .6rem; }
      .account strong { display: block; } .account-actions, .actions { display: flex; flex-wrap: wrap; gap: .6rem; margin-top: .75rem; }
      button { padding: .65rem 1rem; border: 0; border-radius: .5rem; font: inherit; cursor: pointer; } button.primary { background: #2563eb; color: white; }
      button.secondary { background: #e7eaf0; color: #172033; } button.danger { background: #b91c1c; color: white; }
      @media (prefers-color-scheme: dark) { body { background: #111827; color: #eef2ff; } main { background: #1f2937; border-color: #4b5563; } fieldset, .scope, .account { border-color: #4b5563; } input, select { background: #111827; color: #eef2ff; border-color: #6b7280; } .error { background: #451a1a; color: #fecaca; } .hint { color: #c0c9da; } button.secondary { background: #374151; color: #eef2ff; } }
    </style>
  </head>
  <body><main><h1>${escapeHtml(title)}</h1><p><strong>${escapeHtml(clientName || "MCP client")}</strong> is requesting access to this Email MCP.</p>${error}${content}</main></body>
</html>`;
}

function hiddenState(state: string, mode?: WizardMode, target?: AccountFormTarget, accountId?: string): string {
  return `<input type="hidden" name="authorization_state" value="${escapeHtml(state)}">${mode ? `<input type="hidden" name="mode" value="${mode}">` : ""}${target ? `<input type="hidden" name="target" value="${target}">` : ""}${accountId ? `<input type="hidden" name="account_id" value="${escapeHtml(accountId)}">` : ""}`;
}

function renderStartPage(
  state: string,
  stored: StoredAuthState,
  selectedScopes: readonly string[],
  errorMessage?: string,
  form?: URLSearchParams,
): string {
  const mode = firstValue(form, ["mode", "profile_mode"]) === "manage" ? "manage" : "create";
  const content = `<form method="post" action="/authorize">
        ${hiddenState(state, undefined, "start")}
        ${scopeConsent(stored.request, selectedScopes)}
        <label for="mode">Profile action</label>
        <select id="mode" name="mode">
          <option value="create"${mode === "create" ? " selected" : ""}>Create a new profile</option>
          <option value="manage"${mode === "manage" ? " selected" : ""}>Manage an existing profile</option>
        </select>
        <p class="hint">Create starts a new profile with the verified account. Manage unlocks an existing profile by verifying any one of its live accounts.</p>
        ${accountFields(form)}
        <div class="actions">
          <button class="secondary" type="submit" name="decision" value="deny">Cancel</button>
          <button class="primary" type="submit" name="action" value="verify">${mode === "manage" ? "Unlock profile" : "Verify and continue"}</button>
        </div>
      </form>`;
  return renderPageShell("Email MCP", stored.clientName, content, errorMessage);
}

function renderAccountFormPage(
  state: string,
  stored: StoredAuthState,
  draft: AccountDraft,
  target: "add" | "edit",
  selectedScopes: readonly string[],
  errorMessage?: string,
  form?: URLSearchParams,
  existing?: StoredMailAccount,
): string {
  const heading = target === "add" ? "Add an account" : "Edit an account";
  const content = `<form method="post" action="/authorize">
        ${hiddenState(state, "manage", target, existing?.accountId)}
        ${scopeConsent(stored.request, selectedScopes)}
        <p class="hint">Account changes are held in this encrypted reconnect draft until you choose Continue.</p>
        ${accountFields(form, existing)}
        <div class="actions">
          <button class="secondary" type="submit" name="action" value="list">Back to accounts</button>
          <button class="primary" type="submit" name="action" value="verify">Verify and save draft</button>
        </div>
      </form>`;
  return renderPageShell(heading, stored.clientName, content, errorMessage);
}

function capabilityText(capabilities: AccountCapabilities, selectedScopes: readonly string[]): string {
  const hasScope = (prefix: "mail" | "calendar" | "contacts"): boolean => selectedScopes.some((scope) => scope.startsWith(`${prefix}.`));
  const label = (name: string, prefix: "mail" | "calendar" | "contacts"): string => (
    hasScope(prefix) ? name : `${name} (unavailable until the MCP client requests its OAuth scope)`
  );
  return [
    capabilities.mail ? label("Mail", "mail") : "",
    capabilities.calendar ? label("Calendar", "calendar") : "",
    capabilities.contacts ? label("Contacts", "contacts") : "",
  ].filter(Boolean).join(", ");
}

function renderManagementPage(
  state: string,
  stored: StoredAuthState,
  draft: AccountDraft,
  selectedScopes: readonly string[],
  message?: string,
): string {
  const accountList = draft.accounts.map((account) => `<article class="account">
          <strong>${escapeHtml(account.label)}${account.accountId === draft.defaultAccountId ? " (default)" : ""}</strong>
          <span>${escapeHtml(account.address)}</span><br>
          <span class="hint">${escapeHtml(account.preset === "icloud" ? "iCloud preset" : "Custom IMAP/SMTP")} · ${escapeHtml(capabilityText(account.capabilities, selectedScopes) || "No services")}</span>
          <form class="account-actions" method="post" action="/authorize">
            ${hiddenState(state, "manage")}
            <input type="hidden" name="account_id" value="${escapeHtml(account.accountId)}">
            ${selectedScopes.map((scope) => `<input type="hidden" name="scope" value="${escapeHtml(scope)}">`).join("")}
            <input type="hidden" name="scope_form" value="1">
            <button class="secondary" type="submit" name="action" value="test">Test</button>
            <button class="secondary" type="submit" name="action" value="edit">Edit</button>
            ${account.accountId === draft.defaultAccountId ? "" : `<button class="secondary" type="submit" name="action" value="set_default">Make default</button>`}
            <button class="danger" type="submit" name="action" value="remove">Remove</button>
          </form>
        </article>`).join("");
  const content = `${message ? `<p class="hint" role="status">${escapeHtml(message)}</p>` : ""}
        <p>Manage the accounts attached to this Email MCP profile. The verified account details are stored encrypted; mailbox, calendar, and contact content is never stored here.</p>
        ${accountList}
        <form method="post" action="/authorize">
        ${hiddenState(state, "manage")}
        ${scopeConsent(stored.request, selectedScopes)}
        <div class="actions">
          <button class="secondary" type="submit" name="action" value="add">Add account</button>
          <button class="primary" type="submit" name="action" value="continue">Continue</button>
          <button class="secondary" type="submit" name="decision" value="deny">Cancel</button>
        </div>
      </form>`;
  return renderPageShell("Manage Email MCP accounts", stored.clientName, content);
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

async function persistAuthState(env: OAuthEnv, state: string, stored: StoredAuthState): Promise<void> {
  await env.OAUTH_KV.put(`${STATE_KEY_PREFIX}${state}`, JSON.stringify(stored), {
    expirationTtl: AUTH_STATE_TTL_SECONDS,
  });
}

async function deleteWizardState(env: OAuthEnv, state: string): Promise<void> {
  await Promise.all([
    env.OAUTH_KV.delete(`${STATE_KEY_PREFIX}${state}`),
    deleteAccountDraft(env, state),
  ]);
}

function accountSubmissionFromForm(form: URLSearchParams): AccountSubmission {
  const preset = firstValue(form, ["preset"]);
  if (preset !== "icloud" && preset !== "custom") throw new AccountVaultError("Select a supported account provider");
  const numberValue = (name: string): number | undefined => {
    const value = form.get(name);
    if (value === null || value.trim() === "") return undefined;
    return Number(value);
  };
  const serviceOptionsPresent = form.get("service_options_present") === "1";
  const customFieldsPresent = form.get("custom_fields_present") === "1";
  return {
    preset,
    label: firstValue(form, ["label", "account_label"]),
    address: firstValue(form, ["address", "email", "icloud_email"]),
    appPassword: firstValue(form, ["app_password", "icloud_app_password"]) || undefined,
    enableMail: serviceOptionsPresent ? form.has("enable_mail") : undefined,
    enableCalendar: serviceOptionsPresent ? form.has("enable_calendar") : undefined,
    enableContacts: serviceOptionsPresent ? form.has("enable_contacts") : undefined,
    imapHost: firstValue(form, ["imap_host"]) || undefined,
    imapPort: numberValue("imap_port"),
    imapTlsMode: firstValue(form, ["imap_tls_mode"]) === "starttls" ? "starttls" : firstValue(form, ["imap_tls_mode"]) === "implicit" ? "implicit" : undefined,
    imapUser: firstValue(form, ["imap_user"]) || undefined,
    imapPassword: firstValue(form, ["imap_password"]) || undefined,
    smtpHost: firstValue(form, ["smtp_host"]) || undefined,
    smtpPort: numberValue("smtp_port"),
    smtpTlsMode: firstValue(form, ["smtp_tls_mode"]) === "implicit" ? "implicit" : firstValue(form, ["smtp_tls_mode"]) === "starttls" ? "starttls" : undefined,
    smtpUser: firstValue(form, ["smtp_user"]) || undefined,
    smtpPassword: firstValue(form, ["smtp_password"]) || undefined,
    sameSmtpCredentials: customFieldsPresent ? form.has("same_smtp_credentials") : undefined,
  };
}

function accountSubmissionFromStored(account: StoredMailAccount): AccountSubmission {
  const { config } = account;
  if (account.preset === "icloud") {
    return {
      preset: "icloud",
      label: account.label,
      address: account.address,
      appPassword: config.password,
      enableMail: account.capabilities.mail,
      enableCalendar: account.capabilities.calendar,
      enableContacts: account.capabilities.contacts,
    };
  }
  return {
    preset: "custom",
    label: account.label,
    address: account.address,
    enableMail: account.capabilities.mail,
    enableCalendar: false,
    enableContacts: false,
    imapHost: config.imapHost,
    imapPort: config.imapPort,
    imapTlsMode: config.imapTlsMode,
    imapUser: config.imapUser,
    imapPassword: config.password,
    smtpHost: config.smtpHost,
    smtpPort: config.smtpPort,
    smtpTlsMode: config.smtpTlsMode,
    smtpUser: config.smtpUser,
    smtpPassword: config.smtpPassword,
    sameSmtpCredentials: config.smtpUser === config.imapUser && config.smtpPassword === config.password,
  };
}

function selectedScopesForForm(form: URLSearchParams, stored: StoredAuthState): string[] {
  const requested = requestedScopes(stored.request);
  const values = form.get("scope_form") === "1"
    ? form.getAll("scope")
    : stored.grantedScopes ?? requested;
  return requested.filter((scope) => values.includes(scope));
}

function stateCookieFor(request: Request, state: string, secret: string): Promise<string> {
  return signState(state, secret).then((signature) => stateCookie(request, state, signature));
}

function isVerificationError(error: unknown): boolean {
  return error instanceof MailCredentialError || error instanceof AccountVaultError || error instanceof z.ZodError;
}

function verificationFailureMessage(mode: WizardMode, target: AccountFormTarget): string {
  if (mode === "manage" && target === "start") return "The account profile could not be unlocked. Check the account details and try again.";
  return "The account could not be verified. Check the account details and try again.";
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
    return errorRedirect(oauthRequest, "invalid_scope", "Request at least one supported Email MCP permission");
  }

  assertCredentialConfiguration(env);
  const secret = getCredentialsEncryptionSecret(env);
  const state = randomToken(32);
  const stored: StoredAuthState = {
    request: oauthRequest,
    clientName: client.clientName?.slice(0, 256) || "MCP client",
    attempts: 0,
  };
  await persistAuthState(env, state, stored);
  return htmlResponse(renderStartPage(state, stored, requestedScopes(oauthRequest)), 200, await stateCookieFor(request, state, secret));
}

async function completeAuthorization(
  request: Request,
  env: OAuthEnv,
  dependencies: Required<CredentialAuthDependencies>,
): Promise<Response> {
  assertCredentialConfiguration(env);
  const form = await readForm(request);
  const stateToken = form.get("authorization_state")?.trim() ?? "";
  if (!STATE_TOKEN_PATTERN.test(stateToken)) return jsonError("Invalid authorization state", 400);

  const secret = getCredentialsEncryptionSecret(env);
  const cookie = cookieValue(request, stateCookieName(stateToken));
  const [cookieState, cookieSignature] = cookie?.split(".") ?? [];
  const cookieValid = cookieState === stateToken && Boolean(cookieSignature) && await verifyState(stateToken, cookieSignature, secret);
  if (!cookieValid && !sameOriginFormSubmission(request)) {
    return jsonError("Invalid authorization state", 400);
  }

  const stored = asStoredState(await env.OAUTH_KV.get(`${STATE_KEY_PREFIX}${stateToken}`, "json"));
  if (!stored) {
    await deleteAccountDraft(env, stateToken);
    return jsonError("Expired authorization state", 400);
  }

  if (form.get("decision") === "deny") {
    await deleteWizardState(env, stateToken);
    const denial = errorRedirect(stored.request, "access_denied", "Authorization was denied");
    return redirectWithCookie(
      denial.headers.get("Location") ?? stored.request.redirectUri,
      clearStateCookie(request, stateToken),
    );
  }

  const selectedScopes = selectedScopesForForm(form, stored);
  const grantedResourceScopes = resourceScopes(selectedScopes);
  if (!grantedResourceScopes.length) {
    return htmlResponse(
      renderStartPage(stateToken, stored, selectedScopes, "Select at least one requested permission.", form),
      400,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  const action = form.get("action") ?? "verify";
  const mode = form.get("mode") === "manage" || stored.mode === "manage" ? "manage" : "create";
  const targetValue = form.get("target");
  const target: AccountFormTarget = targetValue === "add" || targetValue === "edit" ? targetValue : "start";
  const stateWithSelection: StoredAuthState = { ...stored, grantedScopes: selectedScopes, mode };

  if (action === "add" || action === "edit") {
    const draft = await loadAccountDraft(env, stateToken);
    if (!draft) return jsonError("Expired authorization state", 400);
    const existing = action === "edit" ? draft.accounts.find((account) => account.accountId === (form.get("account_id") ?? "")) : undefined;
    const nextState = { ...stateWithSelection, mode: "manage" as const };
    await persistAuthState(env, stateToken, nextState);
    return htmlResponse(
      renderAccountFormPage(stateToken, nextState, draft, action, selectedScopes, undefined, undefined, existing),
      200,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  if (action === "list") {
    const draft = await loadAccountDraft(env, stateToken);
    if (!draft) return jsonError("Expired authorization state", 400);
    await persistAuthState(env, stateToken, stateWithSelection);
    return htmlResponse(
      renderManagementPage(stateToken, stateWithSelection, draft, selectedScopes),
      200,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  if (action === "remove" || action === "set_default" || action === "test" || action === "continue") {
    const draft = await loadAccountDraft(env, stateToken);
    if (!draft) return jsonError("Expired authorization state", 400);
    const accountId = form.get("account_id") ?? "";
    const account = draft.accounts.find((candidate) => candidate.accountId === accountId);
    try {
      if (action === "remove") {
        const nextDraft = removeDraftAccount(draft, accountId);
        await saveAccountDraft(env, stateToken, nextDraft);
        await persistAuthState(env, stateToken, stateWithSelection);
        return htmlResponse(
          renderManagementPage(stateToken, stateWithSelection, nextDraft, selectedScopes, "The account was removed from this draft."),
          200,
          await stateCookieFor(request, stateToken, secret),
        );
      }
      if (action === "set_default") {
        const nextDraft = setDraftDefault(draft, accountId);
        await saveAccountDraft(env, stateToken, nextDraft);
        await persistAuthState(env, stateToken, stateWithSelection);
        return htmlResponse(
          renderManagementPage(stateToken, stateWithSelection, nextDraft, selectedScopes, "The default account was updated in this draft."),
          200,
          await stateCookieFor(request, stateToken, secret),
        );
      }
      if (action === "test") {
        if (!account) throw new AccountVaultError("Unknown accountId");
        try {
          await dependencies.verifyAccountSubmission(env, accountSubmissionFromStored(account), {}, account.accountId);
        } catch (error) {
          if (!isVerificationError(error)) throw error;
          const attempts = stored.attempts + 1;
          if (attempts >= MAX_AUTH_ATTEMPTS) {
            await deleteWizardState(env, stateToken);
            const response = jsonError("Account verification failed too many times", 401);
            response.headers.set("Set-Cookie", clearStateCookie(request, stateToken));
            return response;
          }
          const nextState = { ...stateWithSelection, attempts };
          await persistAuthState(env, stateToken, nextState);
          return htmlResponse(
            renderManagementPage(stateToken, nextState, draft, selectedScopes, "The account could not be verified. Check its credentials and try again."),
            401,
            await stateCookieFor(request, stateToken, secret),
          );
        }
        await persistAuthState(env, stateToken, stateWithSelection);
        return htmlResponse(
          renderManagementPage(stateToken, stateWithSelection, draft, selectedScopes, "The account connection was verified."),
          200,
          await stateCookieFor(request, stateToken, secret),
        );
      }
      const committed = await commitAccountDraft(env, draft);
      try {
        const result = await env.OAUTH_PROVIDER.completeAuthorization({
          request: stored.request,
          userId: committed.userId,
          metadata: { clientName: stored.clientName },
          scope: selectedScopes,
          props: { userId: committed.userId, scopes: grantedResourceScopes },
        });
        return redirectWithCookie(result.redirectTo, clearStateCookie(request, stateToken));
      } finally {
        await deleteWizardState(env, stateToken);
      }
    } catch (error) {
      if (error instanceof AccountVaultError) {
        return htmlResponse(
          renderManagementPage(stateToken, stateWithSelection, draft, selectedScopes, error.message),
          409,
          await stateCookieFor(request, stateToken, secret),
        );
      }
      throw error;
    }
  }

  const submission = accountSubmissionFromForm(form);
  let verifiedAccount: StoredMailAccount;
  try {
    const existingId = target === "edit" ? form.get("account_id") ?? undefined : undefined;
    verifiedAccount = await dependencies.verifyAccountSubmission(env, submission, {}, existingId);
  } catch (error) {
    if (!isVerificationError(error)) throw error;
    const attempts = stored.attempts + 1;
    if (attempts >= MAX_AUTH_ATTEMPTS) {
      await deleteWizardState(env, stateToken);
      const response = jsonError("Account verification failed too many times", 401);
      response.headers.set("Set-Cookie", clearStateCookie(request, stateToken));
      return response;
    }
    const nextState: StoredAuthState = { ...stateWithSelection, attempts };
    await persistAuthState(env, stateToken, nextState);
    if (target === "add" || target === "edit") {
      const draft = await loadAccountDraft(env, stateToken);
      if (!draft) return jsonError("Expired authorization state", 400);
      const existing = target === "edit" ? draft.accounts.find((account) => account.accountId === (form.get("account_id") ?? "")) : undefined;
      return htmlResponse(
        renderAccountFormPage(stateToken, nextState, draft, target, selectedScopes, verificationFailureMessage(mode, target), form, existing),
        401,
        await stateCookieFor(request, stateToken, secret),
      );
    }
    return htmlResponse(
      renderStartPage(stateToken, nextState, selectedScopes, verificationFailureMessage(mode, target), form),
      401,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  let draft: AccountDraft;
  try {
    if (target === "start" && mode === "manage") {
      draft = await unlockAccountDraft(env, verifiedAccount);
    } else if (target === "start") {
      draft = newAccountDraft(verifiedAccount);
    } else {
      const existingDraft = await loadAccountDraft(env, stateToken);
      if (!existingDraft) return jsonError("Expired authorization state", 400);
      draft = target === "add"
        ? addDraftAccount(existingDraft, verifiedAccount)
        : replaceDraftAccount(existingDraft, verifiedAccount);
    }
  } catch (error) {
    if (!(error instanceof AccountVaultError)) throw error;
    const attempts = target === "start" ? stored.attempts + 1 : stored.attempts;
    if (attempts >= MAX_AUTH_ATTEMPTS) {
      await deleteWizardState(env, stateToken);
      const response = jsonError("Account verification failed too many times", 401);
      response.headers.set("Set-Cookie", clearStateCookie(request, stateToken));
      return response;
    }
    const nextState: StoredAuthState = { ...stateWithSelection, mode, attempts };
    await persistAuthState(env, stateToken, nextState);
    if (target === "start") {
      return htmlResponse(
        renderStartPage(stateToken, nextState, selectedScopes, "The account profile could not be unlocked. Check the account details and try again.", form),
        401,
        await stateCookieFor(request, stateToken, secret),
      );
    }
    const existingDraft = await loadAccountDraft(env, stateToken);
    if (!existingDraft) return jsonError("Expired authorization state", 400);
    const existing = target === "edit" ? existingDraft.accounts.find((account) => account.accountId === (form.get("account_id") ?? "")) : undefined;
    return htmlResponse(
      renderAccountFormPage(stateToken, nextState, existingDraft, target, selectedScopes, "The account could not be added to this profile.", form, existing),
      409,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  await saveAccountDraft(env, stateToken, draft);
  const nextState: StoredAuthState = { ...stateWithSelection, mode: "manage" };
  await persistAuthState(env, stateToken, nextState);
  return htmlResponse(
    renderManagementPage(stateToken, nextState, draft, selectedScopes, target === "start" ? "The account was verified. Review the profile, then Continue." : "The account changes were saved to this draft."),
    200,
    await stateCookieFor(request, stateToken, secret),
  );
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
    verifyAccountSubmission: dependencies.verifyAccountSubmission ?? verifyAccountSubmission,
  };
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      try {
        if (url.pathname === "/authorize") {
          if (request.method === "GET") return await beginCredentialAuthorization(request, env);
          if (request.method === "POST") return await completeAuthorization(request, env, resolved);
          return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
        }
        if (url.pathname === "/" && (request.method === "GET" || request.method === "HEAD")) {
          return Response.json({ name: "email-mcp", endpoint: "/mcp", status: "ok" });
        }
        return new Response("Not found", { status: 404 });
      } catch (error) {
        logFailure(
          "oauth_request_failed",
          { method: request.method, path: url.pathname },
          error,
        );
        if (isCredentialConfigurationError(error)) return jsonError("Mail credential storage is not configured", 503);
        return jsonError("OAuth authorization failed", 502);
      }
    },
  };
}

export const credentialAuthHandler = createCredentialAuthHandler();
