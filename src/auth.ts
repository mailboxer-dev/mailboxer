import {
  AuthorizationError,
  type AuthRequest,
} from "@cloudflare/workers-oauth-provider";
import { z } from "zod";
import {
  AccountError,
  commitAccountDraft,
  deleteAccountDraft,
  findAccountDraft,
  findAccountDraftByEmail,
  loadAccountDraft,
  newAccountDraft,
  saveAccountDraft,
  verifyAccountSubmission,
  type AccountDraft,
  type AccountSubmission,
} from "./accounts";
import {
  detectAccountPreset,
  renderUiPage,
  renderAuthPage,
  type AccountFormModel,
  type AccountFormStep,
  type LandingPageModel,
} from "./auth-ui";
import { getCredentialsEncryptionSecret } from "./config";
import { MailCredentialError } from "./credentials";
import { logFailure } from "./diagnostics";
import { AccountDiscoveryError, discoverAccountSettings } from "./discovery";
import type { DiscoveredAccountSettings } from "./discovery/types";
import {
  RESOURCE_SCOPES,
  type OAuthEnv,
  type StoredMailAccount,
} from "./types";

const AUTH_STATE_TTL_SECONDS = 600;
const MAX_AUTH_ATTEMPTS = 5;
const MAX_FORM_BYTES = 16 * 1024;
const STATE_KEY_PREFIX = "mail-oauth:state:";
const STATE_COOKIE_NAME = "mcp_oauth_state";
const OPENAI_APPS_CHALLENGE = "wsetZFtnQmQTZWCkDGGthIkRpBFDj9yOks1V3O2yPO8";
const AUTH_SCOPES = [...RESOURCE_SCOPES, "offline_access"] as const;
const STATE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,128}$/u;
interface StoredAuthState {
  request: AuthRequest;
  clientName: string;
  attempts: number;
  grantedScopes?: string[];
}

export interface CredentialAuthDependencies {
  verifyAccountSubmission?: typeof verifyAccountSubmission;
  discoverAccountSettings?: typeof discoverAccountSettings;
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

function formActionSource(redirectUri: string): string {
  const redirect = new URL(redirectUri);
  // CSP cannot represent an opaque custom-scheme origin; the scheme is the
  // narrowest source expression available for those registered callbacks.
  return redirect.origin === "null" ? redirect.protocol : redirect.origin;
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

function isLocalDevelopmentRequest(request: Request): boolean {
  const url = new URL(request.url);
  return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}

function buildHtmlResponse(request: Request, body: string, formAction: string, status = 200, cookie?: string): Response {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "text/html; charset=utf-8",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  if (!isLocalDevelopmentRequest(request)) {
    headers.set(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self' ${formAction}; base-uri 'none'; frame-ancestors 'none'`,
    );
  }
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(body, { status, headers });
}

function landingPageModel(request: Request): LandingPageModel {
  const origin = new URL(request.url).origin;
  return {
    version: 1,
    kind: "landing",
    origin,
    mcpUrl: new URL("/mcp", origin).toString(),
    agentSetupUrl: new URL("/agent-setup/prompt.md", origin).toString(),
  };
}

function publicHeaders(request: Request, contentType: string): Headers {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": contentType,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  if (!isLocalDevelopmentRequest(request)) {
    headers.set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  }
  return headers;
}

function landingHtmlResponse(request: Request, body: string): Response {
  const headers = publicHeaders(request, "text/html; charset=utf-8");
  if (!isLocalDevelopmentRequest(request)) {
    headers.set(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
  }
  return new Response(request.method === "HEAD" ? null : body, { status: 200, headers });
}

function publicTextResponse(request: Request, body: string, contentType: string): Response {
  return new Response(request.method === "HEAD" ? null : body, {
    status: 200,
    headers: publicHeaders(request, contentType),
  });
}

function publicJsonResponse(request: Request, value: unknown): Response {
  return publicTextResponse(request, JSON.stringify(value), "application/json");
}

function methodNotAllowed(allow: string): Response {
  return new Response("Method not allowed", {
    status: 405,
    headers: {
      Allow: allow,
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function agentSetupPrompt(page: LandingPageModel): string {
  return `# Connect this agent to Mailboxer

You are helping the user connect their current AI agent to Mailboxer, which gives the agent access to the user's email, calendars, and contacts after the user signs in. Identify the agent you are running in and follow only the matching section below.

Mailboxer MCP address: \`${page.mcpUrl}\`

Each connection authorizes one account. To use more accounts, create separately named connections to this same address and sign in to each independently.

Do not ask the user for a mailbox password, request that they paste one into this chat, or handle one yourself. Mailboxer collects and protects sign-in details in its existing browser authorization flow.

## Codex CLI

Run these commands in the user's terminal:

\`\`\`sh
codex mcp add mailboxer --url ${page.mcpUrl}
codex mcp login mailboxer
\`\`\`

If the login command opens a browser, have the user finish signing in there. Keep the mailbox password in that browser flow.

## Pi

Run these commands in the user's terminal:

\`\`\`sh
pi mcp add mailboxer --url ${page.mcpUrl}
pi mcp login mailboxer
\`\`\`

Complete browser sign-in. Each connection authorizes one account. For additional accounts, repeat with a different connection name, such as \`mailboxer-work\`, and the same MCP address.

## Claude Code

Run this command in the user's terminal:

\`\`\`sh
claude mcp add --transport http --scope user mailboxer ${page.mcpUrl}
\`\`\`

Then have the user complete the browser sign-in when Claude Code requests authentication. The \`--scope user\` option keeps the connection available to the user's Claude Code sessions instead of writing a repository-local configuration.

## ChatGPT or Claude on the web

You cannot change the host app's connector settings from inside the conversation. Give the user these short manual steps instead:

1. In ChatGPT, open Settings → Apps, create a custom app, paste \`${page.mcpUrl}\`, and follow the sign-in prompt.
2. In Claude, open Settings → Connectors, add a custom connector, paste \`${page.mcpUrl}\`, and choose Connect.
3. Name the connection \`mailboxer\` and complete Mailboxer's browser sign-in when prompted.

For ChatGPT, use the [custom app and full MCP connector guide](https://help.openai.com/en/articles/12584461-developer-mode-apps-and-full-mcp-connectors-in-chatgpt-beta). For Claude, use [Anthropic's custom connector guide](https://support.anthropic.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp).

## Other compatible agents

Add a user-level remote MCP server named \`mailboxer\` with this address:

\`\`\`text
${page.mcpUrl}
\`\`\`

Prefer a user-level connection so the agent can use Mailboxer across projects. Do not create a repository-local configuration unless the user specifically asks for one.

## Verify the connection

After registration, confirm that a server named \`mailboxer\` is present and initialize it or list its available tools. If the agent reports that authorization is required, follow the browser sign-in page and then retry the connection. Tell the user whether registration succeeded and whether browser sign-in is still required.
`;
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
  caldavUrl: string;
  carddavUrl: string;
  davUser: string;
}

function firstValue(form: URLSearchParams | undefined, names: readonly string[]): string {
  if (!form) return "";
  for (const name of names) {
    const value = form.get(name);
    if (value !== null) return value;
  }
  return "";
}

function accountFormValues(
  form?: URLSearchParams,
  existing?: StoredMailAccount,
  defaults = { mail: true, calendar: false, contacts: false },
): AccountFormValues {
  const config = existing?.config;
  const serviceOptionsPresent = form?.get("service_options_present") === "1";
  const customFieldsPresent = form?.get("custom_fields_present") === "1";
  const presetValue = firstValue(form, ["preset"]);
  const address = firstValue(form, ["address", "email", "icloud_email"]) || existing?.address || "";
  const preset = presetValue === "custom" || (!presetValue && existing?.preset === "custom")
    ? "custom"
    : presetValue === "icloud" || existing?.preset === "icloud"
      ? "icloud"
      : address ? detectAccountPreset(address) : "icloud";
  return {
    preset,
    label: firstValue(form, ["label", "account_label"]) || existing?.label || "",
    address,
    enableMail: serviceOptionsPresent ? Boolean(form?.get("enable_mail")) : existing?.capabilities.mail ?? defaults.mail,
    enableCalendar: serviceOptionsPresent ? Boolean(form?.get("enable_calendar")) : existing?.capabilities.calendar ?? defaults.calendar,
    enableContacts: serviceOptionsPresent ? Boolean(form?.get("enable_contacts")) : existing?.capabilities.contacts ?? defaults.contacts,
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
    caldavUrl: firstValue(form, ["caldav_url"]) || existing?.davConfig?.caldavUrl || "",
    carddavUrl: firstValue(form, ["carddav_url"]) || existing?.davConfig?.carddavUrl || "",
    davUser: firstValue(form, ["dav_user"]) || existing?.davConfig?.username || config?.imapUser || address,
  };
}

function accountFormModel(
  form?: URLSearchParams,
  existing?: StoredMailAccount,
  defaults?: { mail: boolean; calendar: boolean; contacts: boolean },
): AccountFormModel {
  const values = accountFormValues(form, existing, defaults);
  return {
    preset: values.preset,
    label: values.label,
    address: values.address,
    services: {
      mail: values.enableMail,
      calendar: values.enableCalendar,
      contacts: values.enableContacts,
    },
    imap: {
      host: values.imapHost,
      port: values.imapPort,
      tlsMode: values.imapTlsMode,
      user: values.imapUser,
    },
    smtp: {
      host: values.smtpHost,
      port: values.smtpPort,
      tlsMode: values.smtpTlsMode,
      user: values.smtpUser,
      sameCredentials: values.sameSmtpCredentials,
    },
    dav: {
      calendarUrl: values.caldavUrl,
      contactsUrl: values.carddavUrl,
      user: values.davUser,
    },
  };
}

function renderStartPage(
  state: string,
  stored: StoredAuthState,
  errorMessage?: string,
  form?: URLSearchParams,
  step: AccountFormStep = "email",
): string {
  const scopes = requestedScopes(stored.request);
  return renderAuthPage({
    version: 1,
    kind: "account-form",
    title: step === "email" ? "Connect your email" : "Set up your account",
    clientName: stored.clientName,
    state,
    target: "start",
    step,
    account: accountFormModel(form, undefined, {
      mail: scopes.some((scope) => scope.startsWith("mail.")),
      calendar: scopes.some((scope) => scope.startsWith("calendar.")),
      contacts: scopes.some((scope) => scope.startsWith("contacts.")),
    }),
    ...(errorMessage ? { message: { kind: "error" as const, text: errorMessage } } : {}),
  });
}

function renderPasswordPage(
  state: string,
  stored: StoredAuthState,
  account: StoredMailAccount,
  errorMessage?: string,
): string {
  const accountModel = accountFormModel(undefined, account);
  return renderAuthPage({
    version: 1,
    kind: "account-form",
    title: "Welcome back",
    clientName: stored.clientName,
    state,
    target: "start",
    step: "password",
    account: {
      ...accountModel,
      label: "",
      imap: { host: "", port: "993", tlsMode: "implicit", user: "" },
      smtp: { host: "", port: "587", tlsMode: "starttls", user: "", sameCredentials: true },
      dav: { calendarUrl: "", contactsUrl: "", user: "" },
    },
    ...(errorMessage ? { message: { kind: "error" as const, text: errorMessage } } : {}),
  });
}

function renderNewAccountPasswordPage(
  state: string,
  stored: StoredAuthState,
  address: string,
  errorMessage?: string,
): string {
  const form = new URLSearchParams({ address, preset: detectAccountPreset(address) });
  return renderAuthPage({
    version: 1,
    kind: "account-form",
    title: "Connect your account",
    clientName: stored.clientName,
    state,
    target: "start",
    step: "new-password",
    account: accountFormModel(form, undefined, { mail: false, calendar: false, contacts: false }),
    ...(errorMessage ? { message: { kind: "error" as const, text: errorMessage } } : {}),
  });
}

function applyDiscoveredSettings(form: URLSearchParams, settings: DiscoveredAccountSettings, password: string): void {
  const preset = detectAccountPreset(form.get("address") ?? "");
  form.set("preset", preset);
  form.set("label", settings.providerName);
  form.set("service_options_present", "1");
  form.delete("enable_mail");
  form.delete("enable_calendar");
  form.delete("enable_contacts");
  if (settings.mail) form.set("enable_mail", "1");
  if (settings.caldavUrl) form.set("enable_calendar", "1");
  if (settings.carddavUrl) form.set("enable_contacts", "1");
  if (preset === "icloud") {
    form.set("app_password", password);
    return;
  }
  form.set("custom_fields_present", "1");
  form.set("same_smtp_credentials", "1");
  form.set("imap_password", password);
  if (settings.mail) {
    form.set("imap_host", settings.mail.imapHost);
    form.set("imap_port", String(settings.mail.imapPort));
    form.set("imap_tls_mode", settings.mail.imapTlsMode);
    form.set("imap_user", settings.mail.imapUser);
    form.set("smtp_host", settings.mail.smtpHost);
    form.set("smtp_port", String(settings.mail.smtpPort));
    form.set("smtp_tls_mode", settings.mail.smtpTlsMode);
    form.set("smtp_user", settings.mail.smtpUser);
  }
  if (settings.caldavUrl) form.set("caldav_url", settings.caldavUrl);
  if (settings.carddavUrl) form.set("carddav_url", settings.carddavUrl);
  form.set("dav_user", settings.davUser);
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
  if (!env.OAUTH_KV) throw new Error("OAUTH_KV binding is not configured");
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
  if (preset !== "icloud" && preset !== "custom") throw new AccountError("Select a supported account provider");
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
    caldavUrl: firstValue(form, ["caldav_url"]) || undefined,
    carddavUrl: firstValue(form, ["carddav_url"]) || undefined,
    davUser: firstValue(form, ["dav_user"]) || undefined,
  };
}

async function storedAccountPasswordMatches(account: StoredMailAccount, password: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const candidate = account.preset === "icloud" ? password.trim() : password;
  const subtle = crypto.subtle as SubtleCrypto & {
    timingSafeEqual(a: ArrayBuffer | ArrayBufferView, b: ArrayBuffer | ArrayBufferView): boolean;
  };
  const [candidateDigest, storedDigest] = await Promise.all([
    subtle.digest("SHA-256", encoder.encode(candidate)),
    subtle.digest("SHA-256", encoder.encode(account.config.password)),
  ]);
  return subtle.timingSafeEqual(candidateDigest, storedDigest);
}

function automaticallyGrantedScopes(stored: StoredAuthState): string[] {
  return requestedScopes(stored.request);
}

function stateCookieFor(request: Request, state: string, secret: string): Promise<string> {
  return signState(state, secret).then((signature) => stateCookie(request, state, signature));
}

function isVerificationError(error: unknown): boolean {
  return error instanceof MailCredentialError || error instanceof AccountError || error instanceof z.ZodError;
}

function verificationFailureMessage(error?: unknown): string {
  if (error instanceof AccountError && error.message.startsWith("We couldn't connect ")) {
    return `${error.message}. Check those settings or turn off that service.`;
  }
  return "We couldn't sign in. Check the details and try again.";
}

async function beginCredentialAuthorization(request: Request, env: OAuthEnv): Promise<Response> {
  const htmlResponse = (body: string, formAction: string, status = 200, cookie?: string): Response =>
    buildHtmlResponse(request, body, formAction, status, cookie);
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
  return htmlResponse(
    renderStartPage(state, stored),
    formActionSource(oauthRequest.redirectUri),
    200,
    await stateCookieFor(request, state, secret),
  );
}

async function completeAuthorization(
  request: Request,
  env: OAuthEnv,
  dependencies: Required<CredentialAuthDependencies>,
): Promise<Response> {
  const htmlResponse = (body: string, formAction: string, status = 200, cookie?: string): Response =>
    buildHtmlResponse(request, body, formAction, status, cookie);
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
  const callbackFormAction = formActionSource(stored.request.redirectUri);

  if (form.get("decision") === "deny") {
    await deleteWizardState(env, stateToken);
    const denial = errorRedirect(stored.request, "access_denied", "Authorization was denied");
    return redirectWithCookie(
      denial.headers.get("Location") ?? stored.request.redirectUri,
      clearStateCookie(request, stateToken),
    );
  }

  const selectedScopes = automaticallyGrantedScopes(stored);
  const grantedResourceScopes = resourceScopes(selectedScopes);
  const action = form.get("action") ?? "verify";
  async function finishAuthorization(draft: AccountDraft): Promise<Response> {
    const committed = await commitAccountDraft(env, draft);
    try {
      const result = await env.OAUTH_PROVIDER.completeAuthorization({
        request: stored!.request, userId: committed.userId, metadata: { clientName: stored!.clientName },
        scope: selectedScopes, props: { userId: committed.userId, accountVersion: 3, scopes: grantedResourceScopes },
      });
      return redirectWithCookie(result.redirectTo, clearStateCookie(request, stateToken));
    } finally {
      await deleteWizardState(env, stateToken);
    }
  }

  const stateWithSelection: StoredAuthState = { ...stored, grantedScopes: selectedScopes };

  if (action === "restart") {
    await deleteAccountDraft(env, stateToken);
    await persistAuthState(env, stateToken, stateWithSelection);
    return htmlResponse(
      renderStartPage(stateToken, stateWithSelection),
      callbackFormAction,
      200,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  if (action === "lookup") {
    const addressResult = z.string().trim().email().max(320).safeParse(form.get("address") ?? "");
    if (!addressResult.success) {
      return htmlResponse(
        renderStartPage(stateToken, stateWithSelection, "Enter a valid email address.", form),
        callbackFormAction,
        400,
        await stateCookieFor(request, stateToken, secret),
      );
    }
    const address = addressResult.data.toLowerCase();
    form.set("address", address);
    const existingDraft = await findAccountDraftByEmail(env, address);
    if (existingDraft) {
      const account = existingDraft.account;
      if (!account) throw new AccountError("The saved account could not be opened");
      await saveAccountDraft(env, stateToken, existingDraft);
      await persistAuthState(env, stateToken, stateWithSelection);
      return htmlResponse(
        renderPasswordPage(stateToken, stateWithSelection, account),
        callbackFormAction,
        200,
        await stateCookieFor(request, stateToken, secret),
      );
    }
    await persistAuthState(env, stateToken, stateWithSelection);
    return htmlResponse(
      renderNewAccountPasswordPage(stateToken, stateWithSelection, address),
      callbackFormAction,
      200,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  if (action === "new_password") {
    const draft = await loadAccountDraft(env, stateToken);
    if (!draft) return jsonError("Expired authorization state", 400);
    await deleteAccountDraft(env, stateToken);
    return htmlResponse(
      renderNewAccountPasswordPage(stateToken, stateWithSelection, draft.account.address),
      callbackFormAction,
      200,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  if (action === "unlock") {
    const draft = await loadAccountDraft(env, stateToken);
    if (!draft) return jsonError("Expired authorization state", 400);
    const account = draft.account;
    if (!account) throw new AccountError("The saved account could not be opened");
    try {
      const password = z.string().min(1).max(256).parse(form.get("account_password") ?? "");
      if (!await storedAccountPasswordMatches(account, password)) {
        throw new AccountError("The saved account password did not match");
      }
      return finishAuthorization(draft);
    } catch (error) {
      if (!isVerificationError(error)) throw error;
      const attempts = stored.attempts + 1;
      if (attempts >= MAX_AUTH_ATTEMPTS) {
        await deleteWizardState(env, stateToken);
        const response = jsonError("Too many failed attempts. Start again.", 401);
        response.headers.set("Set-Cookie", clearStateCookie(request, stateToken));
        return response;
      }
      const nextState = { ...stateWithSelection, attempts };
      await persistAuthState(env, stateToken, nextState);
      return htmlResponse(
        renderPasswordPage(stateToken, nextState, account, "That password didn't work. Try again."),
        callbackFormAction,
        401,
        await stateCookieFor(request, stateToken, secret),
      );
    }
  }

  if (action === "discover") {
    const addressResult = z.string().trim().email().max(320).safeParse(form.get("address") ?? "");
    const passwordResult = z.string().min(1).max(256).safeParse(form.get("new_account_password") ?? "");
    if (!addressResult.success || !passwordResult.success) {
      const address = addressResult.success ? addressResult.data.toLowerCase() : "";
      return htmlResponse(
        renderNewAccountPasswordPage(stateToken, stateWithSelection, address, "Enter your account password."),
        callbackFormAction,
        400,
        await stateCookieFor(request, stateToken, secret),
      );
    }
    const address = addressResult.data.toLowerCase();
    form.set("address", address);
    try {
      const settings = await dependencies.discoverAccountSettings(address);
      applyDiscoveredSettings(form, settings, passwordResult.data);
    } catch (error) {
      if (!(error instanceof AccountDiscoveryError)) {
        logFailure("account_discovery_failed", { operation: "autoconfigure" }, error);
      }
      form.set("preset", detectAccountPreset(address));
      form.set("label", address.split("@").at(-1) ?? "Email");
      form.set("service_options_present", "1");
      return htmlResponse(
        renderStartPage(stateToken, stateWithSelection, "We couldn't find all of your settings. Add or correct them below.", form, "config"),
        callbackFormAction,
        200,
        await stateCookieFor(request, stateToken, secret),
      );
    }
  }

  if (action !== "verify" && action !== "discover") return jsonError("Unknown authorization action", 400);
  const submission = accountSubmissionFromForm(form);
  let verifiedAccount: StoredMailAccount;
  try {
    verifiedAccount = await dependencies.verifyAccountSubmission(env, submission, {});
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
    return htmlResponse(
      renderStartPage(stateToken, nextState, verificationFailureMessage(error), form, "config"),
      callbackFormAction,
      401,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  const existing = await findAccountDraft(env, verifiedAccount);
  const draft = existing ? { ...existing, account: { ...verifiedAccount, accountId: existing.account.accountId } } : newAccountDraft(verifiedAccount);
  return finishAuthorization(draft);
}

function isCredentialConfigurationError(error: unknown): boolean {
  return error instanceof Error && (
    error.message.startsWith("Missing Worker secret or variable: MAIL_CREDENTIALS_ENCRYPTION_KEY") ||
    error.message.startsWith("MAIL_CREDENTIALS_ENCRYPTION_KEY must") ||
    error.message === "OAUTH_KV binding is not configured"
  );
}

export function createCredentialAuthHandler(dependencies: CredentialAuthDependencies = {}): ExportedHandler<OAuthEnv> {
  const resolved: Required<CredentialAuthDependencies> = {
    verifyAccountSubmission: dependencies.verifyAccountSubmission ?? verifyAccountSubmission,
    discoverAccountSettings: dependencies.discoverAccountSettings ?? discoverAccountSettings,
  };
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      try {
        if (url.pathname === "/authorize") {
          if (request.method === "GET") return await beginCredentialAuthorization(request, env);
          if (request.method === "POST") return await completeAuthorization(request, env, resolved);
          return methodNotAllowed("GET, POST");
        }
        if (url.pathname === "/") {
          if (request.method === "GET" || request.method === "HEAD") {
            return landingHtmlResponse(request, renderUiPage(landingPageModel(request)));
          }
          return methodNotAllowed("GET, HEAD");
        }
        if (url.pathname === "/agent-setup/prompt.md") {
          if (request.method === "GET" || request.method === "HEAD") {
            return publicTextResponse(
              request,
              agentSetupPrompt(landingPageModel(request)),
              "text/markdown; charset=utf-8",
            );
          }
          return methodNotAllowed("GET, HEAD");
        }
        if (url.pathname === "/.well-known/openai-apps-challenge") {
          if (request.method === "GET" || request.method === "HEAD") {
            return publicTextResponse(request, OPENAI_APPS_CHALLENGE, "text/plain; charset=utf-8");
          }
          return methodNotAllowed("GET, HEAD");
        }
        if (url.pathname === "/health") {
          if (request.method === "GET" || request.method === "HEAD") {
            return publicJsonResponse(request, { name: "email-mcp", endpoint: "/mcp", status: "ok" });
          }
          return methodNotAllowed("GET, HEAD");
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
