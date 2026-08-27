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
  findAccountDraft,
  loadAccountDraft,
  newAccountDraft,
  removeDraftAccount,
  replaceDraftAccount,
  saveAccountDraft,
  setDraftDefault,
  verifyAccountSubmission,
  type AccountDraft,
  type AccountSubmission,
} from "./accounts";
import {
  renderAuthPage,
  type AccountFormModel,
  type AccountFormTarget,
} from "./auth-ui";
import { getCredentialsEncryptionSecret } from "./config";
import { MailCredentialError } from "./credentials";
import { logFailure } from "./diagnostics";
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

function htmlResponse(body: string, formAction: string, status = 200, cookie?: string): Response {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Security-Policy": `default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self' ${formAction}; base-uri 'none'; frame-ancestors 'none'`,
    "Content-Type": "text/html; charset=utf-8",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(body, { status, headers });
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
  const preset = presetValue === "custom" || (!presetValue && existing?.preset === "custom") ? "custom" : "icloud";
  return {
    preset,
    label: firstValue(form, ["label", "account_label"]) || existing?.label || "",
    address: firstValue(form, ["address", "email", "icloud_email"]) || existing?.address || "",
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
  };
}

function renderStartPage(
  state: string,
  stored: StoredAuthState,
  errorMessage?: string,
  form?: URLSearchParams,
): string {
  const scopes = requestedScopes(stored.request);
  return renderAuthPage({
    version: 1,
    kind: "account-form",
    title: "Connect Email MCP",
    clientName: stored.clientName,
    state,
    target: "start",
    account: accountFormModel(form, undefined, {
      mail: scopes.some((scope) => scope.startsWith("mail.")),
      calendar: scopes.some((scope) => scope.startsWith("calendar.")),
      contacts: scopes.some((scope) => scope.startsWith("contacts.")),
    }),
    draftNotice: false,
    ...(errorMessage ? { message: { kind: "error" as const, text: errorMessage } } : {}),
  });
}

function renderAccountFormPage(
  state: string,
  stored: StoredAuthState,
  target: "add" | "edit",
  errorMessage?: string,
  form?: URLSearchParams,
  existing?: StoredMailAccount,
): string {
  const heading = target === "add" ? "Add an account" : "Edit an account";
  return renderAuthPage({
    version: 1,
    kind: "account-form",
    title: heading,
    clientName: stored.clientName,
    state,
    target,
    ...(existing ? { accountId: existing.accountId } : {}),
    account: accountFormModel(form, existing),
    draftNotice: true,
    ...(errorMessage ? { message: { kind: "error" as const, text: errorMessage } } : {}),
  });
}

function renderManagementPage(
  state: string,
  stored: StoredAuthState,
  draft: AccountDraft,
  message?: string,
): string {
  return renderAuthPage({
    version: 1,
    kind: "management",
    title: "Manage Email MCP accounts",
    clientName: stored.clientName,
    state,
    accounts: draft.accounts.map((account) => ({
      accountId: account.accountId,
      label: account.label,
      address: account.address,
      preset: account.preset,
      capabilities: account.capabilities,
      isDefault: account.accountId === draft.defaultAccountId,
    })),
    ...(message ? { message: { kind: "status" as const, text: message } } : {}),
  });
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

function automaticallyGrantedScopes(stored: StoredAuthState): string[] {
  return requestedScopes(stored.request);
}

function stateCookieFor(request: Request, state: string, secret: string): Promise<string> {
  return signState(state, secret).then((signature) => stateCookie(request, state, signature));
}

function isVerificationError(error: unknown): boolean {
  return error instanceof MailCredentialError || error instanceof AccountVaultError || error instanceof z.ZodError;
}

function verificationFailureMessage(): string {
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
  const targetValue = form.get("target");
  const target: AccountFormTarget = targetValue === "add" || targetValue === "edit" ? targetValue : "start";
  const stateWithSelection: StoredAuthState = { ...stored, grantedScopes: selectedScopes };

  if (action === "add" || action === "edit") {
    const draft = await loadAccountDraft(env, stateToken);
    if (!draft) return jsonError("Expired authorization state", 400);
    const existing = action === "edit" ? draft.accounts.find((account) => account.accountId === (form.get("account_id") ?? "")) : undefined;
    await persistAuthState(env, stateToken, stateWithSelection);
    return htmlResponse(
      renderAccountFormPage(stateToken, stateWithSelection, action, undefined, undefined, existing),
      callbackFormAction,
      200,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  if (action === "list") {
    const draft = await loadAccountDraft(env, stateToken);
    if (!draft) return jsonError("Expired authorization state", 400);
    await persistAuthState(env, stateToken, stateWithSelection);
    return htmlResponse(
      renderManagementPage(stateToken, stateWithSelection, draft),
      callbackFormAction,
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
          renderManagementPage(stateToken, stateWithSelection, nextDraft, "The account was removed from this draft."),
          callbackFormAction,
          200,
          await stateCookieFor(request, stateToken, secret),
        );
      }
      if (action === "set_default") {
        const nextDraft = setDraftDefault(draft, accountId);
        await saveAccountDraft(env, stateToken, nextDraft);
        await persistAuthState(env, stateToken, stateWithSelection);
        return htmlResponse(
          renderManagementPage(stateToken, stateWithSelection, nextDraft, "The default account was updated in this draft."),
          callbackFormAction,
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
            renderManagementPage(stateToken, nextState, draft, "The account could not be verified. Check its credentials and try again."),
            callbackFormAction,
            401,
            await stateCookieFor(request, stateToken, secret),
          );
        }
        await persistAuthState(env, stateToken, stateWithSelection);
        return htmlResponse(
          renderManagementPage(stateToken, stateWithSelection, draft, "The account connection was verified."),
          callbackFormAction,
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
          renderManagementPage(stateToken, stateWithSelection, draft, error.message),
          callbackFormAction,
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
        renderAccountFormPage(stateToken, nextState, target, verificationFailureMessage(), form, existing),
        callbackFormAction,
        401,
        await stateCookieFor(request, stateToken, secret),
      );
    }
    return htmlResponse(
      renderStartPage(stateToken, nextState, verificationFailureMessage(), form),
      callbackFormAction,
      401,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  let draft: AccountDraft;
  let matchedExistingProfile = false;
  try {
    if (target === "start") {
      const existingDraft = await findAccountDraft(env, verifiedAccount);
      matchedExistingProfile = existingDraft !== null;
      draft = existingDraft ?? newAccountDraft(verifiedAccount);
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
    const nextState: StoredAuthState = { ...stateWithSelection, attempts };
    await persistAuthState(env, stateToken, nextState);
    if (target === "start") {
      return htmlResponse(
        renderStartPage(stateToken, nextState, "The account profile could not be unlocked. Check the account details and try again.", form),
        callbackFormAction,
        401,
        await stateCookieFor(request, stateToken, secret),
      );
    }
    const existingDraft = await loadAccountDraft(env, stateToken);
    if (!existingDraft) return jsonError("Expired authorization state", 400);
    const existing = target === "edit" ? existingDraft.accounts.find((account) => account.accountId === (form.get("account_id") ?? "")) : undefined;
    return htmlResponse(
      renderAccountFormPage(stateToken, nextState, target, "The account could not be added to this profile.", form, existing),
      callbackFormAction,
      409,
      await stateCookieFor(request, stateToken, secret),
    );
  }

  await saveAccountDraft(env, stateToken, draft);
  await persistAuthState(env, stateToken, stateWithSelection);
  const resultMessage = target === "start"
    ? matchedExistingProfile
      ? "Existing profile found. Review its accounts, then Continue."
      : "New profile ready. Review the account, then Continue."
    : "The account changes were saved to this draft.";
  return htmlResponse(
    renderManagementPage(stateToken, stateWithSelection, draft, resultMessage),
    callbackFormAction,
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
