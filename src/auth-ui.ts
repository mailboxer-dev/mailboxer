export type AccountFormTarget = "start" | "add" | "edit";
export type AccountFormStep = "email" | "password" | "new-password" | "config";
export type AccountPreset = "icloud" | "custom";
export type TlsMode = "implicit" | "starttls";

const ICLOUD_EMAIL_DOMAINS = new Set(["icloud.com", "me.com", "mac.com"]);

export function detectAccountPreset(address: string): AccountPreset {
  const domain = address.trim().toLowerCase().split("@").at(-1) ?? "";
  return ICLOUD_EMAIL_DOMAINS.has(domain) ? "icloud" : "custom";
}

export interface AccountFormModel {
  preset: AccountPreset;
  label: string;
  address: string;
  services: {
    mail: boolean;
    calendar: boolean;
    contacts: boolean;
  };
  imap: {
    host: string;
    port: string;
    tlsMode: TlsMode;
    user: string;
  };
  smtp: {
    host: string;
    port: string;
    tlsMode: TlsMode;
    user: string;
    sameCredentials: boolean;
  };
  dav: {
    calendarUrl: string;
    contactsUrl: string;
    user: string;
  };
}

/**
 * Data used by the public onboarding page.
 *
 * Keep this model deliberately small: the page is rendered by the same
 * bundled React entrypoint as the authorization wizard, but it does not need
 * to know anything about OAuth state or account credentials.
 */
export interface LandingPageModel {
  version: 1;
  kind: "landing";
  origin: string;
  mcpUrl: string;
  agentSetupUrl: string;
}

interface AuthPageBase {
  version: 1;
  clientName: string;
  title: string;
  message?: {
    kind: "error" | "status";
    text: string;
  };
}

export type AuthPageModel =
  | (AuthPageBase & {
      kind: "account-form";
      state: string;
      target: AccountFormTarget;
      step: AccountFormStep;
      accountId?: string;
      account: AccountFormModel;
    })
  | (AuthPageBase & {
      kind: "management";
      state: string;
      accounts: Array<{
        accountId: string;
        label: string;
        address: string;
        preset: AccountPreset;
        capabilities: {
          mail: boolean;
          calendar: boolean;
          contacts: boolean;
        };
        isDefault: boolean;
      }>;
    });

export type UiPageModel = LandingPageModel | AuthPageModel;

function base64UrlEncodeUtf8(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

function decodePageModel(value: string): UiPageModel {
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as UiPageModel;
}

export function decodeUiPageModel(value: string): UiPageModel {
  return decodePageModel(value);
}

export function decodeAuthPageModel(value: string): AuthPageModel {
  // Keep the original decoder's permissive behavior for authorization
  // callers. New callers that need to distinguish the public page should use
  // decodeUiPageModel instead.
  return decodePageModel(value) as AuthPageModel;
}

function escapeAttribute(value: string): string {
  return value.replace(/&/gu, "&amp;").replace(/"/gu, "&quot;").replace(/</gu, "&lt;").replace(/>/gu, "&gt;");
}

export function renderUiPage(page: UiPageModel): string {
  const model = escapeAttribute(base64UrlEncodeUtf8(JSON.stringify(page)));
  const title = page.kind === "landing" ? "Mailboxer — connect your agent" : page.title;
  const description = page.kind === "landing"
    ? "Give your agent a mailbox. Connect your email, calendar, and contacts to ChatGPT, Claude, or Codex with Mailboxer."
    : undefined;
  const noScriptMessage = page.kind === "landing"
    ? "This onboarding page requires JavaScript."
    : "This authorization screen requires JavaScript.";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="light">
    <meta name="theme-color" content="#062b66">
    ${description ? `<meta name="description" content="${escapeAttribute(description)}">` : ""}
    <title>${escapeAttribute(title)}</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <link rel="stylesheet" href="/style.css">
  </head>
  <body>
    <div id="root" data-page="${model}"></div>
    <noscript>${noScriptMessage}</noscript>
    <script type="module" src="/auth.js"></script>
  </body>
</html>`;
}

/** Render an authorization page while retaining the pre-onboarding API. */
export function renderAuthPage(page: AuthPageModel): string {
  return renderUiPage(page);
}
