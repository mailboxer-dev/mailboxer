export type AccountFormTarget = "start" | "add" | "edit";
export type AccountFormStep = "email" | "password" | "config";
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

function base64UrlEncodeUtf8(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

export function decodeAuthPageModel(value: string): AuthPageModel {
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as AuthPageModel;
}

function escapeAttribute(value: string): string {
  return value.replace(/&/gu, "&amp;").replace(/"/gu, "&quot;").replace(/</gu, "&lt;").replace(/>/gu, "&gt;");
}

export function renderAuthPage(page: AuthPageModel): string {
  const model = escapeAttribute(base64UrlEncodeUtf8(JSON.stringify(page)));
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="color-scheme" content="light">
    <meta name="theme-color" content="#062b66">
    <title>${escapeAttribute(page.title)}</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <link rel="stylesheet" href="/style.css">
  </head>
  <body>
    <div id="root" data-page="${model}"></div>
    <noscript>This authorization screen requires JavaScript.</noscript>
    <script type="module" src="/auth.js"></script>
  </body>
</html>`;
}
