import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export const MAIL_SCOPES = ["mail.read", "mail.write"] as const;
export type MailScope = (typeof MAIL_SCOPES)[number];

export const CALENDAR_SCOPES = ["calendar.read", "calendar.write"] as const;
export type CalendarScope = (typeof CALENDAR_SCOPES)[number];

export const CONTACT_SCOPES = ["contacts.read", "contacts.write"] as const;
export type ContactScope = (typeof CONTACT_SCOPES)[number];

export const RESOURCE_SCOPES = [...MAIL_SCOPES, ...CALENDAR_SCOPES, ...CONTACT_SCOPES] as const;
export type ResourceScope = (typeof RESOURCE_SCOPES)[number];

export interface AuthProps {
  userId: string;
  /** Present on grants created before multi-account vaults were introduced. */
  credentialId?: string;
  scopes: string[];
}

export type MailAuthProps = AuthProps;

export function restrictPropsToTokenScope(props: unknown, scopes: string[]): AuthProps {
  const record = props && typeof props === "object" ? props as Record<string, unknown> : {};
  const userId = typeof record.userId === "string" ? record.userId : "";
  const credentialId = typeof record.credentialId === "string" ? record.credentialId : undefined;
  const resourceScopes = scopes.filter((scope) => (RESOURCE_SCOPES as readonly string[]).includes(scope));
  return { userId, ...(credentialId ? { credentialId } : {}), scopes: resourceScopes };
}

export const restrictMailPropsToTokenScope = restrictPropsToTokenScope;

export type AppEnv = Env & {
  OAUTH_PROVIDER: OAuthHelpers;
  MAIL_CREDENTIALS_ENCRYPTION_KEY: string;
};

export type OAuthEnv = AppEnv & { OAUTH_PROVIDER: OAuthHelpers };

export interface MailConfig {
  email: string;
  imapUser: string;
  password: string;
  imapHost: string;
  imapPort: number;
  imapTlsMode: "implicit" | "starttls";
  smtpHost: string;
  smtpPort: number;
  smtpTlsMode: "implicit" | "starttls";
  smtpUser: string;
  smtpPassword: string;
}

export type AccountPreset = "icloud" | "custom";
export type AccountCapability = "mail" | "calendar" | "contacts";

export interface AccountCapabilities {
  mail: boolean;
  calendar: boolean;
  contacts: boolean;
}

export interface AccountSummary {
  accountId: string;
  label: string;
  address: string;
  preset: AccountPreset;
  capabilities: AccountCapabilities;
  isDefault: boolean;
}

export interface StoredMailAccount {
  accountId: string;
  label: string;
  preset: AccountPreset;
  address: string;
  capabilities: AccountCapabilities;
  config: MailConfig;
  davConfig?: DavConfig;
}

export interface AccountVaultV2 {
  version: 2;
  userId: string;
  revision: number;
  defaultAccountId: string;
  accounts: StoredMailAccount[];
}

export interface DavConfig {
  caldavUrl?: string;
  carddavUrl?: string;
  username?: string;
}

export interface MailCredentials {
  email: string;
  imapUser: string;
  appPassword: string;
}

export interface Mailbox {
  name: string;
  delimiter: string | null;
  attributes: string[];
  specialUse?: string;
}

export interface AddressInfo {
  name: string;
  address: string;
}

export interface AttachmentPart {
  part: string;
  filename: string | null;
  mimeType: string;
  disposition: string | null;
  encoding: string;
  size: number;
  contentId?: string;
}

export interface MessageMetadata {
  uid: number;
  flags: string[];
  size: number;
  internalDate: string | null;
  subject: string | null;
  from: AddressInfo[];
  sender: AddressInfo[];
  replyTo: AddressInfo[];
  to: AddressInfo[];
  cc: AddressInfo[];
  bcc: AddressInfo[];
  inReplyTo: string | null;
  messageId: string | null;
  attachments: AttachmentPart[];
}

export interface MessagePage {
  mailbox: string;
  messages: MessageMetadata[];
  nextBeforeUid: number | null;
}

export interface ParsedMessage {
  metadata: MessageMetadata;
  headers: Array<{ key: string; value: string }>;
  text: string | null;
  html: string | null;
  attachments: Array<{
    part: string | null;
    filename: string | null;
    mimeType: string;
    disposition: string | null;
    contentBase64: string;
    size: number;
  }>;
}

export interface SendResult {
  delivery: "sent";
  sentMailbox: string;
  sentSaved: boolean;
  sentSaveError?: string;
  messageId: string;
}

export const DEFAULT_PAGE_SIZE = 50;
export const MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
export const MAX_ATTACHMENT_BYTES = 1024 * 1024;
export const MAX_COMPOSED_MESSAGE_BYTES = 4 * 1024 * 1024;
export const MAX_ATTACHMENT_COUNT = 10;
