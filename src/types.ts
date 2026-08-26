import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export const MAIL_SCOPES = ["mail.read", "mail.write"] as const;
export type MailScope = (typeof MAIL_SCOPES)[number];

export const OWNER_USER_ID = "owner";

export interface MailAuthProps {
  userId: string;
  scopes: string[];
}

export function restrictMailPropsToTokenScope(props: unknown, scopes: string[]): MailAuthProps {
  const record = props && typeof props === "object" ? props as Record<string, unknown> : {};
  const userId = typeof record.userId === "string" ? record.userId : "";
  const mailScopes = scopes.filter((scope) => (MAIL_SCOPES as readonly string[]).includes(scope));
  return { userId, scopes: mailScopes };
}

export type AppEnv = Env & {
  OAUTH_PROVIDER: OAuthHelpers;
  MCP_LOGIN_SECRET: string;
  ICLOUD_EMAIL: string;
  ICLOUD_IMAP_USER: string;
  ICLOUD_APP_PASSWORD: string;
};

export type OAuthEnv = AppEnv & { OAUTH_PROVIDER: OAuthHelpers };

export interface MailConfig {
  email: string;
  imapUser: string;
  password: string;
  imapHost: string;
  imapPort: number;
  smtpHost: string;
  smtpPort: number;
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
