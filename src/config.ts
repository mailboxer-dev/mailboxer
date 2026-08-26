import type { AppEnv, MailConfig } from "./types";

export type MailSettingsEnv = Pick<AppEnv, "ICLOUD_EMAIL" | "ICLOUD_IMAP_USER" | "ICLOUD_APP_PASSWORD"> & {
  IMAP_HOST?: string;
  IMAP_PORT?: string;
  SMTP_HOST?: string;
  SMTP_PORT?: string;
};

function required(value: string | undefined, name: string): string {
  if (!value?.trim()) {
    throw new Error(`Missing Worker secret or variable: ${name}`);
  }
  return value.trim();
}

function port(value: string | undefined, name: string, fallback: number): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`Invalid ${name}`);
  }
  return parsed;
}

export function getMailConfig(env: MailSettingsEnv): MailConfig {
  return {
    email: required(env.ICLOUD_EMAIL, "ICLOUD_EMAIL"),
    imapUser: required(env.ICLOUD_IMAP_USER || env.ICLOUD_EMAIL, "ICLOUD_IMAP_USER"),
    password: required(env.ICLOUD_APP_PASSWORD, "ICLOUD_APP_PASSWORD"),
    imapHost: env.IMAP_HOST || "imap.mail.me.com",
    imapPort: port(env.IMAP_PORT, "IMAP_PORT", 993),
    smtpHost: env.SMTP_HOST || "smtp.mail.me.com",
    smtpPort: port(env.SMTP_PORT, "SMTP_PORT", 587),
  };
}

export function assertAllowedEmail(env: AppEnv, email: string): void {
  const allowed = required(env.MCP_ALLOWED_EMAIL, "MCP_ALLOWED_EMAIL").toLowerCase();
  const mailboxOwner = required(env.ICLOUD_EMAIL, "ICLOUD_EMAIL").toLowerCase();
  if (email.trim().toLowerCase() !== allowed || email.trim().toLowerCase() !== mailboxOwner) {
    throw new Error("Access identity is not allowlisted");
  }
}
