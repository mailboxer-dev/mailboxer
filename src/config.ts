import type { AppEnv, MailConfig, MailCredentials } from "./types";

export type MailSettingsEnv = Pick<AppEnv, "IMAP_HOST" | "IMAP_PORT" | "SMTP_HOST" | "SMTP_PORT"> & {
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

export function getCredentialsEncryptionSecret(env: Pick<AppEnv, "MAIL_CREDENTIALS_ENCRYPTION_KEY">): string {
  const secret = required(env.MAIL_CREDENTIALS_ENCRYPTION_KEY, "MAIL_CREDENTIALS_ENCRYPTION_KEY");
  if (secret.length < 32) throw new Error("MAIL_CREDENTIALS_ENCRYPTION_KEY must contain at least 32 characters");
  return secret;
}

function port(value: string | undefined, name: string, fallback: number): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`Invalid ${name}`);
  }
  return parsed;
}

export function getMailConfig(env: MailSettingsEnv, credentials: MailCredentials): MailConfig {
  return {
    email: required(credentials.email, "iCloud email"),
    imapUser: required(credentials.imapUser, "iCloud IMAP username"),
    password: required(credentials.appPassword, "iCloud app-specific password"),
    imapHost: env.IMAP_HOST || "imap.mail.me.com",
    imapPort: port(env.IMAP_PORT, "IMAP_PORT", 993),
    smtpHost: env.SMTP_HOST || "smtp.mail.me.com",
    smtpPort: port(env.SMTP_PORT, "SMTP_PORT", 587),
  };
}
