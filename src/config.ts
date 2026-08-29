import type { AppEnv, MailConfig, MailCredentials } from "./types";

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

export function isICloudDavHost(hostname: string, service?: "calendar" | "contacts"): boolean {
  if (service === "calendar") return /^(?:caldav|p\d+-caldav)\.icloud\.com$/iu.test(hostname);
  if (service === "contacts") return /^(?:contacts|p\d+-contacts)\.icloud\.com$/iu.test(hostname);
  return /^(?:caldav|contacts|p\d+-caldav|p\d+-contacts)\.icloud\.com$/iu.test(hostname);
}

export function getMailConfig(_env: unknown, credentials: MailCredentials): MailConfig {
  return {
    email: required(credentials.email, "iCloud email"),
    imapUser: required(credentials.imapUser, "iCloud IMAP username"),
    password: required(credentials.appPassword, "iCloud app-specific password"),
    imapHost: "imap.mail.me.com",
    imapPort: 993,
    imapTlsMode: "implicit",
    smtpHost: "smtp.mail.me.com",
    smtpPort: 587,
    smtpTlsMode: "starttls",
    smtpUser: required(credentials.email, "iCloud SMTP username"),
    smtpPassword: required(credentials.appPassword, "iCloud app-specific password"),
  };
}
