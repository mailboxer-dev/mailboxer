import type { AppEnv, DavConfig, MailConfig, MailCredentials } from "./types";

export type MailSettingsEnv = Pick<AppEnv, "IMAP_HOST" | "IMAP_PORT" | "SMTP_HOST" | "SMTP_PORT"> & {
  IMAP_HOST?: string;
  IMAP_PORT?: string;
  SMTP_HOST?: string;
  SMTP_PORT?: string;
};

export type DavSettingsEnv = {
  CALDAV_URL?: string;
  CARDDAV_URL?: string;
};

const DEFAULT_CALDAV_URL = "https://caldav.icloud.com/";
const DEFAULT_CARDDAV_URL = "https://contacts.icloud.com/";

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

function davUrl(value: string | undefined, name: string, fallback: string, service: "calendar" | "contacts"): string {
  let url: URL;
  try {
    url = new URL(value || fallback);
  } catch {
    throw new Error(`Invalid ${name}`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error(`Invalid ${name}`);
  }
  if (!isICloudDavHost(url.hostname, service)) throw new Error(`Invalid ${name}`);
  url.pathname = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
  return url.toString();
}

export function isICloudDavHost(hostname: string, service?: "calendar" | "contacts"): boolean {
  if (service === "calendar") return /^(?:caldav|p\d+-caldav)\.icloud\.com$/iu.test(hostname);
  if (service === "contacts") return /^(?:contacts|p\d+-contacts)\.icloud\.com$/iu.test(hostname);
  return /^(?:caldav|contacts|p\d+-caldav|p\d+-contacts)\.icloud\.com$/iu.test(hostname);
}

export function getDavConfig(env: unknown): DavConfig {
  const settings = env && typeof env === "object" ? env as DavSettingsEnv : {};
  return {
    caldavUrl: davUrl(settings.CALDAV_URL, "CALDAV_URL", DEFAULT_CALDAV_URL, "calendar"),
    carddavUrl: davUrl(settings.CARDDAV_URL, "CARDDAV_URL", DEFAULT_CARDDAV_URL, "contacts"),
  };
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
