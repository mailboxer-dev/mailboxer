import { z } from "zod";
import { getCredentialsEncryptionSecret, getDavConfig, getMailConfig } from "./config";
import { DavClient } from "./dav/client";
import type { DavService } from "./dav/types";
import { ImapClient } from "./imap/client";
import { SmtpClient } from "./smtp/client";
import { withSpan } from "./tracing";
import {
  type AppEnv,
  type MailConfig,
  type MailCredentials,
} from "./types";
import { CALENDAR_SCOPES, CONTACT_SCOPES, MAIL_SCOPES } from "./types";

const CREDENTIAL_KEY_PREFIX = "mail:credentials:v1:";
const CREDENTIAL_ID_PREFIX = "icloud-";
const CREDENTIAL_ID_PATTERN = /^icloud-[A-Za-z0-9_-]{43}$/u;
const MAX_CREDENTIAL_RECORD_BYTES = 8 * 1024;
const CREDENTIAL_ENCRYPTION_CONTEXT = "icloud-mail-mcp credential encryption v1\u0000";
const CREDENTIAL_ID_CONTEXT = "icloud-mail-mcp credential id v1\u0000";

const credentialSubmissionSchema = z.object({
  email: z.string().trim().email().max(320),
  appPassword: z.string().trim().min(1).max(256),
});

const storedCredentialsSchema = z.object({
  email: z.string().email().max(320),
  imapUser: z.string().min(1).max(320),
  appPassword: z.string().min(1).max(256),
});

const encryptedCredentialsSchema = z.object({
  version: z.literal(1),
  iv: z.string().min(1).max(64),
  ciphertext: z.string().min(1).max(MAX_CREDENTIAL_RECORD_BYTES * 2),
});

export class MailCredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MailCredentialError";
  }
}

export interface CredentialVerificationDependencies {
  imapOpen?: typeof ImapClient.open;
  smtpOpen?: typeof SmtpClient.open;
  davVerify?: (config: MailConfig, service: DavService) => Promise<void>;
}

function encoder(): TextEncoder {
  return new TextEncoder();
}

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

async function sha256(value: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", encoder().encode(value));
  return new Uint8Array(digest);
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function normalizeSubmission(input: unknown): { email: string; appPassword: string } {
  const parsed = credentialSubmissionSchema.safeParse(input);
  if (!parsed.success) throw new MailCredentialError("Enter a valid iCloud email and app-specific password");
  return {
    email: normalizeEmail(parsed.data.email),
    appPassword: parsed.data.appPassword,
  };
}

function imapUserCandidates(email: string): string[] {
  const localPart = email.split("@", 1)[0] ?? "";
  return [...new Set([localPart, email].filter((candidate) => candidate.length > 0))];
}

function credentialKey(credentialId: string): string {
  if (!CREDENTIAL_ID_PATTERN.test(credentialId)) throw new MailCredentialError("Invalid iCloud credential reference");
  return `${CREDENTIAL_KEY_PREFIX}${credentialId}`;
}

function credentialsKv(env: Pick<AppEnv, "MAIL_CREDENTIALS_KV">): KVNamespace {
  if (!env.MAIL_CREDENTIALS_KV) throw new Error("MAIL_CREDENTIALS_KV binding is not configured");
  return env.MAIL_CREDENTIALS_KV;
}

async function encryptionKey(secret: string): Promise<CryptoKey> {
  const material = await sha256(`${CREDENTIAL_ENCRYPTION_CONTEXT}${secret}`);
  return crypto.subtle.importKey(
    "raw",
    asArrayBuffer(material),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function credentialIdForEmail(email: string, secret: string): Promise<string> {
  const digest = await sha256(`${CREDENTIAL_ID_CONTEXT}${secret}\u0000${normalizeEmail(email)}`);
  return `${CREDENTIAL_ID_PREFIX}${base64UrlEncode(digest)}`;
}

async function encryptCredentials(
  credentialId: string,
  credentials: MailCredentials,
  secret: string,
): Promise<z.infer<typeof encryptedCredentialsSchema>> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const associatedData = encoder().encode(`${CREDENTIAL_KEY_PREFIX}${credentialId}`);
  const plaintext = encoder().encode(JSON.stringify(credentials));
  if (plaintext.byteLength > MAX_CREDENTIAL_RECORD_BYTES) throw new MailCredentialError("iCloud credentials are too large");
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: asArrayBuffer(iv),
      additionalData: asArrayBuffer(associatedData),
    },
    await encryptionKey(secret),
    asArrayBuffer(plaintext),
  );
  return {
    version: 1,
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(new Uint8Array(encrypted)),
  };
}

async function decryptCredentials(
  credentialId: string,
  value: unknown,
  secret: string,
): Promise<MailCredentials> {
  const parsedEnvelope = encryptedCredentialsSchema.safeParse(value);
  if (!parsedEnvelope.success) throw new MailCredentialError("Stored iCloud credentials are invalid");
  try {
    const associatedData = encoder().encode(`${CREDENTIAL_KEY_PREFIX}${credentialId}`);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(base64UrlDecode(parsedEnvelope.data.iv)),
        additionalData: asArrayBuffer(associatedData),
      },
      await encryptionKey(secret),
      asArrayBuffer(base64UrlDecode(parsedEnvelope.data.ciphertext)),
    );
    const parsedCredentials = storedCredentialsSchema.safeParse(JSON.parse(new TextDecoder().decode(new Uint8Array(decrypted))));
    if (!parsedCredentials.success) throw new MailCredentialError("Stored iCloud credentials are invalid");
    return parsedCredentials.data;
  } catch (error) {
    if (error instanceof MailCredentialError) throw error;
    throw new MailCredentialError("Stored iCloud credentials cannot be decrypted");
  }
}

async function verifyImap(
  config: MailConfig,
  open: typeof ImapClient.open,
  candidate: number,
): Promise<void> {
  return withSpan(
    "mail.credentials.verify_imap",
    { "mail.credentials.imap_candidate": candidate },
    async () => {
      const client = await open(config);
      client.close();
    },
  );
}

async function verifySmtp(config: MailConfig, open: typeof SmtpClient.open): Promise<void> {
  return withSpan("mail.credentials.verify_smtp", {}, async () => {
    const client = await open(config);
    try {
      await client.authenticate();
    } finally {
      await client.quit().catch(() => undefined);
      client.close();
    }
  });
}

export async function verifyMailCredentials(
  env: AppEnv,
  input: unknown,
  scopesOrDependencies: readonly string[] | CredentialVerificationDependencies = MAIL_SCOPES,
  dependencyOverrides: CredentialVerificationDependencies = {},
): Promise<MailCredentials> {
  const submission = normalizeSubmission(input);
  const scopes: readonly string[] = Array.isArray(scopesOrDependencies) ? scopesOrDependencies : MAIL_SCOPES;
  const dependencies: CredentialVerificationDependencies = Array.isArray(scopesOrDependencies)
    ? dependencyOverrides
    : scopesOrDependencies as CredentialVerificationDependencies;
  const mailReadRequested = scopes.includes("mail.read");
  const mailWriteRequested = scopes.includes("mail.write");
  const mailRequested = mailReadRequested || mailWriteRequested;
  const calendarRequested = scopes.some((scope) => (CALENDAR_SCOPES as readonly string[]).includes(scope));
  const contactsRequested = scopes.some((scope) => (CONTACT_SCOPES as readonly string[]).includes(scope));
  if (!mailRequested && !calendarRequested && !contactsRequested) {
    throw new MailCredentialError("Select at least one supported iCloud permission");
  }
  const imapOpen = dependencies.imapOpen ?? ImapClient.open;
  const smtpOpen = dependencies.smtpOpen ?? SmtpClient.open;
  const davVerify = dependencies.davVerify ?? ((config: MailConfig, service: DavService) => (
    new DavClient(config, getDavConfig(env)).verifyService(service)
  ));
  let verifiedConfig = getMailConfig(env, {
    email: submission.email,
    imapUser: imapUserCandidates(submission.email)[0] ?? submission.email,
    appPassword: submission.appPassword,
  });

  if (mailRequested) {
    let imapVerified = false;
    for (const [index, imapUser] of imapUserCandidates(submission.email).entries()) {
      const config = getMailConfig(env, {
        email: submission.email,
        imapUser,
        appPassword: submission.appPassword,
      });
      try {
        await verifyImap(config, imapOpen, index + 1);
        verifiedConfig = config;
        imapVerified = true;
        break;
      } catch {
        // Apple accepts either the local part or, for some accounts, the full address.
      }
    }

    if (!imapVerified) throw new MailCredentialError("iCloud credentials could not be verified");
    if (mailWriteRequested) {
      try {
        await verifySmtp(verifiedConfig, smtpOpen);
      } catch {
        throw new MailCredentialError("iCloud SMTP credentials could not be verified");
      }
    }
  }

  for (const service of [
    ...(calendarRequested ? ["calendar" as const] : []),
    ...(contactsRequested ? ["contacts" as const] : []),
  ]) {
    try {
      await davVerify(verifiedConfig, service);
    } catch {
      throw new MailCredentialError("iCloud DAV credentials could not be verified");
    }
  }
  return {
    email: verifiedConfig.email,
    imapUser: verifiedConfig.imapUser,
    appPassword: verifiedConfig.password,
  };
}

export async function storeMailCredentials(env: AppEnv, credentials: MailCredentials): Promise<string> {
  const secret = getCredentialsEncryptionSecret(env);
  const parsed = storedCredentialsSchema.safeParse(credentials);
  if (!parsed.success) throw new MailCredentialError("iCloud credentials are invalid");
  const normalized: MailCredentials = {
    email: normalizeEmail(parsed.data.email),
    imapUser: parsed.data.imapUser,
    appPassword: parsed.data.appPassword,
  };
  const credentialId = await credentialIdForEmail(normalized.email, secret);
  const envelope = await encryptCredentials(credentialId, normalized, secret);
  await credentialsKv(env).put(`${CREDENTIAL_KEY_PREFIX}${credentialId}`, JSON.stringify(envelope));
  return credentialId;
}

export async function loadMailCredentials(env: AppEnv, credentialId: string): Promise<MailCredentials> {
  const secret = getCredentialsEncryptionSecret(env);
  const raw = await credentialsKv(env).get(credentialKey(credentialId), "json");
  if (!raw) throw new MailCredentialError("iCloud credentials are not configured; reconnect the account");
  const credentials = await decryptCredentials(credentialId, raw, secret);
  const expectedId = await credentialIdForEmail(credentials.email, secret);
  if (expectedId !== credentialId) throw new MailCredentialError("Stored iCloud credentials are invalid");
  return credentials;
}

export async function getMailConfigForCredential(env: AppEnv, credentialId: string): Promise<MailConfig> {
  return getMailConfig(env, await loadMailCredentials(env, credentialId));
}
