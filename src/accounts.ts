import { z } from "zod";
import { getCredentialsEncryptionSecret, getMailConfig } from "./config";
import {
  credentialIdForEmail,
  loadMailCredentials,
  MailCredentialError,
  verifyMailCredentials,
} from "./credentials";
import { DavClient } from "./dav/client";
import { logFailure } from "./diagnostics";
import { ImapClient } from "./imap/client";
import { SmtpClient } from "./smtp/client";
import { customDavConfig, ICLOUD_DAV_CONFIG } from "./providers";
import type {
  AccountCapability,
  AccountSummary,
  AccountRecord,
  AppEnv,
  AuthProps,
  MailConfig,
  DavConfig,
  StoredMailAccount,
} from "./types";

const VAULT_KEY_PREFIX = "mail:account-vault:v2:";
const INDEX_KEY_PREFIX = "mail:account-index:v2:";
const EMAIL_INDEX_KEY_PREFIX = "mail:account-email-index:v2:";
const DRAFT_KEY_PREFIX = "mail:account-draft:v3:";
// Keep the legacy key derivation so saved v2 credentials remain readable during reconnect.
const VAULT_CONTEXT = "email-mcp account vault v2\u0000";
const INDEX_CONTEXT = "email-mcp account locator v2\u0000";
const EMAIL_INDEX_CONTEXT = "email-mcp account email index v2\u0000";
const MAX_VAULT_BYTES = 96 * 1024;
export const ACCOUNT_DRAFT_TTL_SECONDS = 10 * 60;

const hostnameSchema = z.string().trim().min(4).max(253);
const accountIdSchema = z.string().regex(/^acct_[A-Za-z0-9_-]{22}$/u);
const userIdSchema = z.string().regex(/^(?:usr_[A-Za-z0-9_-]{32}|icloud-[A-Za-z0-9_-]{43})$/u);
const capabilitiesSchema = z.object({
  mail: z.boolean(),
  calendar: z.boolean(),
  contacts: z.boolean(),
});
const tlsModeSchema = z.enum(["implicit", "starttls"]);
const mailConfigSchema = z.object({
  email: z.string().email().max(320),
  imapUser: z.string().min(1).max(320),
  password: z.string().min(1).max(256),
  imapHost: hostnameSchema,
  imapPort: z.number().int(),
  imapTlsMode: tlsModeSchema,
  smtpHost: hostnameSchema,
  smtpPort: z.number().int(),
  smtpTlsMode: tlsModeSchema,
  smtpUser: z.string().min(1).max(320),
  smtpPassword: z.string().min(1).max(256),
});
const storedAccountSchema = z.object({
  accountId: accountIdSchema,
  label: z.string().trim().min(1).max(80),
  preset: z.enum(["icloud", "custom"]),
  address: z.string().email().max(320),
  capabilities: capabilitiesSchema,
  config: mailConfigSchema,
  davConfig: z.object({
    caldavUrl: z.string().url().optional(),
    carddavUrl: z.string().url().optional(),
    username: z.string().min(1).max(320).optional(),
  }).optional(),
});
const recordSchema = z.object({
  version: z.literal(3),
  userId: userIdSchema,
  revision: z.number().int().min(1),
  account: storedAccountSchema,
});
const ACCOUNT_KEY_PREFIX = "mail:account:v3:";
const envelopeSchema = z.object({
  version: z.literal(2),
  iv: z.string().min(1).max(64),
  ciphertext: z.string().min(1).max(MAX_VAULT_BYTES * 2),
});

export interface AccountDraft {
  userId: string;
  baseRevision: number | null;
  account: StoredMailAccount;
}
const draftSchema = z.object({
  userId: userIdSchema,
  baseRevision: z.number().int().min(1).nullable(),
  account: storedAccountSchema,
});

export interface AccountSubmission {
  preset: "icloud" | "custom";
  label: string;
  address: string;
  appPassword?: string;
  enableMail?: boolean;
  enableCalendar?: boolean;
  enableContacts?: boolean;
  imapHost?: string;
  imapPort?: number;
  imapTlsMode?: "implicit" | "starttls";
  imapUser?: string;
  imapPassword?: string;
  smtpHost?: string;
  smtpPort?: number;
  smtpTlsMode?: "implicit" | "starttls";
  smtpUser?: string;
  smtpPassword?: string;
  sameSmtpCredentials?: boolean;
  caldavUrl?: string;
  carddavUrl?: string;
  davUser?: string;
}

export interface VerifyAccountDependencies {
  imapOpen?: typeof ImapClient.open;
  smtpOpen?: typeof SmtpClient.open;
  davVerify?: (config: MailConfig, davConfig: DavConfig, service: "calendar" | "contacts") => Promise<void>;
}

export class AccountError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccountError";
  }
}

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function asArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

function base64UrlEncode(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function randomId(prefix: "usr_" | "acct_"): string {
  const length = prefix === "usr_" ? 24 : 16;
  const random = new Uint8Array(length);
  crypto.getRandomValues(random);
  return `${prefix}${base64UrlEncode(random)}`;
}

async function aesKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", asArrayBuffer(bytes(`${VAULT_CONTEXT}${secret}`)));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptRecord(value: unknown, aad: string, secret: string): Promise<string> {
  const plaintext = bytes(JSON.stringify(value));
  if (plaintext.byteLength > MAX_VAULT_BYTES) throw new AccountError("Account configuration is too large");
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv), additionalData: asArrayBuffer(bytes(aad)) },
    await aesKey(secret),
    asArrayBuffer(plaintext),
  );
  return JSON.stringify({ version: 2, iv: base64UrlEncode(iv), ciphertext: base64UrlEncode(new Uint8Array(ciphertext)) });
}

async function decryptRecord(value: string, aad: string, secret: string): Promise<unknown> {
  try {
    const envelope = envelopeSchema.parse(JSON.parse(value));
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(base64UrlDecode(envelope.iv)),
        additionalData: asArrayBuffer(bytes(aad)),
      },
      await aesKey(secret),
      asArrayBuffer(base64UrlDecode(envelope.ciphertext)),
    );
    return JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
  } catch (error) {
    if (error instanceof AccountError) throw error;
    throw new AccountError("Stored account configuration cannot be decrypted");
  }
}

function normalizeAddress(value: string): string {
  return value.trim().toLowerCase();
}

function validateHostname(value: string, field: string): string {
  const hasControl = Array.from(value).some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 32 || code === 127;
  });
  const hostname = value.trim().toLowerCase().replace(/\.$/u, "");
  if (!hostnameSchema.safeParse(hostname).success || hostname.includes("..") || !hostname.includes(".")) {
    throw new AccountError(`Enter a valid public hostname for ${field}`);
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(hostname) || hostname.includes(":") || hasControl) {
    throw new AccountError(`${field} must be a hostname, not an IP address`);
  }
  if (/(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid)$/u.test(hostname)) {
    throw new AccountError(`${field} must be a public hostname`);
  }
  const labels = hostname.split(".");
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw new AccountError(`Enter a valid public hostname for ${field}`);
  }
  return hostname;
}

function assertTransport(port: number, mode: "implicit" | "starttls", service: "IMAP" | "SMTP"): void {
  const valid = service === "IMAP"
    ? (port === 993 && mode === "implicit") || (port === 143 && mode === "starttls")
    : (port === 465 && mode === "implicit") || ([587, 2525].includes(port) && mode === "starttls");
  if (!valid) throw new AccountError(`Unsupported ${service} port and TLS mode combination`);
}

function capabilitiesFor(submission: AccountSubmission): StoredMailAccount["capabilities"] {
  const capabilities = {
    mail: submission.enableMail !== false,
    calendar: submission.enableCalendar === true,
    contacts: submission.enableContacts === true,
  };
  if (!capabilities.mail && !capabilities.calendar && !capabilities.contacts) {
    throw new AccountError("Enable at least one service for this account");
  }
  return capabilities;
}

function customConfig(submission: AccountSubmission): MailConfig {
  const address = z.string().trim().email().max(320).parse(submission.address);
  const imapHost = validateHostname(submission.imapHost ?? "", "IMAP");
  const smtpHost = validateHostname(submission.smtpHost ?? "", "SMTP");
  const imapPort = Number(submission.imapPort);
  const smtpPort = Number(submission.smtpPort);
  const imapTlsMode = tlsModeSchema.parse(submission.imapTlsMode);
  const smtpTlsMode = tlsModeSchema.parse(submission.smtpTlsMode);
  assertTransport(imapPort, imapTlsMode, "IMAP");
  assertTransport(smtpPort, smtpTlsMode, "SMTP");
  const imapUser = z.string().trim().min(1).max(320).parse(submission.imapUser);
  const password = z.string().min(1).max(256).parse(submission.imapPassword);
  const same = submission.sameSmtpCredentials !== false;
  return {
    email: normalizeAddress(address),
    imapHost,
    imapPort,
    imapTlsMode,
    imapUser,
    password,
    smtpHost,
    smtpPort,
    smtpTlsMode,
    smtpUser: same ? imapUser : z.string().trim().min(1).max(320).parse(submission.smtpUser),
    smtpPassword: same ? password : z.string().min(1).max(256).parse(submission.smtpPassword),
  };
}

async function verifyConfig(
  config: MailConfig,
  davConfig: DavConfig,
  capabilities: StoredMailAccount["capabilities"],
  dependencies: VerifyAccountDependencies,
): Promise<void> {
  const checks: Array<{ service: "imap" | "smtp" | "calendar" | "contacts"; run: () => Promise<void> }> = [];
  if (capabilities.mail) {
    checks.push({ service: "imap", run: async () => {
      const imap = await (dependencies.imapOpen ?? ImapClient.open)(config);
      imap.close();
    } });
    checks.push({ service: "smtp", run: async () => {
      const smtp = await (dependencies.smtpOpen ?? SmtpClient.open)(config);
      try {
        await smtp.authenticate();
      } finally {
        await smtp.quit().catch(() => undefined);
        smtp.close();
      }
    } });
  }
  const davVerify = dependencies.davVerify ?? ((candidate: MailConfig, candidateDav: DavConfig, service: "calendar" | "contacts") => (
    new DavClient(candidate, candidateDav).verifyService(service)
  ));
  for (const service of ["calendar", "contacts"] as const) {
    if (!capabilities[service]) continue;
    checks.push({ service, run: () => davVerify(config, davConfig, service) });
  }
  const results = await Promise.allSettled(checks.map(async ({ service, run }) => {
    try {
      await run();
    } catch (error) {
      logFailure("account_verification_failed", {
        service,
        preset: "custom",
        ...(service === "imap" ? { tls_mode: config.imapTlsMode } : {}),
        ...(service === "smtp" ? { tls_mode: config.smtpTlsMode } : {}),
      }, error);
      throw error;
    }
  }));
  const failed = results.flatMap((result, index) => result.status === "rejected" ? [checks[index]!.service] : []);
  if (failed.length) {
    const labels: Record<(typeof failed)[number], string> = {
      imap: "incoming mail",
      smtp: "outgoing mail",
      calendar: "calendar",
      contacts: "contacts",
    };
    throw new AccountError(`We couldn't connect ${failed.map((service) => labels[service]).join(", ")}`);
  }
}

export async function verifyAccountSubmission(
  env: AppEnv,
  submission: AccountSubmission,
  dependencies: VerifyAccountDependencies = {},
  existingAccountId?: string,
): Promise<StoredMailAccount> {
  const label = z.string().trim().min(1).max(80).parse(submission.label);
  const address = normalizeAddress(z.string().trim().email().max(320).parse(submission.address));
  const capabilities = capabilitiesFor(submission);
  let config: MailConfig;
  let davConfig: DavConfig | undefined;
  if (submission.preset === "icloud") {
    const scopes = [
      ...(capabilities.mail ? ["mail.read", "mail.write"] : []),
      ...(capabilities.calendar ? ["calendar.read"] : []),
      ...(capabilities.contacts ? ["contacts.read"] : []),
    ];
    const verified = await verifyMailCredentials(
      env,
      { email: address, appPassword: submission.appPassword ?? "" },
      scopes,
      {
        imapOpen: dependencies.imapOpen,
        smtpOpen: dependencies.smtpOpen,
        ...(dependencies.davVerify ? {
          davVerify: (candidate, service) => dependencies.davVerify?.(candidate, ICLOUD_DAV_CONFIG, service) ?? Promise.resolve(),
        } : {}),
      },
    );
    config = getMailConfig(env, verified);
    davConfig = ICLOUD_DAV_CONFIG;
  } else {
    config = customConfig(submission);
    try {
      davConfig = customDavConfig(submission.caldavUrl, submission.carddavUrl, submission.davUser ?? config.imapUser, capabilities);
    } catch (error) {
      throw new AccountError(error instanceof Error ? error.message : "Enter valid calendar and contacts server addresses");
    }
    await verifyConfig(config, davConfig ?? {}, capabilities, dependencies);
  }
  return storedAccountSchema.parse({
    accountId: existingAccountId ?? randomId("acct_"),
    label,
    preset: submission.preset,
    address,
    capabilities,
    config,
    ...(submission.preset === "custom" && davConfig ? { davConfig } : {}),
  });
}

function canonicalLocator(account: Pick<StoredMailAccount, "preset" | "address" | "config">): string {
  return account.preset === "icloud"
    ? `icloud\u0000${normalizeAddress(account.address)}`
    : `custom\u0000${account.config.imapHost.toLowerCase()}\u0000${account.config.imapUser.trim().toLowerCase()}`;
}

async function indexDigest(value: string, context: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(bytes(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, asArrayBuffer(bytes(`${context}${value}`)));
  return base64UrlEncode(new Uint8Array(signature));
}

async function locatorIndexKey(locator: string, secret: string): Promise<string> {
  return `${INDEX_KEY_PREFIX}${await indexDigest(locator, INDEX_CONTEXT, secret)}`;
}

async function emailIndexKey(email: string, secret: string): Promise<string> {
  return `${EMAIL_INDEX_KEY_PREFIX}${await indexDigest(normalizeAddress(email), EMAIL_INDEX_CONTEXT, secret)}`;
}

export function newAccountDraft(account: StoredMailAccount): AccountDraft {
  return { userId: randomId("usr_"), baseRevision: null, account };
}

export async function loadAccountRecord(env: AppEnv, userId: string): Promise<AccountRecord | null> {
  if (!userIdSchema.safeParse(userId).success) return null;
  const key = `${ACCOUNT_KEY_PREFIX}${userId}`;
  const value = await env.OAUTH_KV.get(key);
  return value ? recordSchema.parse(await decryptRecord(value, key, getCredentialsEncryptionSecret(env))) : null;
}

export async function saveAccountDraft(env: AppEnv, state: string, draft: AccountDraft): Promise<void> {
  const key = `${DRAFT_KEY_PREFIX}${state}`;
  const encrypted = await encryptRecord(draftSchema.parse(draft), key, getCredentialsEncryptionSecret(env));
  await env.OAUTH_KV.put(key, encrypted, { expirationTtl: ACCOUNT_DRAFT_TTL_SECONDS });
}

export async function loadAccountDraft(env: AppEnv, state: string): Promise<AccountDraft | null> {
  const key = `${DRAFT_KEY_PREFIX}${state}`;
  const value = await env.OAUTH_KV.get(key);
  return value ? draftSchema.parse(await decryptRecord(value, key, getCredentialsEncryptionSecret(env))) : null;
}

export async function deleteAccountDraft(env: AppEnv, state: string): Promise<void> {
  await env.OAUTH_KV.delete(`${DRAFT_KEY_PREFIX}${state}`);
}

function draftFromRecord(record: AccountRecord): AccountDraft {
  return { userId: record.userId, baseRevision: record.revision, account: record.account };
}

// Read old vaults only during sign-in. Never authorize a legacy grant or copy sibling accounts.
async function savedAccountByEmail(env: AppEnv, email: string): Promise<StoredMailAccount | null> {
  const secret = getCredentialsEncryptionSecret(env);
  const owner = await env.OAUTH_KV.get(await emailIndexKey(email, secret))
    ?? await env.OAUTH_KV.get(await locatorIndexKey(`icloud\u0000${email}`, secret));
  if (owner) {
    const key = `${VAULT_KEY_PREFIX}${owner}`;
    const value = await env.OAUTH_KV.get(key);
    if (value) {
      const legacy = z.object({ accounts: z.array(storedAccountSchema).min(1).max(10) }).parse(await decryptRecord(value, key, secret));
      return legacy.accounts.find((account) => normalizeAddress(account.address) === email) ?? null;
    }
  }
  try {
    const credentials = await loadMailCredentials(env, await credentialIdForEmail(email, secret));
    return storedAccountSchema.parse({
      accountId: randomId("acct_"),
      label: "iCloud",
      preset: "icloud",
      address: email,
      capabilities: { mail: true, calendar: true, contacts: true },
      config: getMailConfig(env, credentials),
    });
  } catch (error) {
    if (!(error instanceof MailCredentialError)) throw error;
    return null;
  }
}

async function newIndexKey(email: string, secret: string): Promise<string> {
  return `mail:account-email-index:v3:${await indexDigest(normalizeAddress(email), EMAIL_INDEX_CONTEXT, secret)}`;
}

export async function findAccountDraftByEmail(env: AppEnv, email: string): Promise<AccountDraft | null> {
  const parsed = z.string().trim().email().max(320).safeParse(email);
  if (!parsed.success) return null;
  const address = normalizeAddress(parsed.data);
  const owner = await env.OAUTH_KV.get(await newIndexKey(address, getCredentialsEncryptionSecret(env)));
  if (owner) {
    const record = await loadAccountRecord(env, owner);
    if (!record) throw new AccountError("The saved account could not be opened");
    return draftFromRecord(record);
  }
  const account = await savedAccountByEmail(env, address);
  return account ? newAccountDraft(account) : null;
}

export async function findAccountDraft(env: AppEnv, account: StoredMailAccount): Promise<AccountDraft | null> {
  const draft = await findAccountDraftByEmail(env, account.address);
  if (draft && canonicalLocator(draft.account) !== canonicalLocator(account)) {
    throw new AccountError("This email address is already configured with another server");
  }
  return draft;
}

export async function commitAccountDraft(env: AppEnv, draft: AccountDraft): Promise<AccountRecord> {
  const parsed = draftSchema.parse(draft);
  const existing = await loadAccountRecord(env, parsed.userId);
  if (parsed.baseRevision === null ? existing !== null : existing?.revision !== parsed.baseRevision) {
    throw new AccountError("Account configuration changed in another reconnect; restart reconnecting");
  }
  const secret = getCredentialsEncryptionSecret(env);
  const index = await newIndexKey(parsed.account.address, secret);
  const owner = await env.OAUTH_KV.get(index);
  if (owner && owner !== parsed.userId) throw new AccountError("This account is already configured; reconnect it");
  const record = recordSchema.parse({
    version: 3,
    userId: parsed.userId,
    revision: (existing?.revision ?? 0) + 1,
    account: parsed.account,
  });
  const key = `${ACCOUNT_KEY_PREFIX}${record.userId}`;
  await env.OAUTH_KV.put(key, await encryptRecord(record, key, secret));
  await env.OAUTH_KV.put(index, record.userId);
  return record;
}

export function accountSummary(account: StoredMailAccount): AccountSummary {
  return {
    accountId: account.accountId,
    label: account.label,
    address: account.address,
    preset: account.preset,
    capabilities: account.capabilities,
  };
}

export async function resolveAccount(env: AppEnv, props: AuthProps, capability?: AccountCapability): Promise<{ account: StoredMailAccount; summary: AccountSummary }> {
  if (props.accountVersion !== 3) throw new AccountError("Reconnect the MCP server and authorize each account separately");
  const record = await loadAccountRecord(env, props.userId);
  if (!record) throw new AccountError("Account is not configured; reconnect the MCP server");
  if (capability && !record.account.capabilities[capability]) throw new AccountError(`The connected account does not support ${capability}`);
  return { account: record.account, summary: accountSummary(record.account) };
}
