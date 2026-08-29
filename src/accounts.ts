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
import { withSpan } from "./tracing";
import { customDavConfig, ICLOUD_DAV_CONFIG } from "./providers";
import type {
  AccountCapability,
  AccountSummary,
  AccountVaultV2,
  AppEnv,
  AuthProps,
  MailConfig,
  DavConfig,
  StoredMailAccount,
} from "./types";

const VAULT_KEY_PREFIX = "mail:account-vault:v2:";
const INDEX_KEY_PREFIX = "mail:account-index:v2:";
const EMAIL_INDEX_KEY_PREFIX = "mail:account-email-index:v2:";
const DRAFT_KEY_PREFIX = "mail:account-draft:v2:";
const VAULT_CONTEXT = "email-mcp account vault v2\u0000";
const INDEX_CONTEXT = "email-mcp account locator v2\u0000";
const EMAIL_INDEX_CONTEXT = "email-mcp account email index v2\u0000";
const MAX_VAULT_BYTES = 96 * 1024;
const MAX_ACCOUNTS = 10;
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
const vaultSchema = z.object({
  version: z.literal(2),
  userId: userIdSchema,
  revision: z.number().int().min(1),
  defaultAccountId: accountIdSchema,
  accounts: z.array(storedAccountSchema).min(1).max(MAX_ACCOUNTS),
});
const envelopeSchema = z.object({
  version: z.literal(2),
  iv: z.string().min(1).max(64),
  ciphertext: z.string().min(1).max(MAX_VAULT_BYTES * 2),
});

export interface AccountDraft {
  userId: string;
  baseRevision: number | null;
  defaultAccountId: string;
  accounts: StoredMailAccount[];
}

const draftSchema = z.object({
  userId: userIdSchema,
  baseRevision: z.number().int().min(1).nullable(),
  defaultAccountId: accountIdSchema,
  accounts: z.array(storedAccountSchema).min(1).max(MAX_ACCOUNTS),
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

export class AccountVaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccountVaultError";
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
  if (plaintext.byteLength > MAX_VAULT_BYTES) throw new AccountVaultError("Account configuration is too large");
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
    if (error instanceof AccountVaultError) throw error;
    throw new AccountVaultError("Stored account configuration cannot be decrypted");
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
    throw new AccountVaultError(`Enter a valid public hostname for ${field}`);
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(hostname) || hostname.includes(":") || hasControl) {
    throw new AccountVaultError(`${field} must be a hostname, not an IP address`);
  }
  if (/(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid)$/u.test(hostname)) {
    throw new AccountVaultError(`${field} must be a public hostname`);
  }
  const labels = hostname.split(".");
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) {
    throw new AccountVaultError(`Enter a valid public hostname for ${field}`);
  }
  return hostname;
}

function assertTransport(port: number, mode: "implicit" | "starttls", service: "IMAP" | "SMTP"): void {
  const valid = service === "IMAP"
    ? (port === 993 && mode === "implicit") || (port === 143 && mode === "starttls")
    : (port === 465 && mode === "implicit") || ([587, 2525].includes(port) && mode === "starttls");
  if (!valid) throw new AccountVaultError(`Unsupported ${service} port and TLS mode combination`);
}

function capabilitiesFor(submission: AccountSubmission): StoredMailAccount["capabilities"] {
  const capabilities = {
    mail: submission.enableMail !== false,
    calendar: submission.enableCalendar === true,
    contacts: submission.enableContacts === true,
  };
  if (!capabilities.mail && !capabilities.calendar && !capabilities.contacts) {
    throw new AccountVaultError("Enable at least one service for this account");
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
    throw new AccountVaultError(`We couldn't connect ${failed.map((service) => labels[service]).join(", ")}`);
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
      throw new AccountVaultError(error instanceof Error ? error.message : "Enter valid calendar and contacts server addresses");
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

async function indexKey(account: StoredMailAccount, secret: string): Promise<string> {
  return locatorIndexKey(canonicalLocator(account), secret);
}

async function emailIndexKey(email: string, secret: string): Promise<string> {
  return `${EMAIL_INDEX_KEY_PREFIX}${await indexDigest(normalizeAddress(email), EMAIL_INDEX_CONTEXT, secret)}`;
}

function validateVault(vault: AccountVaultV2): AccountVaultV2 {
  const parsed = vaultSchema.parse(vault);
  const ids = new Set(parsed.accounts.map((account) => account.accountId));
  const locators = new Set(parsed.accounts.map(canonicalLocator));
  const addresses = new Set(parsed.accounts.map((account) => normalizeAddress(account.address)));
  if (ids.size !== parsed.accounts.length || locators.size !== parsed.accounts.length || addresses.size !== parsed.accounts.length || !ids.has(parsed.defaultAccountId)) {
    throw new AccountVaultError("Account vault has an invalid account list or default account");
  }
  return parsed;
}

export function newAccountDraft(account: StoredMailAccount): AccountDraft {
  const userId = randomId("usr_");
  return { userId, baseRevision: null, defaultAccountId: account.accountId, accounts: [account] };
}

export async function loadAccountVault(env: AppEnv, userId: string): Promise<AccountVaultV2 | null> {
  if (!userIdSchema.safeParse(userId).success) return null;
  const key = `${VAULT_KEY_PREFIX}${userId}`;
  const value = await env.OAUTH_KV.get(key);
  if (!value) return null;
  const decrypted = await decryptRecord(value, key, getCredentialsEncryptionSecret(env));
  return validateVault(vaultSchema.parse(decrypted));
}

export async function saveAccountDraft(env: AppEnv, state: string, draft: AccountDraft): Promise<void> {
  const parsed = draftSchema.parse(draft);
  const key = `${DRAFT_KEY_PREFIX}${state}`;
  const encrypted = await encryptRecord(parsed, key, getCredentialsEncryptionSecret(env));
  await env.OAUTH_KV.put(key, encrypted, { expirationTtl: ACCOUNT_DRAFT_TTL_SECONDS });
}

export async function loadAccountDraft(env: AppEnv, state: string): Promise<AccountDraft | null> {
  const key = `${DRAFT_KEY_PREFIX}${state}`;
  const value = await env.OAUTH_KV.get(key);
  if (!value) return null;
  return draftSchema.parse(await decryptRecord(value, key, getCredentialsEncryptionSecret(env)));
}

export async function deleteAccountDraft(env: AppEnv, state: string): Promise<void> {
  await env.OAUTH_KV.delete(`${DRAFT_KEY_PREFIX}${state}`);
}

function draftFromVault(vault: AccountVaultV2): AccountDraft {
  return {
    userId: vault.userId,
    baseRevision: vault.revision,
    defaultAccountId: vault.defaultAccountId,
    accounts: vault.accounts,
  };
}

async function loadDraftForOwner(env: AppEnv, owner: string): Promise<AccountDraft> {
  const vault = await loadAccountVault(env, owner);
  if (!vault) throw new AccountVaultError("The account profile could not be unlocked");
  return draftFromVault(vault);
}

async function loadLegacyAccountDraftByEmail(env: AppEnv, email: string, secret: string): Promise<AccountDraft | null> {
  const legacyId = await credentialIdForEmail(email, secret);
  try {
    const credentials = await loadMailCredentials(env, legacyId);
    const account = storedAccountSchema.parse({
      accountId: randomId("acct_"),
      label: "iCloud",
      preset: "icloud",
      address: normalizeAddress(credentials.email),
      capabilities: { mail: true, calendar: true, contacts: true },
      config: getMailConfig(env, credentials),
    });
    return {
      userId: legacyId,
      baseRevision: null,
      defaultAccountId: account.accountId,
      accounts: [account],
    };
  } catch (error) {
    if (!(error instanceof MailCredentialError)) throw error;
    return null;
  }
}

export async function findAccountDraftByEmail(env: AppEnv, email: string): Promise<AccountDraft | null> {
  const parsedEmail = z.string().trim().email().max(320).safeParse(email);
  if (!parsedEmail.success) return null;
  const normalizedEmail = normalizeAddress(parsedEmail.data);
  const secret = getCredentialsEncryptionSecret(env);

  const owner = await env.OAUTH_KV.get(await emailIndexKey(normalizedEmail, secret));
  if (owner) return loadDraftForOwner(env, owner);

  // Older v2 iCloud accounts only have the locator index, which is also email-based.
  const legacyLocatorOwner = await env.OAUTH_KV.get(
    await locatorIndexKey(`icloud\u0000${normalizedEmail}`, secret),
  );
  if (legacyLocatorOwner) return loadDraftForOwner(env, legacyLocatorOwner);

  // Before account vaults existed, iCloud credentials were keyed by a digest of the email.
  return loadLegacyAccountDraftByEmail(env, normalizedEmail, secret);
}

export async function commitAccountDraft(env: AppEnv, draft: AccountDraft): Promise<AccountVaultV2> {
  return withSpan("mail.accounts.commit", { "mail.accounts.count": draft.accounts.length }, async () => {
    const parsed = draftSchema.parse(draft);
    const existing = await loadAccountVault(env, parsed.userId);
    if (parsed.baseRevision === null ? existing !== null : existing?.revision !== parsed.baseRevision) {
      throw new AccountVaultError("Account configuration changed in another reconnect; restart reconnecting");
    }
    const vault = validateVault({
      version: 2,
      userId: parsed.userId,
      revision: (existing?.revision ?? 0) + 1,
      defaultAccountId: parsed.defaultAccountId,
      accounts: parsed.accounts,
    });
    const secret = getCredentialsEncryptionSecret(env);
    const nextLocatorKeys = await Promise.all(vault.accounts.map((account) => indexKey(account, secret)));
    const nextEmailKeys = [...new Set(await Promise.all(vault.accounts.map((account) => emailIndexKey(account.address, secret))))];
    const nextKeys = [...new Set([...nextLocatorKeys, ...nextEmailKeys])];
    for (const key of nextKeys) {
      const owner = await env.OAUTH_KV.get(key);
      if (owner && owner !== vault.userId) throw new AccountVaultError("This upstream account is already attached to another profile");
    }
    const vaultKey = `${VAULT_KEY_PREFIX}${vault.userId}`;
    await env.OAUTH_KV.put(vaultKey, await encryptRecord(vault, vaultKey, secret));
    await Promise.all(nextKeys.map((key) => env.OAUTH_KV.put(key, vault.userId)));
    if (existing) {
      const oldLocatorKeys = await Promise.all(existing.accounts.map((account) => indexKey(account, secret)));
      const oldEmailKeys = [...new Set(await Promise.all(existing.accounts.map((account) => emailIndexKey(account.address, secret))))];
      const oldKeys = [...new Set([...oldLocatorKeys, ...oldEmailKeys])];
      await Promise.all(oldKeys.filter((key) => !nextKeys.includes(key)).map((key) => env.OAUTH_KV.delete(key)));
    }
    return vault;
  });
}

export async function findAccountDraft(env: AppEnv, verifiedAccount: StoredMailAccount): Promise<AccountDraft | null> {
  const secret = getCredentialsEncryptionSecret(env);
  const owner = await env.OAUTH_KV.get(await indexKey(verifiedAccount, secret));
  if (owner) {
    return loadDraftForOwner(env, owner);
  }
  if (verifiedAccount.preset === "icloud") {
    const legacyId = await credentialIdForEmail(verifiedAccount.address, secret);
    try {
      await loadMailCredentials(env, legacyId);
      return {
        userId: legacyId,
        baseRevision: null,
        defaultAccountId: verifiedAccount.accountId,
        accounts: [verifiedAccount],
      };
    } catch (error) {
      if (!(error instanceof MailCredentialError)) throw error;
    }
  }
  return null;
}

export async function unlockAccountDraft(env: AppEnv, verifiedAccount: StoredMailAccount): Promise<AccountDraft> {
  const draft = await findAccountDraft(env, verifiedAccount);
  if (!draft) throw new AccountVaultError("The account profile could not be unlocked");
  return draft;
}

export function accountSummary(account: StoredMailAccount, defaultAccountId: string): AccountSummary {
  return {
    accountId: account.accountId,
    label: account.label,
    address: account.address,
    preset: account.preset,
    capabilities: account.capabilities,
    isDefault: account.accountId === defaultAccountId,
  };
}

export async function listAccountsForUser(env: AppEnv, props: AuthProps): Promise<{ accounts: AccountSummary[]; defaultAccountId: string }> {
  const vault = await loadAccountVault(env, props.userId);
  if (vault) return {
    accounts: vault.accounts.map((account) => accountSummary(account, vault.defaultAccountId)),
    defaultAccountId: vault.defaultAccountId,
  };
  if (!props.credentialId) throw new AccountVaultError("Accounts are not configured; reconnect the MCP server");
  const credentials = await loadMailCredentials(env, props.credentialId);
  const accountId = props.credentialId;
  return {
    accounts: [{
      accountId,
      label: "iCloud",
      address: credentials.email,
      preset: "icloud",
      capabilities: { mail: true, calendar: true, contacts: true },
      isDefault: true,
    }],
    defaultAccountId: accountId,
  };
}

export async function resolveAccount(
  env: AppEnv,
  props: AuthProps,
  accountId?: string,
  capability?: AccountCapability,
): Promise<{ account: StoredMailAccount; summary: AccountSummary }> {
  return withSpan("mail.accounts.resolve", { "mail.accounts.capability": capability }, async (span) => {
    const vault = await loadAccountVault(env, props.userId);
    if (vault) {
      const selectedId = accountId ?? vault.defaultAccountId;
      const account = vault.accounts.find((candidate) => candidate.accountId === selectedId);
      if (!account) throw new AccountVaultError("Unknown accountId");
      if (capability && !account.capabilities[capability]) throw new AccountVaultError(`The selected account does not support ${capability}`);
      span.setAttribute("mail.accounts.preset", account.preset);
      span.setAttribute("mail.accounts.count", vault.accounts.length);
      span.setAttribute("mail.accounts.imap_tls", account.config.imapTlsMode);
      span.setAttribute("mail.accounts.smtp_tls", account.config.smtpTlsMode);
      return { account, summary: accountSummary(account, vault.defaultAccountId) };
    }
    if (!props.credentialId || (accountId && accountId !== props.credentialId)) throw new AccountVaultError("Unknown accountId");
    const credentials = await loadMailCredentials(env, props.credentialId);
    const account: StoredMailAccount = {
      accountId: props.credentialId,
      label: "iCloud",
      preset: "icloud",
      address: credentials.email,
      capabilities: { mail: true, calendar: true, contacts: true },
      config: getMailConfig(env, credentials),
    };
    span.setAttribute("mail.accounts.preset", "icloud");
    span.setAttribute("mail.accounts.imap_tls", "implicit");
    span.setAttribute("mail.accounts.smtp_tls", "starttls");
    return { account, summary: accountSummary(account, account.accountId) };
  });
}

export function addDraftAccount(draft: AccountDraft, account: StoredMailAccount): AccountDraft {
  if (draft.accounts.length >= MAX_ACCOUNTS) throw new AccountVaultError(`A profile can contain at most ${MAX_ACCOUNTS} accounts`);
  return draftSchema.parse({ ...draft, accounts: [...draft.accounts, account] });
}

export function replaceDraftAccount(draft: AccountDraft, account: StoredMailAccount): AccountDraft {
  if (!draft.accounts.some((candidate) => candidate.accountId === account.accountId)) throw new AccountVaultError("Unknown accountId");
  return draftSchema.parse({ ...draft, accounts: draft.accounts.map((candidate) => candidate.accountId === account.accountId ? account : candidate) });
}

export function removeDraftAccount(draft: AccountDraft, accountId: string): AccountDraft {
  if (draft.accounts.length === 1) throw new AccountVaultError("The final account cannot be removed");
  const accounts = draft.accounts.filter((account) => account.accountId !== accountId);
  if (accounts.length === draft.accounts.length) throw new AccountVaultError("Unknown accountId");
  return draftSchema.parse({
    ...draft,
    accounts,
    defaultAccountId: draft.defaultAccountId === accountId ? accounts[0].accountId : draft.defaultAccountId,
  });
}

export function setDraftDefault(draft: AccountDraft, accountId: string): AccountDraft {
  if (!draft.accounts.some((account) => account.accountId === accountId)) throw new AccountVaultError("Unknown accountId");
  return draftSchema.parse({ ...draft, defaultAccountId: accountId });
}
