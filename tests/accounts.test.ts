import { describe, expect, it, vi } from "vitest";
import {
  commitAccountDraft,
  findAccountDraft,
  findAccountDraftByEmail,
  loadAccountDraft,
  newAccountDraft,
  resolveAccount,
  saveAccountDraft,
  verifyAccountSubmission,
} from "../src/accounts";
import { storeMailCredentials } from "../src/credentials";
import type { AppEnv, StoredMailAccount } from "../src/types";

class MemoryKv {
  readonly values = new Map<string, string>();

  async put(key: string, value: string): Promise<void> {
    this.values.set(key, value);
  }

  async get(key: string, type?: "json"): Promise<unknown> {
    const value = this.values.get(key);
    if (value === undefined) return null;
    return type === "json" ? JSON.parse(value) as unknown : value;
  }

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }
}

function env(kv = new MemoryKv()): AppEnv {
  return {
    OAUTH_KV: kv as unknown as KVNamespace,
    MAIL_CREDENTIALS_ENCRYPTION_KEY: "test-account-vault-key-that-is-at-least-32-characters",
  } as AppEnv;
}

function account(seed: string, capabilities = { mail: true, calendar: false, contacts: false }): StoredMailAccount {
  return {
    accountId: `acct_${seed.padEnd(22, "x").slice(0, 22)}`,
    label: `Account ${seed}`,
    preset: "custom",
    address: `${seed}@example.com`,
    capabilities,
    config: {
      email: `${seed}@example.com`,
      imapHost: `imap-${seed}.example.com`,
      imapPort: 993,
      imapTlsMode: "implicit",
      imapUser: seed,
      password: "imap-password",
      smtpHost: `smtp-${seed}.example.com`,
      smtpPort: 587,
      smtpTlsMode: "starttls",
      smtpUser: seed,
      smtpPassword: "smtp-password",
    },
  };
}

// Reproduce the persisted v2 format, independently of the new account writer.
async function seedLegacyVault(environment: AppEnv, kv: MemoryKv, accounts: StoredMailAccount[]): Promise<string> {
  const encoder = new TextEncoder();
  const userId = `usr_${"x".repeat(32)}`;
  const keyName = `mail:account-vault:v2:${userId}`;
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(`email-mcp account vault v2\u0000${environment.MAIL_CREDENTIALS_ENCRYPTION_KEY}`));
  const key = await crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(keyName) }, key,
    encoder.encode(JSON.stringify({ version: 2, userId, revision: 1, defaultAccountId: accounts[0].accountId, accounts })));
  const encode = (value: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
  await kv.put(keyName, JSON.stringify({ version: 2, iv: encode(iv), ciphertext: encode(ciphertext) }));
  const hmac = await crypto.subtle.importKey("raw", encoder.encode(environment.MAIL_CREDENTIALS_ENCRYPTION_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  for (const account of accounts) {
    const signature = await crypto.subtle.sign("HMAC", hmac, encoder.encode(`email-mcp account email index v2\u0000${account.address.toLowerCase()}`));
    await kv.put(`mail:account-email-index:v2:${encode(signature)}`, userId);
  }
  return userId;
}

describe("single-account storage", () => {
  it("returns no draft for a verified account that is not attached yet", async () => {
    await expect(findAccountDraft(env(), account("new"))).resolves.toBeNull();
  });

  it("encrypts one account, resolves only version 3 grants, and hides credentials", async () => {
    const kv = new MemoryKv();
    const environment = env(kv);
    const draft = newAccountDraft(account("one"));
    await saveAccountDraft(environment, "state", draft);
    expect(await loadAccountDraft(environment, "state")).toEqual(draft);
    const record = await commitAccountDraft(environment, draft);
    expect((await findAccountDraftByEmail(environment, " ONE@EXAMPLE.COM "))?.userId).toBe(record.userId);
    const selected = await resolveAccount(environment, { userId: record.userId, accountVersion: 3, scopes: [] }, "mail");
    expect(selected.account.accountId).toBe(draft.account.accountId);
    expect(JSON.stringify(selected.summary)).not.toContain("password");
    expect([...kv.values.values()].join(" ")).not.toContain(draft.account.config.password);
    await expect(resolveAccount(environment, { userId: record.userId, scopes: [] })).rejects.toThrow("Reconnect");
    await expect(resolveAccount(environment, { userId: record.userId, accountVersion: 3, scopes: [] }, "calendar")).rejects.toThrow("does not support calendar");
    await expect(commitAccountDraft(environment, draft)).rejects.toThrow("changed");
  });

  it("keeps different accounts in separate records", async () => {
    const environment = env();
    const first = await commitAccountDraft(environment, newAccountDraft(account("one")));
    const second = await commitAccountDraft(environment, newAccountDraft(account("two")));
    expect(first.userId).not.toBe(second.userId);
    const selected = await resolveAccount(environment, { userId: first.userId, accountVersion: 3, scopes: [] });
    expect(selected.account.address).toBe(first.account.address);
    await expect(commitAccountDraft(environment, newAccountDraft(first.account))).rejects.toThrow("already configured");
  });

  it("reconnects v2 sibling accounts into independent records and rejects the old grant", async () => {
    const kv = new MemoryKv();
    const environment = env(kv);
    const first = account("personal");
    const second = account("work");
    const oldUserId = await seedLegacyVault(environment, kv, [first, second]);
    await expect(resolveAccount(environment, { userId: oldUserId, scopes: [] })).rejects.toThrow("Reconnect");
    const firstDraft = await findAccountDraftByEmail(environment, first.address);
    expect(firstDraft?.account).toEqual(first);
    const firstRecord = await commitAccountDraft(environment, firstDraft!);
    const secondDraft = await findAccountDraftByEmail(environment, second.address);
    const secondRecord = await commitAccountDraft(environment, secondDraft!);
    expect(firstRecord.userId).not.toBe(secondRecord.userId);
    expect(firstRecord.userId).not.toBe(oldUserId);
    expect(secondRecord.account).toEqual(second);
    expect(await resolveAccount(environment, { userId: firstRecord.userId, accountVersion: 3, scopes: [] })).toMatchObject({ account: first });
    expect(kv.values.has(`mail:account-vault:v2:${oldUserId}`)).toBe(true);
    expect(JSON.stringify(firstRecord)).not.toContain(second.address);
  });

  it("validates custom host and TLS combinations before opening a socket", async () => {
    const environment = env();
    const base = {
      preset: "custom" as const,
      label: "Custom",
      address: "me@example.com",
      enableMail: true,
      imapHost: "imap.example.com",
      imapPort: 993,
      imapTlsMode: "implicit" as const,
      imapUser: "me",
      imapPassword: "imap-password",
      smtpHost: "smtp.example.com",
      smtpPort: 587,
      smtpTlsMode: "starttls" as const,
      sameSmtpCredentials: true,
    };
    await expect(verifyAccountSubmission(environment, { ...base, imapHost: "127.0.0.1" })).rejects.toThrow(/hostname/u);
    await expect(verifyAccountSubmission(environment, { ...base, smtpPort: 25 })).rejects.toThrow(/Unsupported SMTP/u);
    await expect(verifyAccountSubmission(environment, { ...base, imapHost: "mail.local" })).rejects.toThrow(/public hostname/u);
  });

  it("stores and verifies custom calendar and contacts servers per account", async () => {
    const davVerify = vi.fn(async () => undefined);
    const submission = {
      preset: "custom" as const,
      label: "Other provider",
      address: "me@example.com",
      enableMail: false,
      enableCalendar: true,
      enableContacts: true,
      imapHost: "imap.example.com",
      imapPort: 993,
      imapTlsMode: "implicit" as const,
      imapUser: "calendar-user",
      imapPassword: "account-password",
      smtpHost: "smtp.example.com",
      smtpPort: 587,
      smtpTlsMode: "starttls" as const,
      sameSmtpCredentials: true,
      caldavUrl: "https://dav.example.com/calendar",
      carddavUrl: "https://dav.example.com/contacts",
      davUser: "dav-user",
    };

    const verified = await verifyAccountSubmission(env(), submission, { davVerify });
    expect(verified.capabilities).toEqual({ mail: false, calendar: true, contacts: true });
    expect(verified.davConfig).toEqual({
      caldavUrl: "https://dav.example.com/calendar/",
      carddavUrl: "https://dav.example.com/contacts/",
      username: "dav-user",
    });
    expect(davVerify).toHaveBeenNthCalledWith(1, verified.config, verified.davConfig, "calendar");
    expect(davVerify).toHaveBeenNthCalledWith(2, verified.config, verified.davConfig, "contacts");

    await expect(verifyAccountSubmission(env(), {
      ...submission,
      caldavUrl: "http://127.0.0.1/calendar",
    }, { davVerify })).rejects.toThrow(/secure public calendar server/u);
  });

  it("attempts every enabled discovered service before reporting verification failures", async () => {
    const imapOpen = vi.fn(async () => { throw new Error("imap failed"); });
    const smtpOpen = vi.fn(async () => { throw new Error("smtp failed"); });
    const davVerify = vi.fn(async () => { throw new Error("dav failed"); });
    await expect(verifyAccountSubmission(env(), {
      preset: "custom",
      label: "Discovered",
      address: "me@example.com",
      enableMail: true,
      enableCalendar: true,
      enableContacts: true,
      imapHost: "imap.example.com",
      imapPort: 993,
      imapTlsMode: "implicit",
      imapUser: "me@example.com",
      imapPassword: "password",
      smtpHost: "smtp.example.com",
      smtpPort: 587,
      smtpTlsMode: "starttls",
      sameSmtpCredentials: true,
      caldavUrl: "https://dav.example.com/",
      carddavUrl: "https://dav.example.com/",
      davUser: "me@example.com",
    }, { imapOpen, smtpOpen, davVerify })).rejects.toThrow(/incoming mail, outgoing mail, calendar, contacts/u);
    expect(imapOpen).toHaveBeenCalledOnce();
    expect(smtpOpen).toHaveBeenCalledOnce();
    expect(davVerify).toHaveBeenCalledTimes(2);
  });

  it("loads a legacy iCloud account for reconnect without authorizing its old grant", async () => {
    const environment = env();
    const credentialId = await storeMailCredentials(environment, { email: "legacy@icloud.com", imapUser: "legacy", appPassword: "legacy-password" });
    const draft = await findAccountDraftByEmail(environment, " LEGACY@ICLOUD.COM ");
    expect(draft?.account.address).toBe("legacy@icloud.com");
    expect(draft?.userId).not.toBe(credentialId);
    await expect(resolveAccount(environment, { userId: credentialId, credentialId, scopes: [] })).rejects.toThrow("Reconnect");
  });
  it("returns no draft for an unknown email", async () => {
    expect(await findAccountDraftByEmail(env(), "unknown@icloud.com")).toBeNull();
  });
});
