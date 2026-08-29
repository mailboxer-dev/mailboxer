import { describe, expect, it, vi } from "vitest";
import {
  AccountVaultError,
  addDraftAccount,
  commitAccountDraft,
  findAccountDraft,
  findAccountDraftByEmail,
  loadAccountDraft,
  loadAccountVault,
  newAccountDraft,
  removeDraftAccount,
  resolveAccount,
  saveAccountDraft,
  setDraftDefault,
  unlockAccountDraft,
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
    MAIL_CREDENTIALS_KV: kv as unknown as KVNamespace,
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

describe("multi-account vault", () => {
  it("returns no draft for a verified account that is not attached yet", async () => {
    await expect(findAccountDraft(env(), account("new"))).resolves.toBeNull();
  });

  it("finds a committed draft by normalized email before credentials are supplied", async () => {
    const environment = env();
    const vault = await commitAccountDraft(environment, newAccountDraft(account("saved")));

    await expect(findAccountDraftByEmail(environment, "  SAVED@EXAMPLE.COM  ")).resolves.toMatchObject({
      userId: vault.userId,
      baseRevision: vault.revision,
      defaultAccountId: vault.defaultAccountId,
    });
  });

  it("encrypts drafts and vaults, routes by default or explicit account, and returns safe summaries", async () => {
    const kv = new MemoryKv();
    const environment = env(kv);
    let draft = newAccountDraft(account("one"));
    const second = account("two");
    draft = setDraftDefault(addDraftAccount(draft, second), second.accountId);

    await saveAccountDraft(environment, "oauth-state", draft);
    expect([...kv.values.values()].join("\n")).not.toContain("imap-password");
    expect((await loadAccountDraft(environment, "oauth-state"))?.accounts).toHaveLength(2);

    const vault = await commitAccountDraft(environment, draft);
    const props = { userId: vault.userId, scopes: ["mail.read"] };
    const selectedDefault = await resolveAccount(environment, props, undefined, "mail");
    expect(selectedDefault.account.accountId).toBe(second.accountId);
    expect(selectedDefault.summary).toMatchObject({ label: "Account two", isDefault: true });

    const selectedFirst = await resolveAccount(environment, props, draft.accounts[0].accountId, "mail");
    expect(selectedFirst.summary).toMatchObject({ address: "one@example.com", isDefault: false });
    expect(JSON.stringify(selectedFirst.summary)).not.toContain("password");
    expect([...kv.values.values()].join("\n")).not.toContain("smtp-password");
  });

  it("enforces revision conflicts, unique upstream accounts, and final-account removal", async () => {
    const environment = env();
    const firstDraft = newAccountDraft(account("same"));
    const firstVault = await commitAccountDraft(environment, firstDraft);
    await expect(commitAccountDraft(environment, firstDraft)).rejects.toThrow(/changed in another reconnect/u);

    const duplicateDraft = newAccountDraft({ ...account("other"), config: firstDraft.accounts[0].config });
    await expect(commitAccountDraft(environment, duplicateDraft)).rejects.toThrow(/already attached/u);
    expect(() => removeDraftAccount({
      userId: firstVault.userId,
      baseRevision: firstVault.revision,
      defaultAccountId: firstVault.defaultAccountId,
      accounts: firstVault.accounts,
    }, firstVault.defaultAccountId)).toThrow(/final account/u);
  });

  it("rejects email ownership conflicts and removes email indexes for deleted accounts", async () => {
    const kv = new MemoryKv();
    const environment = env(kv);
    const removed = account("removed");
    const retained = account("retained");
    const initialDraft = addDraftAccount(newAccountDraft(removed), retained);
    const firstVault = await commitAccountDraft(environment, initialDraft);
    expect([...kv.values.keys()].filter((key) => key.startsWith("mail:account-email-index:v2:")).length).toBe(2);

    const remainingDraft = removeDraftAccount({
      userId: firstVault.userId,
      baseRevision: firstVault.revision,
      defaultAccountId: firstVault.defaultAccountId,
      accounts: firstVault.accounts,
    }, removed.accountId);
    await commitAccountDraft(environment, remainingDraft);

    await expect(findAccountDraftByEmail(environment, removed.address)).resolves.toBeNull();
    await expect(findAccountDraftByEmail(environment, retained.address)).resolves.toMatchObject({ userId: firstVault.userId });
    expect([...kv.values.keys()].filter((key) => key.startsWith("mail:account-email-index:v2:")).length).toBe(1);

    const duplicate = {
      ...account("duplicate"),
      address: retained.address,
      config: { ...account("duplicate").config, email: retained.address },
    };
    await expect(commitAccountDraft(environment, newAccountDraft(duplicate))).rejects.toThrow(/already attached/u);

    const sameAddress = {
      ...account("same-address"),
      address: retained.address,
      config: { ...account("same-address").config, email: retained.address },
    };
    await expect(commitAccountDraft(environment, addDraftAccount(newAccountDraft(retained), sameAddress)))
      .rejects.toThrow(/invalid account list/u);
  });

  it("rejects unknown accounts and unavailable capabilities without exposing configuration", async () => {
    const environment = env();
    const vault = await commitAccountDraft(environment, newAccountDraft(account("mailonly")));
    const props = { userId: vault.userId, scopes: ["mail.read", "calendar.read"] };
    await expect(resolveAccount(environment, props, "acct_aaaaaaaaaaaaaaaaaaaaaa", "mail")).rejects.toThrow("Unknown accountId");
    await expect(resolveAccount(environment, props, vault.defaultAccountId, "calendar")).rejects.toThrow(/does not support calendar/u);
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

  it("loads committed encrypted vaults", async () => {
    const environment = env();
    const vault = await commitAccountDraft(environment, newAccountDraft(account("stored")));
    expect(await loadAccountVault(environment, vault.userId)).toEqual(vault);
    await expect(loadAccountVault(environment, "not-a-user")).resolves.toBeNull();
    expect(AccountVaultError).toBeDefined();
  });

  it("lazily migrates a legacy iCloud record while retaining its user identity", async () => {
    const environment = env();
    const legacyId = await storeMailCredentials(environment, {
      email: "legacy@icloud.com",
      imapUser: "legacy",
      appPassword: "app-password",
    });
    const verified: StoredMailAccount = {
      ...account("legacy", { mail: true, calendar: true, contacts: true }),
      preset: "icloud",
      address: "legacy@icloud.com",
      config: {
        ...account("legacy").config,
        email: "legacy@icloud.com",
        imapHost: "imap.mail.me.com",
        smtpHost: "smtp.mail.me.com",
      },
    };
    const draft = await unlockAccountDraft(environment, verified);
    expect(draft.userId).toBe(legacyId);
    const migrated = await commitAccountDraft(environment, draft);
    expect(migrated.userId).toBe(legacyId);
    expect(await loadAccountVault(environment, legacyId)).toEqual(migrated);
  });

  it("finds a legacy iCloud record by normalized email", async () => {
    const environment = env();
    const legacyId = await storeMailCredentials(environment, {
      email: "legacy@icloud.com",
      imapUser: "legacy",
      appPassword: "app-password",
    });

    await expect(findAccountDraftByEmail(environment, " LEGACY@ICLOUD.COM ")).resolves.toMatchObject({
      userId: legacyId,
      baseRevision: null,
    });
  });

  it("returns no draft for an unknown email", async () => {
    await expect(findAccountDraftByEmail(env(), "unknown@example.com")).resolves.toBeNull();
  });
});
