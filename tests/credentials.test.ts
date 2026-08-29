import { describe, expect, it, vi } from "vitest";
import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import {
  credentialIdForEmail,
  loadMailCredentials,
  MailCredentialError,
  storeMailCredentials,
  verifyMailCredentials,
} from "../src/credentials";
import type { ImapClient } from "../src/imap/client";
import type { SmtpClient } from "../src/smtp/client";
import type { AppEnv, MailConfig, MailCredentials } from "../src/types";

class MemoryKv {
  private readonly values = new Map<string, string>();

  async put(key: string, value: string, _options?: unknown): Promise<void> {
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

  raw(key: string): string | undefined {
    return this.values.get(key);
  }
}

const encryptionKey = "a-secure-test-encryption-key-with-32-chars";

function env(credentialsKv: MemoryKv, key = encryptionKey): AppEnv {
  return {
    OAUTH_KV: {} as KVNamespace,
    MAIL_CREDENTIALS_KV: credentialsKv as unknown as KVNamespace,
    OAUTH_PROVIDER: {} as OAuthHelpers,
    MAIL_CREDENTIALS_ENCRYPTION_KEY: key,
  };
}

describe("encrypted iCloud credential storage", () => {
  it("stores credentials as encrypted ciphertext and can load them again", async () => {
    const credentialsKv = new MemoryKv();
    const environment = env(credentialsKv);
    const credentials: MailCredentials = {
      email: "Owner@iCloud.com",
      imapUser: "Owner",
      appPassword: "abcd-efgh-ijkl-mnop",
    };

    const credentialId = await storeMailCredentials(environment, credentials);
    const raw = credentialsKv.raw(`mail:credentials:v1:${credentialId}`) ?? "";

    expect(credentialId).toMatch(/^icloud-[A-Za-z0-9_-]{43}$/u);
    expect(raw).not.toContain("Owner@iCloud.com");
    expect(raw).not.toContain("abcd-efgh-ijkl-mnop");
    await expect(loadMailCredentials(environment, credentialId)).resolves.toEqual({
      email: "owner@icloud.com",
      imapUser: "Owner",
      appPassword: "abcd-efgh-ijkl-mnop",
    });
  });

  it("derives a stable opaque ID from the normalized email and encryption key", async () => {
    await expect(credentialIdForEmail("Owner@iCloud.com", encryptionKey))
      .resolves.toBe(await credentialIdForEmail(" owner@icloud.com ", encryptionKey));
    await expect(credentialIdForEmail("other@icloud.com", encryptionKey))
      .resolves.not.toBe(await credentialIdForEmail("owner@icloud.com", encryptionKey));
  });

  it("rejects records with a different key or modified ciphertext", async () => {
    const credentialsKv = new MemoryKv();
    const environment = env(credentialsKv);
    const credentialId = await storeMailCredentials(environment, {
      email: "owner@icloud.com",
      imapUser: "owner",
      appPassword: "abcd-efgh-ijkl-mnop",
    });

    await expect(loadMailCredentials(env(credentialsKv, "another-secure-test-key-with-32-chars"), credentialId))
      .rejects.toBeInstanceOf(MailCredentialError);

    const raw = JSON.parse(credentialsKv.raw(`mail:credentials:v1:${credentialId}`) ?? "{}") as { ciphertext: string };
    raw.ciphertext = `${raw.ciphertext.slice(0, -1)}${raw.ciphertext.endsWith("A") ? "B" : "A"}`;
    await credentialsKv.put(`mail:credentials:v1:${credentialId}`, JSON.stringify(raw));
    await expect(loadMailCredentials(environment, credentialId)).rejects.toBeInstanceOf(MailCredentialError);
  });

  it("verifies IMAP and SMTP before returning storable credentials", async () => {
    const credentialsKv = new MemoryKv();
    const environment = env(credentialsKv);
    const imapClose = vi.fn();
    const smtpAuthenticate = vi.fn(async () => undefined);
    const smtpQuit = vi.fn(async () => undefined);
    const smtpClose = vi.fn();
    const imapOpen = vi.fn(async (config: MailConfig) => {
      if (imapOpen.mock.calls.length === 1) throw new Error("local-part rejected");
      expect(config.imapUser).toBe("owner@icloud.com");
      return { close: imapClose };
    });
    const smtpOpen = vi.fn(async (config: MailConfig) => {
      expect(config.email).toBe("owner@icloud.com");
      expect(config.password).toBe("abcd-efgh-ijkl-mnop");
      return {
        authenticate: smtpAuthenticate,
        quit: smtpQuit,
        close: smtpClose,
      };
    });

    await expect(verifyMailCredentials(
      environment,
      { email: "Owner@iCloud.com", appPassword: "abcd-efgh-ijkl-mnop" },
      {
        imapOpen: imapOpen as unknown as typeof ImapClient.open,
        smtpOpen: smtpOpen as unknown as typeof SmtpClient.open,
      },
    )).resolves.toEqual({
      email: "owner@icloud.com",
      imapUser: "owner@icloud.com",
      appPassword: "abcd-efgh-ijkl-mnop",
    });
    expect(imapOpen).toHaveBeenCalledTimes(2);
    expect(smtpAuthenticate).toHaveBeenCalledOnce();
    expect(smtpQuit).toHaveBeenCalledOnce();
    expect(smtpClose).toHaveBeenCalledOnce();
  });

  it("does not expose protocol failures as credential details", async () => {
    const environment = env(new MemoryKv());
    const failingOpen = vi.fn(async () => {
      throw new Error("server said a private diagnostic");
    });

    await expect(verifyMailCredentials(environment, {
      email: "owner@icloud.com",
      appPassword: "abcd-efgh-ijkl-mnop",
    }, { imapOpen: failingOpen as unknown as typeof ImapClient.open })).rejects.toEqual(
      new MailCredentialError("iCloud credentials could not be verified"),
    );
  });

  it("verifies only the services requested by a calendar-only grant", async () => {
    const environment = env(new MemoryKv());
    const imapOpen = vi.fn(async () => { throw new Error("IMAP must not be contacted"); });
    const smtpOpen = vi.fn(async () => { throw new Error("SMTP must not be contacted"); });
    const davVerify = vi.fn(async (_config: MailConfig, service: "calendar" | "contacts") => {
      expect(service).toBe("calendar");
    });
    await expect(verifyMailCredentials(
      environment,
      { email: "owner@icloud.com", appPassword: "abcd-efgh-ijkl-mnop" },
      ["calendar.read"],
      {
        imapOpen: imapOpen as unknown as typeof ImapClient.open,
        smtpOpen: smtpOpen as unknown as typeof SmtpClient.open,
        davVerify,
      },
    )).resolves.toEqual({
      email: "owner@icloud.com",
      imapUser: "owner",
      appPassword: "abcd-efgh-ijkl-mnop",
    });
    expect(imapOpen).not.toHaveBeenCalled();
    expect(smtpOpen).not.toHaveBeenCalled();
    expect(davVerify).toHaveBeenCalledOnce();
  });

  it("does not probe SMTP for a read-only mail grant", async () => {
    const environment = env(new MemoryKv());
    const imapClose = vi.fn();
    const imapOpen = vi.fn(async () => ({ close: imapClose }));
    const smtpOpen = vi.fn(async () => { throw new Error("SMTP must not be contacted"); });
    await expect(verifyMailCredentials(
      environment,
      { email: "owner@icloud.com", appPassword: "abcd-efgh-ijkl-mnop" },
      ["mail.read"],
      {
        imapOpen: imapOpen as unknown as typeof ImapClient.open,
        smtpOpen: smtpOpen as unknown as typeof SmtpClient.open,
      },
    )).resolves.toMatchObject({ email: "owner@icloud.com" });
    expect(imapOpen).toHaveBeenCalledOnce();
    expect(smtpOpen).not.toHaveBeenCalled();
  });
});
