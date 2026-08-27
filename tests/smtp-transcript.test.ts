import { describe, expect, it } from "vitest";
import { SMTP_SOCKET_OPTIONS, smtpSocketOptions, SmtpClient } from "../src/smtp/client";
import type { MailConfig } from "../src/types";
import { mixedChunks, TranscriptSocket } from "./helpers/transcript-socket";

const config = {
  email: "owner@icloud.com",
  imapUser: "owner",
  password: "app-password",
  imapHost: "imap.mail.me.com",
  imapPort: 993,
  smtpHost: "smtp.mail.me.com",
  smtpPort: 587,
  imapTlsMode: "implicit",
  smtpTlsMode: "starttls",
  smtpUser: "smtp-user@example.com",
  smtpPassword: "smtp-password",
} as MailConfig;

describe("transcript-backed SMTP socket", () => {
  it("enables Cloudflare STARTTLS upgrades on the initial socket", () => {
    expect(SMTP_SOCKET_OPTIONS).toEqual({ secureTransport: "starttls", allowHalfOpen: false });
    expect(smtpSocketOptions(config)).toEqual({ secureTransport: "starttls", allowHalfOpen: false });
  });

  it("performs STARTTLS, authenticates, and dot-stuffs DATA", async () => {
    const socket = new TranscriptSocket(mixedChunks(
      "220 smtp.mail.me.com ESMTP ready\r\n",
      "250-smtp.mail.me.com\r\n250 STARTTLS\r\n",
      "220 2.0.0 Ready to start TLS\r\n",
      "250-smtp.mail.me.com\r\n250 AUTH PLAIN\r\n",
      "235 2.7.0 Authentication successful\r\n",
      "250 2.1.0 OK\r\n",
      "250 2.1.5 OK\r\n",
      "354 End data with <CR><LF>.<CR><LF>\r\n",
      "250 2.0.0 queued\r\n",
      "221 2.0.0 bye\r\n",
    ));
    const client = await SmtpClient.open(config, async () => socket);
    try {
      const result = await client.send({
        from: config.email,
        to: ["recipient@example.com"],
        subject: "Transcript",
        text: "one\r\n.two",
        messageId: "<smtp-test@example.com>",
        date: new Date("2026-08-27T12:00:00Z"),
      });
      expect(result.messageId).toBe("<smtp-test@example.com>");
      expect(socket.outputText()).toContain("STARTTLS\r\n");
      expect(socket.outputText()).toContain("\r\n..two\r\n");
      expect(socket.outputText()).not.toContain("\r\n.two\r\n");
    } finally {
      await client.quit();
      client.close();
    }
  });

  it("prefers AUTH PLAIN and uses the configured SMTP credentials", async () => {
    const socket = new TranscriptSocket(mixedChunks(
      "220 smtp.example ESMTP ready\r\n",
      "250-smtp.example\r\n250-STARTTLS\r\n250 AUTH LOGIN PLAIN\r\n",
      "220 Ready to start TLS\r\n",
      "250-smtp.example\r\n250 AUTH PLAIN\r\n",
      "235 Authenticated\r\n",
    ));
    const client = await SmtpClient.open(config, async () => socket);
    try {
      await client.authenticate();
      const expected = btoa("\u0000smtp-user@example.com\u0000smtp-password");
      expect(socket.outputText()).toContain(`AUTH PLAIN ${expected}\r\n`);
      expect(socket.outputText()).not.toContain("owner@icloud.com");
    } finally {
      client.close();
    }
  });

  it("falls back to the AUTH LOGIN challenge sequence", async () => {
    const implicitConfig = {
      ...config,
      smtpHost: "smtp.example",
      smtpPort: 465,
      smtpTlsMode: "implicit",
    } as MailConfig;
    const socket = new TranscriptSocket(mixedChunks(
      "220 smtp.example ESMTP ready\r\n",
      "250-smtp.example\r\n250 AUTH LOGIN\r\n",
      "334 VXNlcm5hbWU6\r\n",
      "334 UGFzc3dvcmQ6\r\n",
      "235 Authenticated\r\n",
    ));
    const client = await SmtpClient.open(implicitConfig, async () => socket);
    try {
      await client.authenticate();
      const output = socket.outputText();
      expect(output).toContain("AUTH LOGIN\r\n");
      expect(output).toContain(`${btoa("smtp-user@example.com")}\r\n`);
      expect(output).toContain(`${btoa("smtp-password")}\r\n`);
      expect(output).not.toContain("STARTTLS\r\n");
    } finally {
      client.close();
    }
  });

  it("uses implicit TLS on port 465 and STARTTLS on port 2525", () => {
    expect(smtpSocketOptions({ ...config, smtpPort: 465, smtpTlsMode: "implicit" } as MailConfig)).toEqual({
      secureTransport: "on",
      allowHalfOpen: false,
    });
    expect(smtpSocketOptions({ ...config, smtpPort: 2525, smtpTlsMode: "starttls" } as MailConfig)).toEqual({
      secureTransport: "starttls",
      allowHalfOpen: false,
    });
  });

  it("rejects STARTTLS mode on an unsupported port", () => {
    expect(() => smtpSocketOptions({ ...config, smtpPort: 465, smtpTlsMode: "starttls" } as MailConfig)).toThrow(
      /STARTTLS requires port 587 or 2525/u,
    );
  });

  it("rejects a STARTTLS server that omits the STARTTLS capability", async () => {
    const socket = new TranscriptSocket(mixedChunks(
      "220 smtp.example ESMTP ready\r\n",
      "250-smtp.example\r\n250 AUTH PLAIN\r\n",
    ));
    const client = await SmtpClient.open(config, async () => socket);
    await expect(client.authenticate()).rejects.toThrow(/does not advertise STARTTLS/u);
    client.close();
  });
});
