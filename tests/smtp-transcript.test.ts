import { describe, expect, it } from "vitest";
import { SmtpClient } from "../src/smtp/client";
import type { MailConfig } from "../src/types";
import { mixedChunks, TranscriptSocket } from "./helpers/transcript-socket";

const config: MailConfig = {
  email: "owner@icloud.com",
  imapUser: "owner",
  password: "app-password",
  imapHost: "imap.mail.me.com",
  imapPort: 993,
  smtpHost: "smtp.mail.me.com",
  smtpPort: 587,
};

describe("transcript-backed SMTP socket", () => {
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
});
