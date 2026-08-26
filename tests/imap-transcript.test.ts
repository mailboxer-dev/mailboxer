import { describe, expect, it } from "vitest";
import { ImapClient } from "../src/imap/client";
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

describe("transcript-backed IMAP socket", () => {
  it("handles tagged commands, mailbox parsing, UID search, and literals", async () => {
    const rawMessage = "Subject: x\r\n\r\nHi\r\n";
    const socket = new TranscriptSocket(mixedChunks(
      "* OK iCloud IMAP ready\r\n",
      "A0001 OK LOGIN completed\r\n",
      "* CAPABILITY IMAP4rev1 UIDPLUS MOVE\r\nA0002 OK CAPABILITY completed\r\n",
      "* LIST (\\HasNoChildren \\Sent) \"/\" \"Sent\"\r\n",
      "* LIST (\\HasNoChildren \\Trash) \"/\" \"Deleted\"\r\n",
      "A0003 OK LIST completed\r\n",
      "* 1 EXISTS\r\nA0004 OK EXAMINE completed\r\n",
      "* SEARCH 3 2 1\r\nA0005 OK SEARCH completed\r\n",
      `* 1 FETCH (UID 3 RFC822.SIZE ${rawMessage.length} BODY[] {${rawMessage.length}}\r\n`,
      new TextEncoder().encode(rawMessage),
      ")\r\nA0006 OK FETCH completed\r\n",
    ));
    const client = await ImapClient.open(config, async () => socket);
    try {
      const mailboxes = await client.listMailboxes();
      expect(mailboxes.map((mailbox) => mailbox.specialUse)).toEqual(["\\Sent", "\\Trash"]);
      expect(await client.search("INBOX", {})).toEqual([3, 2, 1]);
      expect(new TextDecoder().decode(await client.fetchRaw("INBOX", 3, rawMessage.length))).toBe(rawMessage);
      expect(socket.outputText()).toContain('A0001 LOGIN "owner" "app-password"');
      expect(socket.remainingChunks()).toBe(0);
    } finally {
      client.close();
    }
  });
});
