import { describe, expect, it } from "vitest";
import { composeRfc822, decodeContentTransfer, decodeBase64, dotStuffForSmtp, parseRfc822 } from "../src/mime";
import type { MessageMetadata } from "../src/types";

const metadata: MessageMetadata = {
  uid: 1,
  flags: [],
  size: 0,
  internalDate: null,
  subject: "Test",
  from: [],
  sender: [],
  replyTo: [],
  to: [],
  cc: [],
  bcc: [],
  inReplyTo: null,
  messageId: "<test@example.com>",
  attachments: [],
};

describe("RFC822 and SMTP MIME handling", () => {
  it("composes bounded multipart mail and dot-stuffs line-leading periods", () => {
    const composed = composeRfc822({
      from: "owner@icloud.com",
      to: ["recipient@example.com"],
      subject: "Café update",
      text: "first\n.second",
      html: "<p>second</p>",
      attachments: [{ filename: "note.txt", mimeType: "text/plain", contentBase64: "bm90ZQ==" }],
      messageId: "<fixed@example.com>",
      date: new Date("2026-08-27T12:00:00Z"),
    });
    const raw = new TextDecoder().decode(composed.raw);
    expect(composed.messageId).toBe("<fixed@example.com>");
    expect(raw).toContain("Content-Type: multipart/mixed");
    expect(raw).toContain("Subject: =?UTF-8?B?");
    expect(raw).not.toContain("Bcc:");
    expect(new TextDecoder().decode(dotStuffForSmtp(new TextEncoder().encode("one\r\n.two\r\n")))).toBe("one\r\n..two\r\n");
    expect(() => composeRfc822({
      from: "owner@icloud.com",
      to: ["recipient@example.com\r\nBcc: attacker@example.com"],
      subject: "bad",
      text: "body",
    })).toThrow(/injection/u);
  });

  it("parses RFC822 bodies and decodes transfer encodings", async () => {
    const raw = new TextEncoder().encode(
      "From: Alice <alice@example.com>\r\nTo: owner@icloud.com\r\nSubject: Hello\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n",
    );
    const parsed = await parseRfc822(raw, metadata, []);
    expect(parsed.text).toContain("Hello");
    expect(parsed.headers.map((header) => header.key)).toContain("subject");
    expect(new TextDecoder().decode(decodeContentTransfer(new TextEncoder().encode("a=3Db"), "quoted-printable"))).toBe("a=b");
    expect(decodeContentTransfer(new Uint8Array([0xc3, 0xa9]), "quoted-printable")).toEqual(new Uint8Array([0xc3, 0xa9]));
    expect(new TextDecoder().decode(decodeBase64("SGk="))).toBe("Hi");
  });
});
