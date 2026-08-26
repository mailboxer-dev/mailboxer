import { describe, expect, it } from "vitest";
import { parseFetchMetadata, parseSearchResponse } from "../src/imap/parsers";

describe("IMAP metadata parser", () => {
  it("handles line-wrapped FETCH responses and discovers attachment parts", () => {
    const metadata = parseFetchMetadata([
      '* 7 FETCH (UID 42 FLAGS (\\Seen \\Flagged) RFC822.SIZE 123 INTERNALDATE "27-Aug-2026 12:00:00 +0000"',
      ' ENVELOPE ("Thu, 27 Aug 2026 12:00:00 +0000" "Subject" (("Alice" NIL "alice" "example.com")) NIL NIL (("Owner" NIL "owner" "icloud.com")) NIL NIL NIL "<message@example.com>")',
      ' BODYSTRUCTURE (("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" "10" "1") ("APPLICATION" "PDF" ("NAME" "report.pdf") NIL NIL "BASE64" "12") "MIXED"))',
      "A0001 OK FETCH completed",
    ]);
    expect(metadata).toMatchObject({
      uid: 42,
      flags: ["\\Seen", "\\Flagged"],
      subject: "Subject",
      from: [{ name: "Alice", address: "alice@example.com" }],
      to: [{ name: "Owner", address: "owner@icloud.com" }],
      messageId: "<message@example.com>",
      attachments: [{ part: "2", filename: "report.pdf", mimeType: "application/pdf", size: 12 }],
    });
  });

  it("finds filenames stored in BODYSTRUCTURE disposition parameters", () => {
    const metadata = parseFetchMetadata([
      '* 9 FETCH (UID 9 BODYSTRUCTURE ("APPLICATION" "OCTET-STREAM" NIL NIL NIL "BASE64" "4" ("ATTACHMENT" ("FILENAME" "archive.bin")) NIL))',
      "A0001 OK FETCH completed",
    ]);
    expect(metadata?.attachments).toEqual([
      expect.objectContaining({ part: "1", filename: "archive.bin", mimeType: "application/octet-stream" }),
    ]);
  });

  it("combines wrapped SEARCH result lines", () => {
    expect(parseSearchResponse(["* SEARCH 9 8", "* SEARCH 7", "A0002 OK SEARCH completed"])).toEqual([9, 8, 7]);
  });
});
