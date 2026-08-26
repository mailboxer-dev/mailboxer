import { describe, expect, it } from "vitest";
import {
  decodeModifiedUtf7,
  encodeModifiedUtf7,
  formatImapDate,
  formatUidSet,
  quoteImapMailboxName,
  parseImapValues,
  quoteImapString,
} from "../src/imap/codec";

describe("IMAP codec", () => {
  it("round-trips modified UTF-7, including ampersands and astral UTF-16 pairs", () => {
    const mailbox = "Archive & Café 📬";
    expect(decodeModifiedUtf7(encodeModifiedUtf7(mailbox))).toBe(mailbox);
    expect(encodeModifiedUtf7("A&B")).toBe("A&-B");
    expect(encodeModifiedUtf7("Café")).toContain("&AOk-");
  });

  it("quotes strings and rejects command injection characters", () => {
    expect(quoteImapString('A"B')).toBe('"A\\"B"');
    expect(quoteImapMailboxName("Café")).toBe('"Caf&AOk-"');
    expect(() => quoteImapString("safe\r\nNOOP")).toThrow(/control character/u);
  });

  it("parses nested tagged values and validates dates and UIDs", () => {
    expect(parseImapValues('(\\Seen "hello" NIL ("nested" 4))')).toEqual([
      ["\\Seen", "hello", null, ["nested", "4"]],
    ]);
    expect(formatImapDate("2026-02-03")).toBe("3-Feb-2026");
    expect(() => formatImapDate("2026-02-30")).toThrow(/calendar/u);
    expect(formatUidSet([5, 1, 5, 3])).toBe("1,3,5");
    expect(() => formatUidSet([0])).toThrow(/positive/u);
  });
});
