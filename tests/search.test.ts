import { describe, expect, it } from "vitest";
import { compileSearch } from "../src/imap/search";

describe("structured IMAP search", () => {
  it("compiles bounded structured criteria with safe quoting", () => {
    expect(compileSearch({
      from: 'alice"@example.com',
      subject: "release",
      text: "uid:1",
      since: "2026-01-01",
      before: "2026-02-01",
      unread: true,
      flagged: true,
      answered: false,
      draft: true,
    })).toBe('FROM "alice\\"@example.com" SUBJECT "release" TEXT "uid:1" SINCE 1-Jan-2026 BEFORE 1-Feb-2026 UNSEEN FLAGGED UNANSWERED DRAFT');
    expect(compileSearch({ subject: "Café" })).toBe('CHARSET UTF-8 SUBJECT "Café"');
    expect(() => compileSearch({ text: "uid:1\r\nNOOP" })).toThrow(/control character/u);
  });

  it("uses ALL for an empty filter and rejects oversized values", () => {
    expect(compileSearch({})).toBe("ALL");
    expect(compileSearch({ unread: false, flagged: false, answered: false, draft: false })).toBe("SEEN UNFLAGGED UNANSWERED UNDRAFT");
    expect(() => compileSearch({ subject: "x".repeat(257) })).toThrow(/1-256/u);
  });
});
