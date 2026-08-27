import { describe, expect, it } from "vitest";
import { cursorFingerprint, decodeDavCursor, DavCursorError, encodeDavCursor } from "../src/dav/cursor";

const secret = "a-secure-test-encryption-key-with-32-chars";

describe("stateless signed DAV cursors", () => {
  it("round-trips a versioned domain/query/href cursor", async () => {
    const fingerprint = await cursorFingerprint({ calendarHref: "https://caldav.icloud.com/home/", componentType: "VEVENT", limit: 2 });
    const cursor = await encodeDavCursor("caldav.icloud.com", fingerprint, "https://caldav.icloud.com/home/b.ics", secret);
    await expect(decodeDavCursor(cursor, "caldav.icloud.com", fingerprint, secret))
      .resolves.toBe("https://caldav.icloud.com/home/b.ics");
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u);
  });

  it("rejects tampering, query mismatch, wrong domain, and malformed cursors", async () => {
    const fingerprint = await cursorFingerprint({ query: "ada" });
    const cursor = await encodeDavCursor("contacts.icloud.com", fingerprint, "https://contacts.icloud.com/a/b.vcf", secret);
    const [payload, signature] = cursor.split(".");
    const tampered = `${payload.slice(0, -1)}${payload.endsWith("A") ? "B" : "A"}.${signature}`;
    await expect(decodeDavCursor(tampered, "contacts.icloud.com", fingerprint, secret)).rejects.toBeInstanceOf(DavCursorError);
    await expect(decodeDavCursor(cursor, "contacts.icloud.com", await cursorFingerprint({ query: "other" }), secret)).rejects.toBeInstanceOf(DavCursorError);
    await expect(decodeDavCursor(cursor, "caldav.icloud.com", fingerprint, secret)).rejects.toBeInstanceOf(DavCursorError);
    await expect(decodeDavCursor("not-a-cursor", "contacts.icloud.com", fingerprint, secret)).rejects.toBeInstanceOf(DavCursorError);
    await expect(encodeDavCursor("evil.example", fingerprint, "https://evil.example/a", secret)).rejects.toBeInstanceOf(DavCursorError);
  });
});
