import { describe, expect, it, vi } from "vitest";
import { annotateSpanFailure, describeError, logFailure } from "../src/diagnostics";

describe("failure diagnostics", () => {
  it("redacts credentials, URLs, and email addresses from error details", () => {
    const error = Object.assign(
      new Error("Basic dXNlcjpwYXNz https://caldav.icloud.com/principal owner@icloud.com abcd-efgh-ijkl-mnop password=secret"),
      { status: 401 },
    );

    expect(describeError(error)).toEqual({
      type: "Error",
      message: "Basic [redacted] [redacted-url] [redacted-email] [redacted-secret] password=[redacted]",
      status: 401,
    });
  });

  it("emits one structured failure record without raw sensitive values", () => {
    const write = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      logFailure(
        "dav_request_failed",
        { service: "calendar", method: "PROPFIND", request_bytes: 123 },
        Object.assign(new Error("request failed for owner@icloud.com at https://caldav.icloud.com/"), { status: 401 }),
      );

      expect(write).toHaveBeenCalledOnce();
      const record = JSON.parse(String(write.mock.calls[0]?.[0])) as Record<string, unknown>;
      expect(record).toMatchObject({
        event: "dav_request_failed",
        service: "calendar",
        method: "PROPFIND",
        request_bytes: 123,
        error_type: "Error",
        error_status: 401,
      });
      expect(String(record.error_message)).not.toContain("owner@icloud.com");
      expect(String(record.error_message)).not.toContain("https://caldav.icloud.com/");
    } finally {
      write.mockRestore();
    }
  });

  it("adds safe error attributes to a trace span", () => {
    const attributes = new Map<string, string | number | boolean | undefined>();
    annotateSpanFailure(
      { setAttribute: (name, value) => attributes.set(name, value) },
      Object.assign(new Error("DAV request failed"), { status: 403 }),
    );

    expect(attributes).toEqual(new Map<string, string | number | boolean | undefined>([
      ["error.type", "Error"],
      ["error.message", "DAV request failed"],
      ["error.status_code", 403],
    ]));
  });
});
