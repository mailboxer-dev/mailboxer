import { describe, expect, it } from "vitest";
import { detectAccountPreset } from "../src/auth-ui";

describe("account provider detection", () => {
  it.each([
    "person@icloud.com",
    "person@me.com",
    "person@mac.com",
    " PERSON@ICLOUD.COM ",
  ])("detects %s as iCloud", (address) => {
    expect(detectAccountPreset(address)).toBe("icloud");
  });

  it.each([
    "person@example.com",
    "person@company.test",
    "person@icloud.com.example.org",
  ])("detects %s as a custom server account", (address) => {
    expect(detectAccountPreset(address)).toBe("custom");
  });
});
