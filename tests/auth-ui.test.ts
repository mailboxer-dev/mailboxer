import { describe, expect, it } from "vitest";
import {
  decodeAuthPageModel,
  decodeUiPageModel,
  detectAccountPreset,
  renderUiPage,
  type AuthPageModel,
  type LandingPageModel,
} from "../src/auth-ui";

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

describe("shared UI page models", () => {
  it("round-trips a landing page model through the HTML shell", () => {
    const page: LandingPageModel = {
      version: 1,
      kind: "landing",
      origin: "https://mailboxer.example",
      mcpUrl: "https://mailboxer.example/mcp",
      agentSetupUrl: "https://mailboxer.example/agent-setup/prompt.md",
    };
    const html = renderUiPage(page);
    const encoded = /data-page="([A-Za-z0-9_-]+)"/u.exec(html)?.[1];

    expect(encoded).toBeTruthy();
    expect(decodeUiPageModel(encoded ?? "")).toEqual(page);
    expect(html).toContain("<title>Mailboxer — connect your agent</title>");
    expect(html).toContain("<meta name=\"description\" content=\"Give your agent a mailbox.");
    expect(html).toContain("This onboarding page requires JavaScript.");
    expect(html).toContain("/auth.js");
    expect(html).toContain("/style.css");
  });

  it("keeps authorization decoding separate from landing decoding", () => {
    const page: AuthPageModel = {
      version: 1, kind: "account-form", clientName: "Test client", title: "Connect account", state: "state", target: "start", step: "email",
      account: { preset: "icloud", label: "", address: "", services: { mail: true, calendar: false, contacts: false }, imap: { host: "", port: "993", tlsMode: "implicit", user: "" }, smtp: { host: "", port: "587", tlsMode: "starttls", user: "", sameCredentials: true }, dav: { calendarUrl: "", contactsUrl: "", user: "" } },
    };
    const html = renderUiPage(page);
    const encoded = /data-page="([A-Za-z0-9_-]+)"/u.exec(html)?.[1] ?? "";

    expect(decodeAuthPageModel(encoded)).toEqual(page);
    expect(decodeUiPageModel(encoded)).toEqual(page);
  });
});
