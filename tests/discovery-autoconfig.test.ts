import { describe, expect, it } from "vitest";
import {
  AutoconfigParseError,
  MAX_AUTOCONFIG_BYTES,
  parseThunderbirdAutoconfig,
} from "../src/discovery/autoconfig";

const email = "Alice.Example@example.com";

function config(provider: string): string {
  return `<clientConfig version="1.1"><emailProvider>${provider}</emailProvider></clientConfig>`;
}

function server(
  direction: "incomingServer" | "outgoingServer",
  type: string,
  host: string,
  port: string,
  socketType: string,
  username = "%EMAILADDRESS%",
): string {
  return `<${direction} type="${type}"><hostname>${host}</hostname><port>${port}</port><socketType>${socketType}</socketType><username>${username}</username></${direction}>`;
}

describe("bounded Thunderbird Autoconfig parser", () => {
  it("parses secure IMAP and SMTP settings and expands supported username templates", () => {
    const result = parseThunderbirdAutoconfig(
      config([
        "<domain>example.com</domain>",
        server("incomingServer", "imap", "IMAP.Example.com.", "993", "SSL", "%EMAILLOCALPART%"),
        server("outgoingServer", "smtp", "smtp.example.com", "587", "STARTTLS", "%EMAILDOMAIN%"),
      ].join("")),
      { email },
    );

    expect(result).toEqual({
      imap: { host: "imap.example.com", port: 993, tlsMode: "implicit", username: "Alice.Example" },
      smtp: { host: "smtp.example.com", port: 587, tlsMode: "starttls", username: "example.com" },
    });
  });

  it("expands the full address and preserves static usernames", () => {
    const result = parseThunderbirdAutoconfig(
      config([
        "<domain>example.com</domain>",
        server("incomingServer", "imap", "imap.example.com", "993", "SSL", "%EMAILADDRESS%"),
        server("outgoingServer", "smtp", "smtp.example.com", "465", "SSL", "account-name"),
      ].join("")),
      { email },
    );

    expect(result?.imap.username).toBe(email);
    expect(result?.smtp.username).toBe("account-name");
  });

  it("ignores POP, plaintext, unsupported templates, and incomplete servers", () => {
    const result = parseThunderbirdAutoconfig(
      config([
        "<domain>example.com</domain>",
        server("incomingServer", "pop3", "pop.example.com", "995", "SSL"),
        server("incomingServer", "imap", "imap.example.com", "143", "plain"),
        server("incomingServer", "imap", "imap.example.com", "993", "SSL", "%UNSUPPORTED%"),
        server("incomingServer", "imap", "imap.example.com", "993", "SSL"),
        server("outgoingServer", "smtp", "smtp.example.com", "25", "SSL"),
        server("outgoingServer", "smtp", "smtp.example.com", "587", "plain"),
        server("outgoingServer", "smtp", "smtp.example.com", "465", "SSL"),
      ].join("")),
      { email },
    );

    expect(result).toEqual({
      imap: { host: "imap.example.com", port: 993, tlsMode: "implicit", username: email },
      smtp: { host: "smtp.example.com", port: 465, tlsMode: "implicit", username: email },
    });
  });

  it("chooses the most secure standard pair deterministically", () => {
    const result = parseThunderbirdAutoconfig(
      config([
        "<domain>example.com</domain>",
        server("incomingServer", "imap", "z.example.com", "143", "STARTTLS"),
        server("incomingServer", "imap", "b.example.com", "9999", "SSL"),
        server("incomingServer", "imap", "a.example.com", "993", "SSL"),
        server("outgoingServer", "smtp", "z.example.com", "587", "STARTTLS"),
        server("outgoingServer", "smtp", "b.example.com", "2525", "SSL"),
        server("outgoingServer", "smtp", "a.example.com", "465", "SSL"),
      ].join("")),
      { email },
    );

    expect(result).toEqual({
      imap: { host: "a.example.com", port: 993, tlsMode: "implicit", username: email },
      smtp: { host: "a.example.com", port: 465, tlsMode: "implicit", username: email },
    });
  });

  it("uses stable lexical tie breakers when secure candidates have equal preference", () => {
    const result = parseThunderbirdAutoconfig(
      config([
        "<domain>example.com</domain>",
        server("incomingServer", "imap", "z.example.com", "993", "SSL"),
        server("incomingServer", "imap", "a.example.com", "993", "SSL"),
        server("outgoingServer", "smtp", "z.example.com", "465", "SSL"),
        server("outgoingServer", "smtp", "a.example.com", "465", "SSL"),
      ].join("")),
      { email },
    );

    expect(result?.imap.host).toBe("a.example.com");
    expect(result?.smtp.host).toBe("a.example.com");
  });

  it("accepts only valid public hostnames and valid ports", () => {
    const result = parseThunderbirdAutoconfig(
      config([
        "<domain>example.com</domain>",
        server("incomingServer", "imap", "localhost", "993", "SSL"),
        server("incomingServer", "imap", "127.0.0.1", "993", "SSL"),
        server("incomingServer", "imap", "imap.example.com/path", "993", "SSL"),
        server("incomingServer", "imap", "imap.example.com", "0", "SSL"),
        server("incomingServer", "imap", "imap.example.com", "65536", "SSL"),
        server("incomingServer", "imap", "imap.example.com", "993", "SSL"),
        server("outgoingServer", "smtp", "smtp.example.com", "25", "STARTTLS"),
        server("outgoingServer", "smtp", "smtp.example.com", "70000", "SSL"),
        server("outgoingServer", "smtp", "smtp.example.com", "465", "SSL"),
      ].join("")),
      { email },
    );

    expect(result).toEqual({
      imap: { host: "imap.example.com", port: 993, tlsMode: "implicit", username: email },
      smtp: { host: "smtp.example.com", port: 465, tlsMode: "implicit", username: email },
    });
  });

  it("selects a provider matching the requested email domain", () => {
    const result = parseThunderbirdAutoconfig(
      `<clientConfig><emailProvider><domain>other.example</domain>${server("incomingServer", "imap", "imap.other.example", "993", "SSL")}${server("outgoingServer", "smtp", "smtp.other.example", "465", "SSL")}</emailProvider><emailProvider><domain>EXAMPLE.COM.</domain>${server("incomingServer", "imap", "imap.example.com", "993", "SSL")}${server("outgoingServer", "smtp", "smtp.example.com", "465", "SSL")}</emailProvider></clientConfig>`,
      { email },
    );

    expect(result?.imap.host).toBe("imap.example.com");
    expect(result?.smtp.host).toBe("smtp.example.com");
  });

  it("supports entity and CDATA decoding through the shared XML parser", () => {
    const result = parseThunderbirdAutoconfig(
      config([
        "<domain>example.com</domain>",
        server("incomingServer", "imap", "<![CDATA[imap.example.com]]>", "993", "SSL", "user&amp;name"),
        server("outgoingServer", "smtp", "smtp.example.com", "465", "SSL"),
      ].join("")),
      { email },
    );

    expect(result?.imap).toEqual({ host: "imap.example.com", port: 993, tlsMode: "implicit", username: "user&name" });
  });

  it("returns null when no usable secure pair exists", () => {
    const result = parseThunderbirdAutoconfig(
      config([
        "<domain>example.com</domain>",
        server("incomingServer", "imap", "imap.example.com", "143", "plain"),
        server("outgoingServer", "smtp", "smtp.example.com", "25", "STARTTLS"),
      ].join("")),
      { email },
    );

    expect(result).toBeNull();
  });

  it("rejects malformed XML, DTDs, invalid UTF-8, and oversized input", () => {
    expect(() => parseThunderbirdAutoconfig("<clientConfig>", { email })).toThrow(AutoconfigParseError);
    expect(() => parseThunderbirdAutoconfig("<!DOCTYPE clientConfig><clientConfig />", { email })).toThrow(AutoconfigParseError);
    expect(() => parseThunderbirdAutoconfig(new Uint8Array([0x3c, 0x80]), { email })).toThrow(AutoconfigParseError);
    expect(() => parseThunderbirdAutoconfig(`<clientConfig>${"x".repeat(MAX_AUTOCONFIG_BYTES)}</clientConfig>`, { email })).toThrow(AutoconfigParseError);
  });

  it("rejects malformed document structure and invalid parser limits", () => {
    expect(() => parseThunderbirdAutoconfig("<notClientConfig />", { email })).toThrow("root must be clientConfig");
    expect(() => parseThunderbirdAutoconfig("<clientConfig />", { email })).toThrow("no emailProvider");
    expect(() => parseThunderbirdAutoconfig("<clientConfig />", { email, maxBytes: 0 })).toThrow(AutoconfigParseError);
    expect(() => parseThunderbirdAutoconfig("<clientConfig />", { email, maxDepth: 0 })).toThrow(AutoconfigParseError);
    expect(() => parseThunderbirdAutoconfig("<clientConfig />", { email, maxNodes: 0 })).toThrow(AutoconfigParseError);
  });

  it("rejects invalid email addresses before expanding them into usernames", () => {
    const xml = config([
      "<domain>example.com</domain>",
      server("incomingServer", "imap", "imap.example.com", "993", "SSL"),
      server("outgoingServer", "smtp", "smtp.example.com", "465", "SSL"),
    ].join(""));
    for (const invalidEmail of ["", "missing-at.example.com", "a@@example.com", "a@example.com/path", "a@localhost"]) {
      expect(() => parseThunderbirdAutoconfig(xml, { email: invalidEmail })).toThrow(AutoconfigParseError);
    }
  });

  it("enforces caller limits without allowing them to exceed hard bounds", () => {
    const xml = config([
      "<domain>example.com</domain>",
      server("incomingServer", "imap", "imap.example.com", "993", "SSL"),
      server("outgoingServer", "smtp", "smtp.example.com", "465", "SSL"),
    ].join(""));
    expect(() => parseThunderbirdAutoconfig(xml, { email, maxBytes: 32 })).toThrow("too large");
    expect(() => parseThunderbirdAutoconfig(xml, { email, maxNodes: 2 })).toThrow(AutoconfigParseError);
    expect(parseThunderbirdAutoconfig(xml, { email, maxBytes: MAX_AUTOCONFIG_BYTES + 1 })).not.toBeNull();
  });
});
