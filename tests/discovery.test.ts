import { describe, expect, it, vi } from "vitest";
import { discoverAccountSettings } from "../src/discovery";
import { DNS_RECORD_TYPES, encodeDnsName } from "../src/discovery/dns";

function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function u16(value: number): Uint8Array {
  return Uint8Array.from([value >>> 8, value & 0xff]);
}

function u32(value: number): Uint8Array {
  return Uint8Array.from([value >>> 24, value >>> 16, value >>> 8, value].map((part) => part & 0xff));
}

function questionEnd(query: Uint8Array): number {
  let offset = 12;
  while (query[offset] !== 0) offset += (query[offset] ?? 0) + 1;
  return offset + 5;
}

function queryType(query: Uint8Array): number {
  const end = questionEnd(query);
  return ((query[end - 4] ?? 0) << 8) | (query[end - 3] ?? 0);
}

function queryName(query: Uint8Array): string {
  const labels: string[] = [];
  let offset = 12;
  while ((query[offset] ?? 0) > 0) {
    const length = query[offset] ?? 0;
    labels.push(new TextDecoder().decode(query.slice(offset + 1, offset + 1 + length)));
    offset += length + 1;
  }
  return labels.join(".");
}

function dnsResponse(query: Uint8Array, rcode = 3, answer?: { type: number; rdata: Uint8Array }): Uint8Array {
  const end = questionEnd(query);
  const header = concat(
    query.slice(0, 2),
    u16(0x8180 | rcode),
    u16(1),
    u16(answer ? 1 : 0),
    u16(0),
    u16(0),
  );
  if (!answer) return concat(header, query.slice(12, end));
  const record = concat(
    Uint8Array.from([0xc0, 0x0c]),
    u16(answer.type),
    u16(1),
    u32(300),
    u16(answer.rdata.byteLength),
    answer.rdata,
  );
  return concat(header, query.slice(12, end), record);
}

function dnsHttpResponse(body: Uint8Array): Response {
  const copy = new Uint8Array(body).buffer as ArrayBuffer;
  return new Response(copy, { status: 200, headers: { "Content-Type": "application/dns-message" } });
}

const autoconfigXml = `<?xml version="1.0"?>
<clientConfig><emailProvider id="example"><domain>example.com</domain>
<incomingServer type="imap"><hostname>imap.example.com</hostname><port>993</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username></incomingServer>
<outgoingServer type="smtp"><hostname>smtp.example.com</hostname><port>587</port><socketType>STARTTLS</socketType><username>%EMAILADDRESS%</username></outgoingServer>
</emailProvider></clientConfig>`;

describe("automatic account discovery", () => {
  it("uses exact presets without making discovery requests", async () => {
    const fetcher = vi.fn(async () => { throw new Error("unexpected request"); });
    const result = await discoverAccountSettings("person@icloud.com", { fetcher });
    expect(result.providerName).toBe("iCloud");
    expect(result.mail).toMatchObject({ imapHost: "imap.mail.me.com", smtpHost: "smtp.mail.me.com" });
    expect(result.caldavUrl).toBe("https://caldav.icloud.com/");
    expect(result.carddavUrl).toBe("https://contacts.icloud.com/");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("prefers provider-hosted Autoconfig and never sends credentials", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      expect(request.headers.get("Authorization")).toBeNull();
      if (request.url.startsWith("https://autoconfig.example.com/")) {
        return new Response(autoconfigXml, { headers: { "Content-Type": "application/xml" } });
      }
      if (request.url === "https://cloudflare-dns.com/dns-query") {
        const query = new Uint8Array(await request.arrayBuffer());
        return dnsHttpResponse(dnsResponse(query));
      }
      return new Response(null, { status: 404 });
    });
    const result = await discoverAccountSettings("person@example.com", { fetcher, random: () => 0 });
    expect(result.mail).toEqual({
      imapHost: "imap.example.com",
      imapPort: 993,
      imapTlsMode: "implicit",
      imapUser: "person@example.com",
      smtpHost: "smtp.example.com",
      smtpPort: 587,
      smtpTlsMode: "starttls",
      smtpUser: "person@example.com",
    });
    expect(result.sources).toContain("provider_autoconfig");
  });

  it("recognizes a Purelymail custom domain through its MX record", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      if (request.url === "https://cloudflare-dns.com/dns-query") {
        const query = new Uint8Array(await request.arrayBuffer());
        const answer = queryType(query) === DNS_RECORD_TYPES.MX
          ? { type: DNS_RECORD_TYPES.MX, rdata: concat(u16(10), encodeDnsName("mailserver.purelymail.com")) }
          : undefined;
        return dnsHttpResponse(dnsResponse(query, answer ? 0 : 3, answer));
      }
      return new Response(null, { status: 404 });
    });
    const result = await discoverAccountSettings("person@custom.example", { fetcher, random: () => 0 });
    expect(result.providerName).toBe("Purelymail");
    expect(result.mail).toMatchObject({
      imapHost: "imap.purelymail.com",
      smtpHost: "smtp.purelymail.com",
      imapUser: "person@custom.example",
    });
    expect(result.caldavUrl).toBe("https://purelymail.com/");
    expect(result.carddavUrl).toBe("https://purelymail.com/");
    expect(result.sources).toContain("mx");
  });

  it("combines mail and DAV SRV/TXT records", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      if (request.url === "https://cloudflare-dns.com/dns-query") {
        const query = new Uint8Array(await request.arrayBuffer());
        const name = queryName(query);
        const type = queryType(query);
        let answer: { type: number; rdata: Uint8Array } | undefined;
        if (type === DNS_RECORD_TYPES.SRV && name === "_imaps._tcp.example.com") {
          answer = { type, rdata: concat(u16(0), u16(0), u16(993), encodeDnsName("imap.example.com")) };
        } else if (type === DNS_RECORD_TYPES.SRV && name === "_submissions._tcp.example.com") {
          answer = { type, rdata: concat(u16(0), u16(0), u16(465), encodeDnsName("smtp.example.com")) };
        } else if (type === DNS_RECORD_TYPES.SRV && name === "_caldavs._tcp.example.com") {
          answer = { type, rdata: concat(u16(0), u16(0), u16(443), encodeDnsName("dav.example.com")) };
        } else if (type === DNS_RECORD_TYPES.SRV && name === "_carddavs._tcp.example.com") {
          answer = { type, rdata: concat(u16(0), u16(0), u16(443), encodeDnsName("dav.example.com")) };
        } else if (type === DNS_RECORD_TYPES.TXT && name === "_caldavs._tcp.example.com") {
          const value = new TextEncoder().encode("path=/calendar/");
          answer = { type, rdata: concat(Uint8Array.from([value.byteLength]), value) };
        } else if (type === DNS_RECORD_TYPES.TXT && name === "_carddavs._tcp.example.com") {
          const value = new TextEncoder().encode("path=/contacts/");
          answer = { type, rdata: concat(Uint8Array.from([value.byteLength]), value) };
        }
        return dnsHttpResponse(dnsResponse(query, answer ? 0 : 3, answer));
      }
      return new Response(null, { status: 404 });
    });
    const result = await discoverAccountSettings("person@example.com", { fetcher, random: () => 0 });
    expect(result.mail).toMatchObject({
      imapHost: "imap.example.com",
      imapPort: 993,
      smtpHost: "smtp.example.com",
      smtpPort: 465,
    });
    expect(result.caldavUrl).toBe("https://dav.example.com/calendar/");
    expect(result.carddavUrl).toBe("https://dav.example.com/contacts/");
    expect(result.sources).toContain("dns_srv");
  });

  it("uses bounded HTTPS well-known redirects for DAV roots", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      expect(request.headers.get("Authorization")).toBeNull();
      if (request.url.startsWith("https://autoconfig.example.com/")) {
        return new Response(autoconfigXml, { headers: { "Content-Type": "application/xml" } });
      }
      if (request.url === "https://cloudflare-dns.com/dns-query") {
        return dnsHttpResponse(dnsResponse(new Uint8Array(await request.arrayBuffer())));
      }
      if (request.url === "https://example.com/.well-known/caldav") {
        return new Response(null, { status: 302, headers: { Location: "https://dav.example.com/calendar/" } });
      }
      if (request.url === "https://dav.example.com/calendar/") return new Response(null, { status: 401 });
      return new Response(null, { status: 404 });
    });
    const result = await discoverAccountSettings("person@example.com", { fetcher, random: () => 0 });
    expect(result.caldavUrl).toBe("https://dav.example.com/calendar/");
    expect(result.carddavUrl).toBeUndefined();
    expect(result.sources).toContain("dav_well_known");
  });

  it("rejects unsafe cross-origin redirects during provider discovery", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      if (request.url.startsWith("https://autoconfig.example.com/")) {
        return new Response(null, { status: 302, headers: { Location: "http://127.0.0.1/settings" } });
      }
      if (request.url === "https://cloudflare-dns.com/dns-query") {
        return dnsHttpResponse(dnsResponse(new Uint8Array(await request.arrayBuffer())));
      }
      return new Response(null, { status: 404 });
    });
    await expect(discoverAccountSettings("person@example.com", { fetcher, random: () => 0 })).rejects.toThrow(/could not be discovered/u);
  });
});
