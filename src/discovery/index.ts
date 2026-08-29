import { annotateSpanFailure, logFailure } from "../diagnostics";
import { withSpan } from "../tracing";
import { AutoconfigParseError, parseThunderbirdAutoconfig } from "./autoconfig";
import { optionalDnsLookup, selectedSrv, type DnsLookupResult } from "./doh";
import { decodeDiscoveryText, discoveryFetch, DiscoveryHttpError, publicHttpsUrl, resolveDavWellKnown } from "./http";
import { domainFromAddress, exactProviderSettings, publicMailHostname, settingsForMx } from "./providers";
import type { DiscoveredAccountSettings, DiscoveredMailSettings, DiscoveryFetcher } from "./types";

export class AccountDiscoveryError extends Error {
  constructor(message = "Account settings could not be discovered") {
    super(message);
    this.name = "AccountDiscoveryError";
  }
}

export interface AccountDiscoveryDependencies {
  fetcher?: DiscoveryFetcher;
  random?: () => number;
}

function fromAutoconfig(
  providerName: string,
  source: string,
  settings: NonNullable<ReturnType<typeof parseThunderbirdAutoconfig>>,
  address: string,
): DiscoveredAccountSettings {
  return {
    providerName,
    mail: {
      imapHost: settings.imap.host,
      imapPort: settings.imap.port,
      imapTlsMode: settings.imap.tlsMode,
      imapUser: settings.imap.username,
      smtpHost: settings.smtp.host,
      smtpPort: settings.smtp.port,
      smtpTlsMode: settings.smtp.tlsMode,
      smtpUser: settings.smtp.username,
    },
    davUser: address,
    sources: [source],
  };
}

async function autoconfigAt(
  address: string,
  target: URL,
  source: string,
  providerName: string,
  fetcher: DiscoveryFetcher,
): Promise<DiscoveredAccountSettings | undefined> {
  try {
    const response = await discoveryFetch(source, target, fetcher);
    const parsed = parseThunderbirdAutoconfig(decodeDiscoveryText(response.body), { email: address });
    return parsed ? fromAutoconfig(providerName, source, parsed, address) : undefined;
  } catch (error) {
    if (error instanceof DiscoveryHttpError && error.expectedMiss) return undefined;
    if (error instanceof AutoconfigParseError) logFailure("account_autoconfig_parse_failed", { source }, error);
    return undefined;
  }
}

async function discoverHostedMail(
  address: string,
  domain: string,
  fetcher: DiscoveryFetcher,
): Promise<DiscoveredAccountSettings | undefined> {
  const targets = [
    {
      source: "provider_autoconfig",
      url: new URL(`https://autoconfig.${domain}/mail/config-v1.1.xml?emailaddress=${encodeURIComponent(address)}`),
    },
    {
      source: "provider_well_known",
      url: new URL(`https://${domain}/.well-known/autoconfig/mail/config-v1.1.xml`),
    },
  ];
  const results = await Promise.all(targets.map(({ source, url }) => autoconfigAt(address, url, source, domain, fetcher)));
  return results.find((candidate) => candidate !== undefined);
}

async function discoverIspdbMail(
  address: string,
  domain: string,
  fetcher: DiscoveryFetcher,
): Promise<DiscoveredAccountSettings | undefined> {
  return autoconfigAt(
    address,
    new URL(`https://autoconfig.thunderbird.net/v1.1/${encodeURIComponent(domain)}`),
    "thunderbird_ispdb",
    domain,
    fetcher,
  );
}

interface DnsDiscoveryResults {
  mx: DnsLookupResult;
  imaps: DnsLookupResult;
  imap: DnsLookupResult;
  submissions: DnsLookupResult;
  submission: DnsLookupResult;
  caldavs: DnsLookupResult;
  caldavTxt: DnsLookupResult;
  carddavs: DnsLookupResult;
  carddavTxt: DnsLookupResult;
}

async function discoverDnsRecords(domain: string, fetcher: DiscoveryFetcher): Promise<DnsDiscoveryResults> {
  const requests = {
    mx: optionalDnsLookup(domain, "MX", fetcher),
    imaps: optionalDnsLookup(`_imaps._tcp.${domain}`, "SRV", fetcher),
    imap: optionalDnsLookup(`_imap._tcp.${domain}`, "SRV", fetcher),
    submissions: optionalDnsLookup(`_submissions._tcp.${domain}`, "SRV", fetcher),
    submission: optionalDnsLookup(`_submission._tcp.${domain}`, "SRV", fetcher),
    caldavs: optionalDnsLookup(`_caldavs._tcp.${domain}`, "SRV", fetcher),
    caldavTxt: optionalDnsLookup(`_caldavs._tcp.${domain}`, "TXT", fetcher),
    carddavs: optionalDnsLookup(`_carddavs._tcp.${domain}`, "SRV", fetcher),
    carddavTxt: optionalDnsLookup(`_carddavs._tcp.${domain}`, "TXT", fetcher),
  };
  const entries = await Promise.all(Object.entries(requests).map(async ([key, request]) => [key, await request] as const));
  return Object.fromEntries(entries) as unknown as DnsDiscoveryResults;
}

function dnsMailSettings(records: DnsDiscoveryResults, address: string, random: () => number): DiscoveredMailSettings | undefined {
  const implicitImap = selectedSrv(records.imaps.srv.filter((record) => record.port === 993), random);
  const starttlsImap = selectedSrv(records.imap.srv.filter((record) => record.port === 143), random);
  const implicitSmtp = selectedSrv(records.submissions.srv.filter((record) => record.port === 465), random);
  const starttlsSmtp = selectedSrv(records.submission.srv.filter((record) => [587, 2525].includes(record.port)), random);
  const imap = implicitImap ?? starttlsImap;
  const smtp = implicitSmtp ?? starttlsSmtp;
  const imapHost = imap ? publicMailHostname(imap.target) : undefined;
  const smtpHost = smtp ? publicMailHostname(smtp.target) : undefined;
  if (!imap || !smtp || !imapHost || !smtpHost) return undefined;
  return {
    imapHost,
    imapPort: imap.port,
    imapTlsMode: imap === implicitImap ? "implicit" : "starttls",
    imapUser: address,
    smtpHost,
    smtpPort: smtp.port,
    smtpTlsMode: smtp === implicitSmtp ? "implicit" : "starttls",
    smtpUser: address,
  };
}

function davPath(result: DnsLookupResult): string {
  const value = result.txt.flatMap((record) => record.strings).map((entry) => entry.trim()).find((entry) => entry.startsWith("path="));
  const path = value?.slice("path=".length) ?? "/";
  const hasControl = Array.from(path).some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 0x1f || code === 0x7f;
  });
  if (!path.startsWith("/") || path.startsWith("//") || path.length > 1_024 || hasControl) return "/";
  return path;
}

function dnsDavUrl(srvResult: DnsLookupResult, txtResult: DnsLookupResult, random: () => number): string | undefined {
  const srv = selectedSrv(srvResult.srv.filter((record) => record.port === 443), random);
  const host = srv ? publicMailHostname(srv.target) : undefined;
  if (!host) return undefined;
  return publicHttpsUrl(new URL(davPath(txtResult), `https://${host}/`)).toString();
}

async function wellKnownDavUrl(
  domain: string,
  service: "caldav" | "carddav",
  fetcher: DiscoveryFetcher,
): Promise<string | undefined> {
  const resolved = await resolveDavWellKnown(
    `${service}_well_known`,
    new URL(`https://${domain}/.well-known/${service}`),
    fetcher,
  );
  return resolved?.toString();
}

function mergedSources(...candidates: Array<DiscoveredAccountSettings | undefined>): string[] {
  return [...new Set(candidates.flatMap((candidate) => candidate?.sources ?? []))];
}

export async function discoverAccountSettings(
  address: string,
  dependencies: AccountDiscoveryDependencies = {},
): Promise<DiscoveredAccountSettings> {
  return withSpan("account.discovery", {}, async (span) => {
    try {
      const exact = exactProviderSettings(address);
      if (exact) {
        span.setAttribute("discovery.source_count", exact.sources.length);
        span.setAttribute("discovery.mail_found", Boolean(exact.mail));
        span.setAttribute("discovery.calendar_found", Boolean(exact.caldavUrl));
        span.setAttribute("discovery.contacts_found", Boolean(exact.carddavUrl));
        return exact;
      }
      const domain = domainFromAddress(address);
      if (!domain || !domain.includes(".")) throw new AccountDiscoveryError("Enter a valid email address");
      const fetcher = dependencies.fetcher ?? globalThis.fetch;
      const hosted = await discoverHostedMail(address, domain, fetcher);
      const dns = await discoverDnsRecords(domain, fetcher);
      const random = dependencies.random ?? Math.random;
      const mx = settingsForMx(address, dns.mx.mx.map((record) => record.exchange));
      const dnsMail = dnsMailSettings(dns, address, random);
      const ispdb = hosted?.mail || dnsMail || mx?.mail ? undefined : await discoverIspdbMail(address, domain, fetcher);
      const mail = hosted?.mail ?? dnsMail ?? mx?.mail ?? ispdb?.mail;
      const dnsCalendar = dnsDavUrl(dns.caldavs, dns.caldavTxt, random);
      const dnsContacts = dnsDavUrl(dns.carddavs, dns.carddavTxt, random);
      const [wellKnownCalendar, wellKnownContacts] = await Promise.all([
        dnsCalendar || mx?.caldavUrl ? Promise.resolve(undefined) : wellKnownDavUrl(domain, "caldav", fetcher),
        dnsContacts || mx?.carddavUrl ? Promise.resolve(undefined) : wellKnownDavUrl(domain, "carddav", fetcher),
      ]);
      const caldavUrl = dnsCalendar ?? mx?.caldavUrl ?? wellKnownCalendar;
      const carddavUrl = dnsContacts ?? mx?.carddavUrl ?? wellKnownContacts;
      if (!mail && !caldavUrl && !carddavUrl) throw new AccountDiscoveryError();
      const sources = [
        ...mergedSources(hosted, mx, ispdb),
        ...(dnsMail || dnsCalendar || dnsContacts ? ["dns_srv"] : []),
        ...(wellKnownCalendar || wellKnownContacts ? ["dav_well_known"] : []),
      ];
      const result: DiscoveredAccountSettings = {
        providerName: mx?.providerName ?? hosted?.providerName ?? ispdb?.providerName ?? domain,
        ...(mail ? { mail } : {}),
        ...(caldavUrl ? { caldavUrl } : {}),
        ...(carddavUrl ? { carddavUrl } : {}),
        davUser: mx?.davUser ?? address,
        sources: [...new Set(sources)],
      };
      span.setAttribute("discovery.source_count", result.sources.length);
      span.setAttribute("discovery.mail_found", Boolean(result.mail));
      span.setAttribute("discovery.calendar_found", Boolean(result.caldavUrl));
      span.setAttribute("discovery.contacts_found", Boolean(result.carddavUrl));
      return result;
    } catch (error) {
      annotateSpanFailure(span, error);
      throw error;
    }
  });
}
