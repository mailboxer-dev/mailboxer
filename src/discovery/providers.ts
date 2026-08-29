import type { DiscoveredAccountSettings } from "./types";

const ICLOUD_DOMAINS = new Set(["icloud.com", "me.com", "mac.com"]);
const PURELYMAIL_MX_HOSTS = new Set(["mailserver.purelymail.com"]);

export function publicMailHostname(value: string): string | undefined {
  const hostname = value.trim().toLowerCase().replace(/\.$/u, "");
  if (
    hostname.length > 253
    || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(hostname)
    || /^(?:localhost|\d{1,3}(?:\.\d{1,3}){3})$/u.test(hostname)
    || /(?:^|\.)(?:local|internal|home|lan|test|invalid)$/u.test(hostname)
  ) return undefined;
  return hostname;
}

export function domainFromAddress(address: string): string {
  return address.trim().toLowerCase().split("@").at(-1) ?? "";
}

export function localPartFromAddress(address: string): string {
  return address.trim().slice(0, Math.max(0, address.lastIndexOf("@")));
}

export function exactProviderSettings(address: string): DiscoveredAccountSettings | undefined {
  const domain = domainFromAddress(address);
  if (ICLOUD_DOMAINS.has(domain)) {
    return {
      providerName: "iCloud",
      mail: {
        imapHost: "imap.mail.me.com",
        imapPort: 993,
        imapTlsMode: "implicit",
        imapUser: localPartFromAddress(address) || address,
        smtpHost: "smtp.mail.me.com",
        smtpPort: 587,
        smtpTlsMode: "starttls",
        smtpUser: address,
      },
      davUser: address,
      caldavUrl: "https://caldav.icloud.com/",
      carddavUrl: "https://contacts.icloud.com/",
      sources: ["preset"],
    };
  }
  if (domain === "purelymail.com") return purelymailSettings(address, "preset");
  return undefined;
}

export function settingsForMx(address: string, mxHosts: readonly string[]): DiscoveredAccountSettings | undefined {
  return mxHosts.some((host) => PURELYMAIL_MX_HOSTS.has(host.toLowerCase().replace(/\.$/u, "")))
    ? purelymailSettings(address, "mx")
    : undefined;
}

function purelymailSettings(address: string, source: string): DiscoveredAccountSettings {
  return {
    providerName: "Purelymail",
    mail: {
      imapHost: "imap.purelymail.com",
      imapPort: 993,
      imapTlsMode: "implicit",
      imapUser: address,
      smtpHost: "smtp.purelymail.com",
      smtpPort: 465,
      smtpTlsMode: "implicit",
      smtpUser: address,
    },
    caldavUrl: "https://purelymail.com/",
    carddavUrl: "https://purelymail.com/",
    davUser: address,
    sources: [source],
  };
}
