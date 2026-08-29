import type { AccountPreset, DavConfig, StoredMailAccount } from "./types";

interface ProviderPreset {
  dav: DavConfig;
}

const PROVIDERS = {
  icloud: {
    dav: {
      caldavUrl: "https://caldav.icloud.com/",
      carddavUrl: "https://contacts.icloud.com/",
    },
  },
} satisfies Record<Exclude<AccountPreset, "custom">, ProviderPreset>;

function normalizedDavUrl(value: string, field: string): string {
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new Error(`Enter a valid ${field} address`);
  }
  if (
    url.protocol !== "https:"
    || url.username
    || url.password
    || url.port
    || url.search
    || url.hash
    || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu.test(url.hostname)
    || /^(?:localhost|\d{1,3}(?:\.\d{1,3}){3})$/iu.test(url.hostname)
    || /(?:^|\.)(?:local|internal|home|lan|test|invalid)$/iu.test(url.hostname)
  ) {
    throw new Error(`Enter a secure public ${field} address`);
  }
  url.hostname = url.hostname.toLowerCase();
  url.pathname = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
  return url.toString();
}

export function customDavConfig(
  caldavUrl: string | undefined,
  carddavUrl: string | undefined,
  username: string | undefined,
  capabilities: Pick<StoredMailAccount["capabilities"], "calendar" | "contacts">,
): DavConfig | undefined {
  const config: DavConfig = {};
  if (capabilities.calendar) config.caldavUrl = normalizedDavUrl(caldavUrl ?? "", "calendar server");
  if (capabilities.contacts) config.carddavUrl = normalizedDavUrl(carddavUrl ?? "", "contacts server");
  if (config.caldavUrl || config.carddavUrl) {
    const normalizedUsername = username?.trim();
    if (normalizedUsername) {
      const hasControl = Array.from(normalizedUsername).some((character) => {
        const code = character.codePointAt(0) ?? 0;
        return code <= 0x1f || code === 0x7f;
      });
      if (normalizedUsername.length > 320 || hasControl) {
        throw new Error("Enter a valid calendar and contacts sign-in name");
      }
      config.username = normalizedUsername;
    }
  }
  return config.caldavUrl || config.carddavUrl ? config : undefined;
}

export function davConfigForAccount(account: Pick<StoredMailAccount, "preset" | "davConfig" | "config">): DavConfig {
  if (account.preset === "icloud") return PROVIDERS.icloud.dav;
  return { ...account.davConfig, username: account.davConfig?.username ?? account.config.imapUser };
}

export const ICLOUD_DAV_CONFIG: DavConfig = PROVIDERS.icloud.dav;
