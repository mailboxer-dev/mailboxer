export type DiscoveredTlsMode = "implicit" | "starttls";

export interface DiscoveredMailSettings {
  imapHost: string;
  imapPort: number;
  imapTlsMode: DiscoveredTlsMode;
  imapUser: string;
  smtpHost: string;
  smtpPort: number;
  smtpTlsMode: DiscoveredTlsMode;
  smtpUser: string;
}

export interface DiscoveredAccountSettings {
  providerName: string;
  mail?: DiscoveredMailSettings;
  caldavUrl?: string;
  carddavUrl?: string;
  davUser: string;
  sources: string[];
}

export interface DiscoveryFetcher {
  (input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}
