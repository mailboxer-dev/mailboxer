import { children, parseXml, xmlText, XmlParseError, type XmlNode } from "../dav/xml";

export const MAX_AUTOCONFIG_BYTES = 256 * 1024;
export const MAX_AUTOCONFIG_DEPTH = 32;
export const MAX_AUTOCONFIG_NODES = 2_000;
export const DEFAULT_AUTOCONFIG_BYTES = MAX_AUTOCONFIG_BYTES;
export const DEFAULT_AUTOCONFIG_DEPTH = 16;
export const DEFAULT_AUTOCONFIG_NODES = 512;

const MAX_EMAIL_LENGTH = 320;
const MAX_USERNAME_LENGTH = 320;
const MAX_HOSTNAME_LENGTH = 253;
const MAX_HOST_LABEL_LENGTH = 63;
const HOST_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const LOCAL_HOST_SUFFIX_PATTERN = /(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid)$/u;

export type AutoconfigTlsMode = "implicit" | "starttls";

export interface AutoconfigServerSettings {
  host: string;
  port: number;
  tlsMode: AutoconfigTlsMode;
  username: string;
}

export interface ThunderbirdAutoconfigSettings {
  imap: AutoconfigServerSettings;
  smtp: AutoconfigServerSettings;
}

export interface ThunderbirdAutoconfigOptions {
  email: string;
  maxBytes?: number;
  maxDepth?: number;
  maxNodes?: number;
}

export class AutoconfigParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AutoconfigParseError";
  }
}

interface EmailParts {
  address: string;
  localPart: string;
  domain: string;
}

interface Candidate {
  settings: AutoconfigServerSettings;
  service: "imap" | "smtp";
  sourceIndex: number;
}

function fail(message: string): never {
  throw new AutoconfigParseError(message);
}

function boundedOption(
  value: number | undefined,
  fallback: number,
  maximum: number,
  label: string,
): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 1) fail(`${label} must be a positive integer`);
  return Math.min(value, maximum);
}

function sourceText(source: string | Uint8Array, maxBytes: number): string {
  const bytes = typeof source === "string" ? new TextEncoder().encode(source) : source;
  if (bytes.byteLength > maxBytes) fail("Thunderbird Autoconfig is too large");
  if (typeof source === "string") return source;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(source);
  } catch {
    fail("Thunderbird Autoconfig is not valid UTF-8");
  }
}

function emailParts(value: string): EmailParts {
  const address = value.trim();
  const separator = address.indexOf("@");
  const emailDomain = separator > 0 ? hostname(address.slice(separator + 1)) : null;
  if (
    address.length === 0
    || address.length > MAX_EMAIL_LENGTH
    || separator <= 0
    || separator !== address.lastIndexOf("@")
    || separator === address.length - 1
    || /\s/u.test(address)
    || hasControlCharacter(address)
    || !emailDomain
  ) {
    fail("A valid email address is required to resolve Autoconfig usernames");
  }
  return {
    address,
    localPart: address.slice(0, separator),
    domain: emailDomain,
  };
}

function compareText(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function hasControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

function hostname(value: string): string | null {
  const trimmed = value.trim();
  const normalized = trimmed.endsWith(".") ? trimmed.slice(0, -1).toLowerCase() : trimmed.toLowerCase();
  if (
    normalized.length === 0
    || normalized.length > MAX_HOSTNAME_LENGTH
    || hasControlCharacter(trimmed)
    || normalized.includes(":")
    || /^(?:\d+\.){3}\d+$/u.test(normalized)
    || LOCAL_HOST_SUFFIX_PATTERN.test(normalized)
  ) return null;
  const labels = normalized.split(".");
  if (labels.length < 2 || labels.some((label) => label.length > MAX_HOST_LABEL_LENGTH || !HOST_LABEL_PATTERN.test(label))) {
    return null;
  }
  return normalized;
}

function port(value: string, service: "imap" | "smtp"): number | null {
  const normalized = value.trim();
  if (!/^\d+$/u.test(normalized)) return null;
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65_535) return null;
  if (service === "smtp" && parsed === 25) return null;
  return parsed;
}

function tlsMode(value: string): AutoconfigTlsMode | null {
  const normalized = value.trim().toUpperCase();
  if (normalized === "SSL") return "implicit";
  if (normalized === "STARTTLS") return "starttls";
  return null;
}

function supportedTransport(service: "imap" | "smtp", value: number, mode: AutoconfigTlsMode): boolean {
  return service === "imap"
    ? (value === 993 && mode === "implicit") || (value === 143 && mode === "starttls")
    : (value === 465 && mode === "implicit") || ([587, 2525].includes(value) && mode === "starttls");
}

function directText(node: XmlNode, localName: string, required = true): string | null {
  const matches = children(node, localName);
  if (matches.length !== 1) return required ? null : "";
  const value = xmlText(matches[0]!).trim();
  if (value.length === 0) return required ? null : "";
  if (matches[0]!.children.length > 0 || hasControlCharacter(value)) return null;
  return value;
}

function resolveUsername(template: string, parts: EmailParts): string | null {
  const value = template.trim();
  if (value.length === 0 || hasControlCharacter(value)) return null;
  const resolved = value
    .replaceAll("%EMAILADDRESS%", parts.address)
    .replaceAll("%EMAILLOCALPART%", parts.localPart)
    .replaceAll("%EMAILDOMAIN%", parts.domain);
  if (
    resolved.length === 0
    || resolved.length > MAX_USERNAME_LENGTH
    || /%/u.test(resolved)
    || /\s/u.test(resolved)
    || hasControlCharacter(resolved)
  ) return null;
  return resolved;
}

function parseCandidate(
  node: XmlNode,
  service: "imap" | "smtp",
  parts: EmailParts,
  sourceIndex: number,
): Candidate | null {
  if ((node.attributes.type ?? "").trim().toLowerCase() !== service) return null;
  const hostValue = directText(node, "hostname");
  const portValue = directText(node, "port");
  const socketValue = directText(node, "socketType");
  const usernameValue = directText(node, "username");
  if (!hostValue || !portValue || !socketValue || !usernameValue) return null;
  const host = hostname(hostValue);
  const parsedPort = port(portValue, service);
  const parsedTlsMode = tlsMode(socketValue);
  const username = resolveUsername(usernameValue, parts);
  if (!host || parsedPort === null || !parsedTlsMode || !username || !supportedTransport(service, parsedPort, parsedTlsMode)) return null;
  return {
    settings: { host, port: parsedPort, tlsMode: parsedTlsMode, username },
    service,
    sourceIndex,
  };
}

function standardPortRank(service: "imap" | "smtp", value: number): number {
  if (service === "imap") {
    if (value === 993) return 2;
    if (value === 143) return 1;
    return 0;
  }
  if (value === 465) return 2;
  if (value === 587) return 2;
  if (value === 2525) return 1;
  return 0;
}

function compareCandidates(left: Candidate, right: Candidate): number {
  const leftTlsRank = left.settings.tlsMode === "implicit" ? 1 : 0;
  const rightTlsRank = right.settings.tlsMode === "implicit" ? 1 : 0;
  if (leftTlsRank !== rightTlsRank) return rightTlsRank - leftTlsRank;
  const leftPortRank = standardPortRank(left.service, left.settings.port);
  const rightPortRank = standardPortRank(right.service, right.settings.port);
  if (leftPortRank !== rightPortRank) return rightPortRank - leftPortRank;
  const hostOrder = compareText(left.settings.host, right.settings.host);
  if (hostOrder !== 0) return hostOrder;
  if (left.settings.port !== right.settings.port) return left.settings.port - right.settings.port;
  const usernameOrder = compareText(left.settings.username, right.settings.username);
  if (usernameOrder !== 0) return usernameOrder;
  return left.sourceIndex - right.sourceIndex;
}

function providerMatchesDomain(provider: XmlNode, domain: string): boolean {
  return children(provider, "domain").some((domainNode) => {
    const value = xmlText(domainNode).trim().toLowerCase().replace(/\.$/u, "");
    return value === domain;
  });
}

function selectedProviders(root: XmlNode, domain: string): XmlNode[] {
  const providers = children(root, "emailProvider");
  const matching = providers.filter((provider) => providerMatchesDomain(provider, domain));
  if (matching.length > 0) return matching;
  return providers.filter((provider) => children(provider, "domain").length === 0);
}

export function parseThunderbirdAutoconfig(
  source: string | Uint8Array,
  options: ThunderbirdAutoconfigOptions,
): ThunderbirdAutoconfigSettings | null {
  const maxBytes = boundedOption(options.maxBytes, DEFAULT_AUTOCONFIG_BYTES, MAX_AUTOCONFIG_BYTES, "maxBytes");
  const maxDepth = boundedOption(options.maxDepth, DEFAULT_AUTOCONFIG_DEPTH, MAX_AUTOCONFIG_DEPTH, "maxDepth");
  const maxNodes = boundedOption(options.maxNodes, DEFAULT_AUTOCONFIG_NODES, MAX_AUTOCONFIG_NODES, "maxNodes");
  const parts = emailParts(options.email);
  let root: XmlNode;
  try {
    root = parseXml(sourceText(source, maxBytes), { maxDepth, maxNodes });
  } catch (error) {
    if (error instanceof AutoconfigParseError) throw error;
    if (error instanceof XmlParseError) throw new AutoconfigParseError("Malformed Thunderbird Autoconfig XML");
    throw new AutoconfigParseError("Thunderbird Autoconfig could not be parsed");
  }
  if (root.localName !== "clientConfig") throw new AutoconfigParseError("Thunderbird Autoconfig root must be clientConfig");

  const providers = selectedProviders(root, parts.domain);
  if (children(root, "emailProvider").length === 0) {
    throw new AutoconfigParseError("Thunderbird Autoconfig has no emailProvider");
  }
  if (providers.length === 0) return null;

  const imapCandidates: Candidate[] = [];
  const smtpCandidates: Candidate[] = [];
  let sourceIndex = 0;
  for (const provider of providers) {
    for (const server of children(provider, "incomingServer")) {
      const candidate = parseCandidate(server, "imap", parts, sourceIndex);
      sourceIndex += 1;
      if (candidate) imapCandidates.push(candidate);
    }
    for (const server of children(provider, "outgoingServer")) {
      const candidate = parseCandidate(server, "smtp", parts, sourceIndex);
      sourceIndex += 1;
      if (candidate) smtpCandidates.push(candidate);
    }
  }
  if (imapCandidates.length === 0 || smtpCandidates.length === 0) return null;
  imapCandidates.sort(compareCandidates);
  smtpCandidates.sort(compareCandidates);
  return { imap: imapCandidates[0]!.settings, smtp: smtpCandidates[0]!.settings };
}
