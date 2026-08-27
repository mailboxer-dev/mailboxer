import { getDavConfig } from "../config";
import { annotateSpanFailure, logFailure } from "../diagnostics";
import type { DavConfig, MailConfig } from "../types";
import { withSpan } from "../tracing";
import { parseCalendarResource, serializeCalendarItem, IcalendarParseError } from "./ical";
import { parseContactResource, serializeContact, VcardParseError } from "./vcard";
import { isUtcIsoDateOrDateTime } from "./date";
import type {
  AddressBookCollection,
  CalendarCollection,
  CalendarComponentType,
  CalendarItem,
  CalendarItemInput,
  Contact,
  ContactInput,
  DavItemError,
  DavPage,
  DavService,
} from "./types";
import { child, children, parseXml, type XmlNode, xmlText, XmlParseError } from "./xml";

export const MAX_DAV_PAGE_SIZE = 50;
export const MAX_DAV_RESOURCE_BYTES = 512 * 1024;
export const MAX_DAV_RESPONSE_BYTES = 4 * 1024 * 1024;
export const MAX_DAV_REQUEST_BYTES = 256 * 1024;

const MAX_REDIRECTS = 4;
const MAX_XML_NODES = 20_000;
const DAV_NS = "DAV:";
const CALDAV_NS = "urn:ietf:params:xml:ns:caldav";
const CARDDAV_NS = "urn:ietf:params:xml:ns:carddav";
const APPLE_ICAL_NS = "http://apple.com/ns/ical/";
type DavMethod = "PROPFIND" | "REPORT" | "GET" | "PUT" | "DELETE";

const EMPTY_XML_NODE: XmlNode = {
  qName: "",
  localName: "",
  namespace: null,
  attributes: {},
  children: [],
  text: "",
};

const PRINCIPAL_PROPFIND = `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>`;

const CALENDAR_HOME_PROPFIND = `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/></d:prop></d:propfind>`;

const ADDRESS_BOOK_HOME_PROPFIND = `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><card:addressbook-home-set/></d:prop></d:propfind>`;

const CALENDAR_COLLECTION_PROPFIND = `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:apple="http://apple.com/ns/ical/"><d:prop>
<d:displayname/><d:resourcetype/><d:getetag/><d:getctag/><d:description/>
<c:calendar-description/><c:supported-calendar-component-set/><apple:calendar-color/><apple:calendar-timezone/>
</d:prop></d:propfind>`;

const ADDRESS_BOOK_COLLECTION_PROPFIND = `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop>
<d:displayname/><d:resourcetype/><d:getetag/><d:getctag/><d:description/>
<card:addressbook-description/><card:supported-address-data/>
</d:prop></d:propfind>`;

export class DavProtocolError extends Error {
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "DavProtocolError";
    this.status = status;
  }
}

export class DavAuthenticationError extends DavProtocolError {
  constructor() {
    super("iCloud DAV authentication failed", 401);
    this.name = "DavAuthenticationError";
  }
}

export class DavPermissionError extends DavProtocolError {
  constructor() {
    super("The iCloud DAV service denied access", 403);
    this.name = "DavPermissionError";
  }
}

export class DavNotFoundError extends DavProtocolError {
  constructor() {
    super("The iCloud DAV resource was not found", 404);
    this.name = "DavNotFoundError";
  }
}

export class DavConflictError extends DavProtocolError {
  constructor(status = 412) {
    super("The iCloud DAV resource changed; refresh it and retry with its current ETag", status);
    this.name = "DavConflictError";
  }
}

export class DavPayloadTooLargeError extends DavProtocolError {
  constructor(message = "The iCloud DAV response is too large") {
    super(message);
    this.name = "DavPayloadTooLargeError";
  }
}

export type DavFetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const defaultDavFetcher: DavFetcher = (input, init) => globalThis.fetch(input, init);

interface DavHttpResponse {
  url: string;
  status: number;
  headers: Headers;
  body: Uint8Array;
}

interface DavProperty {
  node: XmlNode;
  status: number;
}

interface DavEntry {
  href: string;
  status: number;
  properties: DavProperty[];
}

interface DavResourceRef {
  href: string;
  etag: string | null;
  collectionHref: string;
}

export interface CalendarQuery {
  calendarHref?: string;
  componentType: CalendarComponentType | "any";
  start?: string;
  end?: string;
  text?: string;
}

export interface ContactQuery {
  addressBookHref?: string;
  query?: string;
}

function serviceHost(service: DavService, hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return service === "calendar"
    ? /^(?:caldav|p\d+-caldav)\.icloud\.com$/u.test(normalized)
    : /^(?:contacts|p\d+-contacts)\.icloud\.com$/u.test(normalized);
}

function safeText(value: string | null | undefined): string | null {
  const trimmed = value?.trim() ?? "";
  return trimmed || null;
}

function validEtag(value: string): boolean {
  if (!value.trim() || value.trim() === "*") return false;
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 31 || code === 127) return false;
  }
  return true;
}

function xmlEscape(value: string): string {
  return value.replace(/[&<>"']/gu, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&apos;",
  })[character] ?? character);
}

function responseStatus(value: string | null): number | null {
  const match = value?.match(/\b(\d{3})\b/u);
  if (!match) return null;
  const status = Number(match[1]);
  return Number.isInteger(status) ? status : null;
}

async function discardResponse(response: Response): Promise<void> {
  if (response.body) await response.body.cancel().catch(() => undefined);
}

async function readBoundedResponse(response: Response, maxBytes: number): Promise<Uint8Array> {
  const declaredLength = Number(response.headers.get("Content-Length") ?? "");
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    await discardResponse(response);
    throw new DavPayloadTooLargeError();
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      if (!result.value) continue;
      total += result.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new DavPayloadTooLargeError();
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new DavProtocolError("The iCloud DAV response was not valid UTF-8");
  }
}

function parseMultiStatus(bytes: Uint8Array): DavEntry[] {
  let root: XmlNode;
  try {
    root = parseXml(decodeUtf8(bytes), { maxNodes: MAX_XML_NODES });
  } catch (error) {
    if (error instanceof XmlParseError) throw new DavProtocolError("The iCloud DAV XML response was invalid");
    throw error;
  }
  if (root.localName !== "multistatus" || root.namespace !== DAV_NS) throw new DavProtocolError("The iCloud DAV response was not a multistatus document");
  return children(root, "response", DAV_NS).map((response) => {
    const href = safeText(xmlText(child(response, "href", DAV_NS) ?? EMPTY_XML_NODE));
    if (!href) throw new DavProtocolError("The iCloud DAV response omitted a resource href");
    const propertyStatuses = children(response, "propstat", DAV_NS).flatMap((propstat) => {
      const status = responseStatus(xmlText(child(propstat, "status", DAV_NS) ?? EMPTY_XML_NODE)) ?? 200;
      const prop = child(propstat, "prop", DAV_NS);
      return prop ? prop.children.map((node) => ({ node, status })) : [];
    });
    const directStatus = responseStatus(xmlText(child(response, "status", DAV_NS) ?? EMPTY_XML_NODE));
    return {
      href,
      status: directStatus ?? propertyStatuses[0]?.status ?? 200,
      properties: propertyStatuses,
    };
  });
}

function property(entry: DavEntry, localName: string, namespace?: string): XmlNode | undefined {
  return entry.properties.find((candidate) => candidate.status >= 200 && candidate.status < 300 && candidate.node.localName === localName && (namespace === undefined || candidate.node.namespace === namespace))?.node;
}

function propertyText(entry: DavEntry, localName: string, namespace?: string): string | null {
  const node = property(entry, localName, namespace);
  return node ? safeText(xmlText(node)) : null;
}

function propertyRawText(entry: DavEntry, localName: string, namespace?: string): string | null {
  const node = property(entry, localName, namespace);
  return node ? xmlText(node) : null;
}

function propertyStatus(entry: DavEntry, localName: string, namespace?: string): number | undefined {
  return entry.properties.find((candidate) => candidate.node.localName === localName && (namespace === undefined || candidate.node.namespace === namespace))?.status;
}

function propertyHref(entry: DavEntry, localName: string, namespace?: string): string | null {
  const node = property(entry, localName, namespace);
  return node ? safeText(xmlText(child(node, "href", DAV_NS) ?? EMPTY_XML_NODE)) : null;
}

function resourceType(entry: DavEntry): XmlNode | undefined {
  return property(entry, "resourcetype", DAV_NS);
}

function hasResourceType(entry: DavEntry, localName: string, namespace: string): boolean {
  const type = resourceType(entry);
  return type?.children.some((node) => node.localName === localName && (node.namespace === namespace || node.namespace === null)) === true;
}

function normalizeHref(value: string, base: URL, service: DavService): string {
  let href: URL;
  try {
    href = new URL(value, base);
  } catch {
    throw new DavProtocolError("The iCloud DAV response contained an invalid href");
  }
  if (href.protocol !== "https:" || href.username || href.password || href.hash || (href.port && href.port !== "443") || !serviceHost(service, href.hostname)) {
    throw new DavProtocolError("The iCloud DAV response contained an unsafe href");
  }
  return href.toString();
}

function davRequestHref(value: string): string {
  const href = new URL(value);
  return `${href.pathname}${href.search}`;
}

function formatReportDate(value: string): string {
  const dateOnly = value.match(/^(\d{4})-(\d{2})-(\d{2})$/u);
  if (dateOnly && isUtcIsoDateOrDateTime(value)) return `${dateOnly[1]}${dateOnly[2]}${dateOnly[3]}T000000Z`;
  if (!isUtcIsoDateOrDateTime(value)) throw new DavProtocolError("Calendar date filters must be valid UTC ISO dates");
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new DavProtocolError("Calendar date filters must be valid UTC ISO dates");
  return parsed.toISOString().replace(/[-:]/gu, "").replace(/\.\d{3}/u, "");
}

function calendarComponentFilter(componentType: CalendarComponentType | "any", query: CalendarQuery, textProperty?: string): string {
  if (componentType === "any") return "";
  const components = [componentType];
  return components.map((component) => {
    const filters: string[] = [];
    if (query.start || query.end) {
      const start = query.start ? ` start="${xmlEscape(formatReportDate(query.start))}"` : "";
      const end = query.end ? ` end="${xmlEscape(formatReportDate(query.end))}"` : "";
      filters.push(`<c:time-range${start}${end}/>`);
    }
    if (query.text && textProperty) {
      filters.push(`<c:prop-filter name="${textProperty}"><c:text-match collation="i;unicode-casemap" match-type="contains">${xmlEscape(query.text)}</c:text-match></c:prop-filter>`);
    }
    return `<c:comp-filter name="${component}">${filters.join("")}</c:comp-filter>`;
  }).join("");
}

function calendarQueryBody(query: CalendarQuery, textProperty?: string): string {
  const start = query.start ? formatReportDate(query.start) : undefined;
  const end = query.end ? formatReportDate(query.end) : undefined;
  if (start && end && start >= end) throw new DavProtocolError("Calendar date filter end must be after start");
  return `<?xml version="1.0" encoding="UTF-8"?>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/></d:prop><c:filter><c:comp-filter name="VCALENDAR">${calendarComponentFilter(query.componentType, query, textProperty)}</c:comp-filter></c:filter></c:calendar-query>`;
}

function calendarMultigetBody(hrefs: string[]): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop>${hrefs.map((href) => `<d:href>${xmlEscape(href)}</d:href>`).join("")}</c:calendar-multiget>`;
}

function addressBookQueryBody(query: string | undefined, textProperty = "FN"): string {
  const filter = query
    ? `<card:prop-filter name="${textProperty}"><card:text-match collation="i;unicode-casemap" match-type="contains">${xmlEscape(query)}</card:text-match></card:prop-filter>`
    : '<card:prop-filter name="FN"/>';
  return `<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/></d:prop><card:filter>${filter}</card:filter></card:addressbook-query>`;
}

function addressBookMultigetBody(hrefs: string[]): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-multiget xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/><card:address-data/></d:prop>${hrefs.map((href) => `<d:href>${xmlEscape(href)}</d:href>`).join("")}</card:addressbook-multiget>`;
}

function entryError(entry: DavEntry, base: URL, service: DavService): DavItemError {
  return { href: normalizeHref(entry.href, base, service), status: entry.status };
}

function entryRef(entry: DavEntry, base: URL, service: DavService, collectionHref: string): DavResourceRef {
  return {
    href: normalizeHref(entry.href, base, service),
    etag: propertyText(entry, "getetag", DAV_NS),
    collectionHref,
  };
}

function uniqueErrors(errors: DavItemError[]): DavItemError[] {
  return [...new Map(errors.map((error) => [`${error.href}\u0000${error.status}`, error])).values()];
}

function parseCalendar(raw: string, href: string, etag: string | null): CalendarItem {
  return withSpan("dav.resource.parse", {
    "dav.service": "calendar",
    "dav.resource_bytes": new TextEncoder().encode(raw).byteLength,
  }, (span) => {
    try {
      const item = parseCalendarResource(raw, href, etag, MAX_DAV_RESOURCE_BYTES);
      span.setAttribute("dav.component_type", item.componentType);
      return item;
    } catch (error) {
      annotateSpanFailure(span, error);
      throw error;
    }
  });
}

function parseContact(raw: string, href: string, etag: string | null): Contact {
  return withSpan("dav.resource.parse", {
    "dav.service": "contacts",
    "dav.resource_bytes": new TextEncoder().encode(raw).byteLength,
  }, (span) => {
    try {
      const contact = parseContactResource(raw, href, etag, MAX_DAV_RESOURCE_BYTES);
      span.setAttribute("dav.resource_type", "vcard");
      return contact;
    } catch (error) {
      annotateSpanFailure(span, error);
      throw error;
    }
  });
}

export class DavClient {
  private readonly authHeader: string;
  private readonly fetcher: DavFetcher;
  private readonly config: DavConfig;
  private readonly discovery = new Map<DavService, { rootUrl: string; homeUrl: string }>();

  constructor(
    credentials: Pick<MailConfig, "email" | "password">,
    config: DavConfig = getDavConfig({}),
    fetcher: DavFetcher = defaultDavFetcher,
  ) {
    this.authHeader = `Basic ${base64(credentials.email, credentials.password)}`;
    this.config = config;
    this.fetcher = fetcher;
  }

  private initialUrl(service: DavService): URL {
    const value = service === "calendar" ? this.config.caldavUrl : this.config.carddavUrl;
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new DavProtocolError("The configured iCloud DAV URL is invalid");
    }
    return this.assertUrl(url, service);
  }

  private assertUrl(url: URL, service: DavService): URL {
    if (url.protocol !== "https:" || url.username || url.password || url.hash || (url.port && url.port !== "443") || !serviceHost(service, url.hostname)) {
      throw new DavProtocolError("The configured iCloud DAV URL is unsafe");
    }
    return url;
  }

  private resolveUrl(value: string, base: URL, service: DavService): URL {
    try {
      return this.assertUrl(new URL(value, base), service);
    } catch (error) {
      if (error instanceof DavProtocolError) throw error;
      throw new DavProtocolError("The iCloud DAV response contained an invalid URL");
    }
  }

  private async request(
    service: DavService,
    method: DavMethod,
    target: URL,
    options: { headers?: Record<string, string>; body?: string } = {},
  ): Promise<DavHttpResponse> {
    return withSpan("dav.request", { "dav.service": service, "dav.method": method }, async (span) => {
      let redirects = 0;
      const bodyBytes = options.body === undefined ? 0 : new TextEncoder().encode(options.body).byteLength;
      try {
        let url = this.assertUrl(target, service);
        if (bodyBytes > MAX_DAV_REQUEST_BYTES) throw new DavPayloadTooLargeError("The DAV request body is too large");
        while (true) {
          const headers = new Headers({
            Accept: "application/xml, text/calendar, text/vcard, text/*;q=0.8",
            Authorization: this.authHeader,
            "Cache-Control": "no-store",
            "User-Agent": "mailboxer/0.1",
            ...options.headers,
          });
          const response = await this.fetcher(url, {
            method,
            headers,
            body: options.body,
            cache: "no-store",
            redirect: "manual",
          });
          span.setAttribute("dav.http_status", response.status);
          if (response.status >= 300 && response.status < 400) {
            if (redirects >= MAX_REDIRECTS) {
              await discardResponse(response);
              throw new DavProtocolError("The iCloud DAV service redirected too many times");
            }
            const location = response.headers.get("Location");
            await discardResponse(response);
            if (!location) throw new DavProtocolError("The iCloud DAV redirect omitted a location");
            url = this.resolveUrl(location, url, service);
            redirects += 1;
            continue;
          }
          span.setAttribute("dav.redirect_count", redirects);
          if (response.status === 401) {
            await discardResponse(response);
            throw new DavAuthenticationError();
          }
          if (response.status === 403) {
            await discardResponse(response);
            throw new DavPermissionError();
          }
          if (response.status === 404) {
            await discardResponse(response);
            throw new DavNotFoundError();
          }
          if (response.status === 409 || response.status === 412) {
            await discardResponse(response);
            throw new DavConflictError(response.status);
          }
          if (response.status >= 500) {
            await discardResponse(response);
            throw new DavProtocolError("The iCloud DAV service is temporarily unavailable", response.status);
          }
          if (response.status < 200 || response.status >= 300) {
            await discardResponse(response);
            throw new DavProtocolError(`The iCloud DAV request failed with HTTP ${response.status}`, response.status);
          }
          const body = await readBoundedResponse(response, method === "GET" ? MAX_DAV_RESOURCE_BYTES : MAX_DAV_RESPONSE_BYTES);
          span.setAttribute("dav.response_bytes", body.byteLength);
          return { url: url.toString(), status: response.status, headers: response.headers, body };
        }
      } catch (error) {
        annotateSpanFailure(span, error);
        logFailure(
          "dav_request_failed",
          {
            service,
            method,
            redirect_count: redirects,
            request_bytes: bodyBytes,
          },
          error,
        );
        throw error;
      }
    });
  }

  private async propfind(service: DavService, url: URL, body: string, depth: "0" | "1"): Promise<{ response: DavHttpResponse; entries: DavEntry[] }> {
    const response = await this.request(service, "PROPFIND", url, {
      headers: { "Content-Type": "application/xml; charset=utf-8", Depth: depth },
      body,
    });
    try {
      return { response, entries: parseMultiStatus(response.body) };
    } catch (error) {
      logFailure(
        "dav_response_parse_failed",
        { service, method: "PROPFIND", response_bytes: response.body.byteLength },
        error,
      );
      throw error;
    }
  }

  private async report(service: DavService, url: URL, body: string): Promise<{ response: DavHttpResponse; entries: DavEntry[] }> {
    return withSpan("dav.report", { "dav.service": service, "dav.request_bytes": new TextEncoder().encode(body).byteLength }, async (span) => {
      const response = await this.request(service, "REPORT", url, {
        headers: { "Content-Type": "application/xml; charset=utf-8", Depth: "1" },
        body,
      });
      try {
        const entries = parseMultiStatus(response.body);
        span.setAttribute("dav.response_status", response.status);
        span.setAttribute("dav.response_bytes", response.body.byteLength);
        span.setAttribute("dav.resource_count", entries.length);
        return { response, entries };
      } catch (error) {
        annotateSpanFailure(span, error);
        logFailure(
          "dav_response_parse_failed",
          { service, method: "REPORT", response_bytes: response.body.byteLength },
          error,
        );
        throw error;
      }
    });
  }

  private async discover(service: DavService): Promise<{ rootUrl: string; homeUrl: string }> {
    const cached = this.discovery.get(service);
    if (cached) return cached;
    return withSpan("dav.discovery", { "dav.service": service }, async (span) => {
      const configured = this.initialUrl(service);
      const wellKnown = new URL(`/.well-known/${service === "calendar" ? "caldav" : "carddav"}`, configured);
      let bootstrap: { response: DavHttpResponse; entries: DavEntry[] };
      try {
        bootstrap = await this.propfind(service, wellKnown, PRINCIPAL_PROPFIND, "0");
      } catch (error) {
        if (!(error instanceof DavNotFoundError)) throw error;
        bootstrap = await this.propfind(service, configured, PRINCIPAL_PROPFIND, "0");
      }
      const rootUrl = new URL(bootstrap.response.url);
      const bootstrapEntry = bootstrap.entries[0];
      const principalHref = bootstrapEntry ? propertyHref(bootstrapEntry, "current-user-principal", DAV_NS) : null;
      const principalUrl = principalHref ? this.resolveUrl(principalHref, rootUrl, service) : rootUrl;
      const homeBody = service === "calendar" ? CALENDAR_HOME_PROPFIND : ADDRESS_BOOK_HOME_PROPFIND;
      const principal = await this.propfind(service, principalUrl, homeBody, "0");
      const principalEntry = principal.entries[0];
      const homeName = service === "calendar" ? "calendar-home-set" : "addressbook-home-set";
      const homeNamespace = service === "calendar" ? CALDAV_NS : CARDDAV_NS;
      const homeHref = (principalEntry ? propertyHref(principalEntry, homeName, homeNamespace) : null) ??
        (bootstrapEntry ? propertyHref(bootstrapEntry, homeName, homeNamespace) : null);
      if (!homeHref) throw new DavProtocolError("The iCloud DAV service did not advertise a home collection");
      const homeUrl = this.resolveUrl(homeHref, new URL(principal.response.url), service);
      span.setAttribute("dav.redirected", bootstrap.response.url !== configured.toString());
      this.discovery.set(service, { rootUrl: rootUrl.toString(), homeUrl: homeUrl.toString() });
      return { rootUrl: rootUrl.toString(), homeUrl: homeUrl.toString() };
    });
  }

  async verifyService(service: DavService): Promise<void> {
    if (service === "calendar") await this.listCalendars();
    else await this.listAddressBooks();
  }

  private async listCollections(service: "calendar"): Promise<CalendarCollection[]>;
  private async listCollections(service: "contacts"): Promise<AddressBookCollection[]>;
  private async listCollections(service: DavService): Promise<Array<CalendarCollection | AddressBookCollection>> {
    const discovered = await this.discover(service);
    const body = service === "calendar" ? CALENDAR_COLLECTION_PROPFIND : ADDRESS_BOOK_COLLECTION_PROPFIND;
    const { response, entries } = await this.propfind(service, new URL(discovered.homeUrl), body, "1");
    const base = new URL(response.url);
    if (service === "calendar") {
      return entries.filter((entry) => hasResourceType(entry, "calendar", CALDAV_NS)).map((entry) => ({
        href: normalizeHref(entry.href, base, service),
        displayName: propertyText(entry, "displayname", DAV_NS),
        description: propertyText(entry, "calendar-description", CALDAV_NS) ?? propertyText(entry, "description", DAV_NS),
        color: propertyText(entry, "calendar-color", CALDAV_NS) ?? propertyText(entry, "calendar-color", APPLE_ICAL_NS),
        timezone: propertyText(entry, "calendar-timezone", CALDAV_NS) ?? propertyText(entry, "calendar-timezone", APPLE_ICAL_NS),
        componentTypes: children(property(entry, "supported-calendar-component-set", CALDAV_NS) ?? EMPTY_XML_NODE, "comp", CALDAV_NS).map((node) => node.attributes.name?.toUpperCase()).filter((name): name is CalendarComponentType => name === "VEVENT" || name === "VTODO"),
      }));
    }
    return entries.filter((entry) => hasResourceType(entry, "addressbook", CARDDAV_NS)).map((entry) => ({
      href: normalizeHref(entry.href, base, service),
      displayName: propertyText(entry, "displayname", DAV_NS),
      description: propertyText(entry, "addressbook-description", CARDDAV_NS) ?? propertyText(entry, "description", DAV_NS),
      vcardVersions: children(property(entry, "supported-address-data", CARDDAV_NS) ?? EMPTY_XML_NODE, "address-data", CARDDAV_NS).map((node) => node.attributes.version).filter((version): version is string => Boolean(version)),
    }));
  }

  async listCalendars(): Promise<CalendarCollection[]> {
    return this.listCollections("calendar");
  }

  async listAddressBooks(): Promise<AddressBookCollection[]> {
    return this.listCollections("contacts");
  }

  private collectionUrl(service: DavService, href: string): URL {
    const base = new URL(service === "calendar" ? this.config.caldavUrl : this.config.carddavUrl);
    return this.resolveUrl(href, base, service);
  }

  private async queryCalendarRefs(query: CalendarQuery): Promise<{ refs: DavResourceRef[]; errors: DavItemError[] }> {
    const collections = query.calendarHref
      ? [{ href: normalizeHref(query.calendarHref, this.initialUrl("calendar"), "calendar") }]
      : await this.listCalendars();
    const refs: DavResourceRef[] = [];
    const errors: DavItemError[] = [];
    const textProperties = query.text ? ["SUMMARY", "DESCRIPTION", "LOCATION"] : [undefined];
    const componentTypes: Array<CalendarComponentType | "any"> = query.componentType === "any" && (query.text || query.start || query.end)
      ? ["VEVENT", "VTODO"]
      : [query.componentType];
    for (const collection of collections) {
      for (const componentType of componentTypes) {
        for (const textProperty of textProperties) {
          const { response, entries } = await this.report("calendar", new URL(collection.href), calendarQueryBody({ ...query, componentType }, textProperty));
          const base = new URL(response.url);
          for (const entry of entries) {
            if (entry.status >= 200 && entry.status < 300) refs.push(entryRef(entry, base, "calendar", collection.href));
            else errors.push(entryError(entry, base, "calendar"));
          }
        }
      }
    }
    return { refs, errors };
  }

  private async queryContactRefs(query: ContactQuery): Promise<{ refs: DavResourceRef[]; errors: DavItemError[] }> {
    const collections = query.addressBookHref
      ? [{ href: normalizeHref(query.addressBookHref, this.initialUrl("contacts"), "contacts") }]
      : await this.listAddressBooks();
    const refs: DavResourceRef[] = [];
    const errors: DavItemError[] = [];
    const textProperties = query.query ? ["FN", "N", "EMAIL", "TEL", "ORG"] : ["FN"];
    for (const collection of collections) {
      for (const textProperty of textProperties) {
        const { response, entries } = await this.report("contacts", new URL(collection.href), addressBookQueryBody(query.query, textProperty));
        const base = new URL(response.url);
        for (const entry of entries) {
          if (entry.status >= 200 && entry.status < 300) refs.push(entryRef(entry, base, "contacts", collection.href));
          else errors.push(entryError(entry, base, "contacts"));
        }
      }
    }
    return { refs, errors };
  }

  private async calendarMultiget(refs: DavResourceRef[]): Promise<{ items: CalendarItem[]; errors: DavItemError[] }> {
    const items: CalendarItem[] = [];
    const errors: DavItemError[] = [];
    const groups = new Map<string, DavResourceRef[]>();
    for (const ref of refs) groups.set(ref.collectionHref, [...(groups.get(ref.collectionHref) ?? []), ref]);
    for (const [collectionHref, group] of groups) {
      const { response, entries } = await this.report("calendar", new URL(collectionHref), calendarMultigetBody(group.map((ref) => davRequestHref(ref.href))));
      const base = new URL(response.url);
      for (const entry of entries) {
        const href = normalizeHref(entry.href, base, "calendar");
        if (entry.status < 200 || entry.status >= 300) {
          errors.push({ href, status: entry.status });
          continue;
        }
        const data = propertyRawText(entry, "calendar-data", CALDAV_NS);
        if (!data) {
          errors.push({ href, status: propertyStatus(entry, "calendar-data", CALDAV_NS) ?? 502 });
          continue;
        }
        try {
          items.push(parseCalendar(data, href, propertyText(entry, "getetag", DAV_NS)));
        } catch (error) {
          if (error instanceof IcalendarParseError) errors.push({ href, status: 422 });
          else throw error;
        }
      }
    }
    return { items, errors };
  }

  private async contactMultiget(refs: DavResourceRef[]): Promise<{ items: Contact[]; errors: DavItemError[] }> {
    const items: Contact[] = [];
    const errors: DavItemError[] = [];
    const groups = new Map<string, DavResourceRef[]>();
    for (const ref of refs) groups.set(ref.collectionHref, [...(groups.get(ref.collectionHref) ?? []), ref]);
    for (const [collectionHref, group] of groups) {
      const { response, entries } = await this.report("contacts", new URL(collectionHref), addressBookMultigetBody(group.map((ref) => davRequestHref(ref.href))));
      const base = new URL(response.url);
      for (const entry of entries) {
        const href = normalizeHref(entry.href, base, "contacts");
        if (entry.status < 200 || entry.status >= 300) {
          errors.push({ href, status: entry.status });
          continue;
        }
        const data = propertyRawText(entry, "address-data", CARDDAV_NS);
        if (!data) {
          errors.push({ href, status: propertyStatus(entry, "address-data", CARDDAV_NS) ?? 502 });
          continue;
        }
        try {
          items.push(parseContact(data, href, propertyText(entry, "getetag", DAV_NS)));
        } catch (error) {
          if (error instanceof VcardParseError) errors.push({ href, status: 422 });
          else throw error;
        }
      }
    }
    return { items, errors };
  }

  async listCalendarItems(query: CalendarQuery, afterHref: string | undefined, limit: number): Promise<DavPage<CalendarItem>> {
    return withSpan("dav.calendar.list_items", { "dav.limit": limit }, async (span) => {
      const result = await this.queryCalendarRefs(query);
      const refs = [...new Map(result.refs.map((ref) => [ref.href, ref])).values()].sort((left, right) => left.href.localeCompare(right.href));
      const after = afterHref ? normalizeHref(afterHref, this.initialUrl("calendar"), "calendar") : undefined;
      const eligible = refs.filter((ref) => !after || ref.href > after);
      const selected = eligible.slice(0, Math.min(limit, MAX_DAV_PAGE_SIZE));
      const fetched = await this.calendarMultiget(selected);
      const order = new Map(selected.map((ref, index) => [ref.href, index]));
      fetched.items.sort((left, right) => (order.get(left.href) ?? 0) - (order.get(right.href) ?? 0));
      span.setAttribute("dav.match_count", refs.length);
      return {
        items: fetched.items,
        errors: uniqueErrors([...result.errors, ...fetched.errors]),
        lastHref: selected.at(-1)?.href ?? null,
        hasMore: eligible.length > selected.length,
      };
    });
  }

  async listContacts(query: ContactQuery, afterHref: string | undefined, limit: number): Promise<DavPage<Contact>> {
    return withSpan("dav.contacts.list_items", { "dav.limit": limit }, async (span) => {
      const result = await this.queryContactRefs(query);
      const refs = [...new Map(result.refs.map((ref) => [ref.href, ref])).values()].sort((left, right) => left.href.localeCompare(right.href));
      const after = afterHref ? normalizeHref(afterHref, this.initialUrl("contacts"), "contacts") : undefined;
      const eligible = refs.filter((ref) => !after || ref.href > after);
      const selected = eligible.slice(0, Math.min(limit, MAX_DAV_PAGE_SIZE));
      const fetched = await this.contactMultiget(selected);
      const order = new Map(selected.map((ref, index) => [ref.href, index]));
      fetched.items.sort((left, right) => (order.get(left.href) ?? 0) - (order.get(right.href) ?? 0));
      span.setAttribute("dav.match_count", refs.length);
      return {
        items: fetched.items,
        errors: uniqueErrors([...result.errors, ...fetched.errors]),
        lastHref: selected.at(-1)?.href ?? null,
        hasMore: eligible.length > selected.length,
      };
    });
  }

  async getCalendarItem(href: string): Promise<CalendarItem> {
    const url = this.collectionUrl("calendar", href);
    const response = await this.request("calendar", "GET", url);
    return parseCalendar(decodeUtf8(response.body), response.url, response.headers.get("ETag"));
  }

  async getContact(href: string): Promise<Contact> {
    const url = this.collectionUrl("contacts", href);
    const response = await this.request("contacts", "GET", url);
    return parseContact(decodeUtf8(response.body), response.url, response.headers.get("ETag"));
  }

  private async write(
    service: DavService,
    href: string,
    body: string,
    contentType: string,
    etag: string | undefined,
  ): Promise<DavHttpResponse> {
    const url = this.collectionUrl(service, href);
    return this.request(service, "PUT", url, {
      headers: {
        "Content-Type": contentType,
        ...(etag ? { "If-Match": etag } : { "If-None-Match": "*" }),
      },
      body,
    });
  }

  async createCalendarItem(calendarHref: string, input: CalendarItemInput): Promise<CalendarItem> {
    const raw = input.rawIcalendar ?? serializeCalendarItem(input);
    const provisional = parseCalendar(raw, "https://caldav.icloud.com/placeholder.ics", null);
    if (provisional.componentType !== input.componentType) throw new IcalendarParseError("Calendar resource type does not match the requested type");
    const collection = this.collectionUrl("calendar", calendarHref);
    if (!collection.pathname.endsWith("/")) collection.pathname += "/";
    const href = new URL(`${crypto.randomUUID()}.ics`, collection).toString();
    const response = await this.write("calendar", href, raw, "text/calendar; charset=utf-8", undefined);
    const etag = response.headers.get("ETag");
    return etag
      ? parseCalendar(raw, href, etag)
      : this.getCalendarItem(href);
  }

  async updateCalendarItem(href: string, etag: string, input: CalendarItemInput): Promise<CalendarItem> {
    if (!validEtag(etag)) throw new DavConflictError();
    const raw = input.rawIcalendar ?? serializeCalendarItem(input);
    const provisional = parseCalendar(raw, href, etag);
    if (provisional.componentType !== input.componentType) throw new IcalendarParseError("Calendar resource type does not match the requested type");
    const response = await this.write("calendar", href, raw, "text/calendar; charset=utf-8", etag);
    const responseEtag = response.headers.get("ETag");
    return responseEtag ? { ...provisional, etag: responseEtag } : this.getCalendarItem(href);
  }

  async createContact(addressBookHref: string, input: ContactInput): Promise<Contact> {
    const raw = input.rawVcard ?? serializeContact(input);
    parseContact(raw, "https://contacts.icloud.com/placeholder.vcf", null);
    const collection = this.collectionUrl("contacts", addressBookHref);
    if (!collection.pathname.endsWith("/")) collection.pathname += "/";
    const href = new URL(`${crypto.randomUUID()}.vcf`, collection).toString();
    const response = await this.write("contacts", href, raw, "text/vcard; version=3.0; charset=utf-8", undefined);
    const etag = response.headers.get("ETag");
    return etag
      ? parseContact(raw, href, etag)
      : this.getContact(href);
  }

  async updateContact(href: string, etag: string, input: ContactInput): Promise<Contact> {
    if (!validEtag(etag)) throw new DavConflictError();
    const raw = input.rawVcard ?? serializeContact(input);
    const provisional = parseContact(raw, href, etag);
    const response = await this.write("contacts", href, raw, "text/vcard; version=3.0; charset=utf-8", etag);
    const responseEtag = response.headers.get("ETag");
    return responseEtag ? { ...provisional, etag: responseEtag } : this.getContact(href);
  }

  async deleteCalendarItem(href: string, etag: string): Promise<void> {
    if (!validEtag(etag)) throw new DavConflictError();
    await this.request("calendar", "DELETE", this.collectionUrl("calendar", href), { headers: { "If-Match": etag } });
  }

  async deleteContact(href: string, etag: string): Promise<void> {
    if (!validEtag(etag)) throw new DavConflictError();
    await this.request("contacts", "DELETE", this.collectionUrl("contacts", href), { headers: { "If-Match": etag } });
  }
}

function base64(email: string, password: string): string {
  const bytes = new TextEncoder().encode(`${email}:${password}`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
