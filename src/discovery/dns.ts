const DNS_HEADER_BYTES = 12;
export const DNS_CLASS_IN = 1;
const DNS_MAX_PACKET_BYTES = 65_535;
const DNS_MAX_NAME_BYTES = 255;
const DNS_MAX_LABEL_BYTES = 63;
const DNS_MAX_RDATA_BYTES = 65_535;
const DNS_MAX_TXT_BYTES = 65_535;
const DNS_MAX_TXT_STRINGS = 1_024;
const DNS_MAX_RECORDS = 1_024;
const DNS_MAX_POINTER_HOPS = 32;

export const DEFAULT_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

export const DNS_RECORD_TYPES = {
  MX: 15,
  TXT: 16,
  SRV: 33,
} as const;

export type DnsRecordType = keyof typeof DNS_RECORD_TYPES;
export type DnsRecordTypeCode = (typeof DNS_RECORD_TYPES)[DnsRecordType];

export interface DnsQuestion {
  name: string;
  type: DnsRecordType;
  typeCode: DnsRecordTypeCode;
  classCode: typeof DNS_CLASS_IN;
}

export interface DnsQuery {
  id: number;
  name: string;
  type: DnsRecordType;
  question: DnsQuestion;
  packet: Uint8Array;
}

export interface DnsQueryOptions {
  /** A transaction ID in the inclusive range 0..65535. */
  id?: number;
  /** Whether the query asks the recursive resolver to perform recursion. */
  recursionDesired?: boolean;
}

export interface DnsParserLimits {
  /** Maximum complete DNS message size accepted by the parser. */
  maxPacketBytes?: number;
  /** Maximum number of resource records across answer, authority, and additional sections. */
  maxRecords?: number;
  /** Maximum expanded wire length of any DNS name, including its root terminator. */
  maxNameBytes?: number;
  /** Maximum number of compression pointers followed while decoding one name. */
  maxPointerHops?: number;
  /** Maximum RDATA length for one resource record. */
  maxRdataBytes?: number;
  /** Maximum total payload bytes in one TXT resource record. */
  maxTxtBytes?: number;
  /** Maximum character-strings in one TXT resource record. */
  maxTxtStrings?: number;
}

export const DEFAULT_DNS_LIMITS = {
  maxPacketBytes: DNS_MAX_PACKET_BYTES,
  maxRecords: DNS_MAX_RECORDS,
  maxNameBytes: DNS_MAX_NAME_BYTES,
  maxPointerHops: DNS_MAX_POINTER_HOPS,
  maxRdataBytes: DNS_MAX_RDATA_BYTES,
  maxTxtBytes: DNS_MAX_TXT_BYTES,
  maxTxtStrings: DNS_MAX_TXT_STRINGS,
} as const satisfies Required<{ [K in keyof DnsParserLimits]-?: number }>;

interface BoundedDnsLimits {
  maxPacketBytes: number;
  maxRecords: number;
  maxNameBytes: number;
  maxPointerHops: number;
  maxRdataBytes: number;
  maxTxtBytes: number;
  maxTxtStrings: number;
}

export class DnsFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DnsFormatError";
  }
}

export interface DnsResponseFlags {
  raw: number;
  qr: boolean;
  opcode: number;
  authoritative: boolean;
  truncated: boolean;
  recursionDesired: boolean;
  recursionAvailable: boolean;
  authenticated: boolean;
  checkingDisabled: boolean;
  rcode: number;
}

interface DnsRecordBase {
  name: string;
  classCode: number;
  ttl: number;
  typeCode: number;
  rdataLength: number;
  section: DnsRecordSection;
}

export type DnsRecordSection = "answer" | "authority" | "additional";

export interface MxRecord extends DnsRecordBase {
  type: "MX";
  typeCode: typeof DNS_RECORD_TYPES.MX;
  preference: number;
  exchange: string;
}

export interface SrvRecord extends DnsRecordBase {
  type: "SRV";
  typeCode: typeof DNS_RECORD_TYPES.SRV;
  priority: number;
  weight: number;
  port: number;
  target: string;
}

export interface TxtRecord extends DnsRecordBase {
  type: "TXT";
  typeCode: typeof DNS_RECORD_TYPES.TXT;
  /** UTF-8-decoded character-strings. The original octets are in rawStrings. */
  strings: string[];
  /** Original DNS character-string octets, copied out of the response packet. */
  rawStrings: Uint8Array[];
  /** RFC 1035 presentation value: character-strings concatenated in order. */
  text: string;
}

export interface UnknownDnsRecord extends DnsRecordBase {
  type: "UNKNOWN";
  typeCode: number;
  rdata: Uint8Array;
}

export type DnsRecord = MxRecord | SrvRecord | TxtRecord | UnknownDnsRecord;

export interface DnsResponse {
  id: number;
  flags: DnsResponseFlags;
  rcode: number;
  question: DnsQuestion;
  answers: DnsRecord[];
  authorities: DnsRecord[];
  additionals: DnsRecord[];
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const lenientTextDecoder = new TextDecoder();

function isSafeIntegerInRange(value: number, maximum: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function checkedLimit(
  value: number | undefined,
  fallback: number,
  maximum: number,
  name: string,
  minimum = 1,
): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) {
    throw new DnsFormatError(`${name} is outside the supported bounds`);
  }
  return result;
}

function boundedLimits(options: DnsParserLimits = {}): BoundedDnsLimits {
  return {
    maxPacketBytes: checkedLimit(options.maxPacketBytes, DNS_MAX_PACKET_BYTES, DNS_MAX_PACKET_BYTES, "Maximum packet size"),
    maxRecords: checkedLimit(options.maxRecords, DNS_MAX_RECORDS, DNS_MAX_RECORDS, "Maximum record count"),
    maxNameBytes: checkedLimit(options.maxNameBytes, DNS_MAX_NAME_BYTES, DNS_MAX_NAME_BYTES, "Maximum name size"),
    maxPointerHops: checkedLimit(options.maxPointerHops, DNS_MAX_POINTER_HOPS, DNS_MAX_POINTER_HOPS, "Maximum compression pointer hops"),
    maxRdataBytes: checkedLimit(options.maxRdataBytes, DNS_MAX_RDATA_BYTES, DNS_MAX_RDATA_BYTES, "Maximum RDATA size", 0),
    maxTxtBytes: checkedLimit(options.maxTxtBytes, DNS_MAX_TXT_BYTES, DNS_MAX_TXT_BYTES, "Maximum TXT size", 0),
    maxTxtStrings: checkedLimit(options.maxTxtStrings, DNS_MAX_TXT_STRINGS, DNS_MAX_TXT_STRINGS, "Maximum TXT string count"),
  };
}

function normalizeNameParts(value: string): string[] {
  if (typeof value !== "string") throw new DnsFormatError("DNS name must be a string");
  const trimmed = value.trim();
  if (trimmed === ".") return [];
  if (!trimmed || trimmed.startsWith(".") || trimmed.includes("..")) {
    throw new DnsFormatError("DNS name is empty or malformed");
  }
  const withoutRoot = trimmed.endsWith(".") ? trimmed.slice(0, -1) : trimmed;
  const labels = withoutRoot.split(".");
  if (!labels.length || labels.some((label) => !label)) {
    throw new DnsFormatError("DNS name contains an empty label");
  }
  for (const label of labels) {
    const labelBytes = textEncoder.encode(label);
    if (labelBytes.length > DNS_MAX_LABEL_BYTES) {
      throw new DnsFormatError("DNS name label is too long");
    }
    for (const character of label) {
      const codePoint = character.codePointAt(0) ?? 0;
      if (codePoint <= 0x20 || codePoint === 0x7f || codePoint === 0xfffd) {
        throw new DnsFormatError("DNS name contains a control character");
      }
    }
  }
  return labels;
}

/** Returns a lower-case, absolute DNS name. The root name is represented as ".". */
export function normalizeDnsName(value: string): string {
  const labels = normalizeNameParts(value);
  if (!labels.length) return ".";
  const encodedLength = labels.reduce((total, label) => total + textEncoder.encode(label).length + 1, 1);
  if (encodedLength > DNS_MAX_NAME_BYTES) throw new DnsFormatError("DNS name is too long");
  return `${labels.map((label) => label.toLowerCase()).join(".")}.`;
}

/** Encodes an absolute DNS name without compression. */
export function encodeDnsName(value: string): Uint8Array {
  const labels = normalizeNameParts(value);
  const encodedLength = labels.reduce((total, label) => total + textEncoder.encode(label).length + 1, 1);
  if (encodedLength > DNS_MAX_NAME_BYTES) throw new DnsFormatError("DNS name is too long");
  const output = new Uint8Array(encodedLength);
  let offset = 0;
  for (const label of labels) {
    const encoded = textEncoder.encode(label);
    output[offset] = encoded.length;
    offset += 1;
    output.set(encoded, offset);
    offset += encoded.length;
  }
  output[offset] = 0;
  return output;
}

function recordTypeCode(type: DnsRecordType): DnsRecordTypeCode {
  switch (type) {
    case "MX":
      return DNS_RECORD_TYPES.MX;
    case "SRV":
      return DNS_RECORD_TYPES.SRV;
    case "TXT":
      return DNS_RECORD_TYPES.TXT;
    default:
      throw new DnsFormatError("Unsupported DNS record type");
  }
}

function randomUint16(): number {
  const bytes = new Uint8Array(2);
  crypto.getRandomValues(bytes);
  return (bytes[0] << 8) | bytes[1];
}

function checkedTransactionId(value: number): number {
  if (!isSafeIntegerInRange(value, 0xffff)) throw new DnsFormatError("DNS transaction ID must be a 16-bit integer");
  return value;
}

/** Creates a DNS wire query and retains the metadata needed to validate its response. */
export function createDnsQuery(name: string, type: DnsRecordType, options: DnsQueryOptions = {}): DnsQuery {
  const normalizedName = normalizeDnsName(name);
  const typeCode = recordTypeCode(type);
  const id = checkedTransactionId(options.id ?? randomUint16());
  const qname = encodeDnsName(normalizedName);
  const packet = new Uint8Array(DNS_HEADER_BYTES + qname.length + 4);
  packet[0] = id >>> 8;
  packet[1] = id & 0xff;
  const flags = options.recursionDesired === false ? 0 : 0x0100;
  packet[2] = flags >>> 8;
  packet[3] = flags & 0xff;
  packet[4] = 0;
  packet[5] = 1;
  packet.set(qname, DNS_HEADER_BYTES);
  const questionOffset = DNS_HEADER_BYTES + qname.length;
  packet[questionOffset] = typeCode >>> 8;
  packet[questionOffset + 1] = typeCode & 0xff;
  packet[questionOffset + 2] = 0;
  packet[questionOffset + 3] = DNS_CLASS_IN;
  const question: DnsQuestion = {
    name: normalizedName,
    type,
    typeCode,
    classCode: DNS_CLASS_IN,
  };
  return { id, name: normalizedName, type, question, packet };
}

/** Alias emphasizing that the returned value is the complete query, not only its bytes. */
export function buildDnsQuery(name: string, type: DnsRecordType, options: DnsQueryOptions = {}): DnsQuery {
  return createDnsQuery(name, type, options);
}

/** Returns only the wire bytes for callers that maintain their own query metadata. */
export function encodeDnsQuery(name: string, type: DnsRecordType, options: DnsQueryOptions = {}): Uint8Array {
  return createDnsQuery(name, type, options).packet;
}

function validatedDohEndpoint(endpoint: string | URL): URL {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new DnsFormatError("DoH endpoint is not a valid URL");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new DnsFormatError("DoH endpoint must be an HTTPS URL without credentials or a fragment");
  }
  return url;
}

/** Builds a fetch Request using the binary RFC 8484 DoH representation. */
export function buildDohRequest(query: DnsQuery, endpoint: string | URL = DEFAULT_DOH_ENDPOINT): Request {
  const url = validatedDohEndpoint(endpoint);
  const body = query.packet.slice();
  return new Request(url, {
    method: "POST",
    headers: {
      Accept: "application/dns-message",
      "Cache-Control": "no-store",
      "Content-Type": "application/dns-message",
    },
    body,
    cache: "no-store",
    // Workers supports "manual" for edge requests; the orchestrator must reject redirects.
    redirect: "manual",
  });
}

/** Alias for callers that name the operation after the resulting fetch request. */
export function createDohRequest(query: DnsQuery, endpoint: string | URL = DEFAULT_DOH_ENDPOINT): Request {
  return buildDohRequest(query, endpoint);
}

function asPacket(value: Uint8Array | ArrayBuffer, maxPacketBytes: number): Uint8Array {
  if (value.byteLength > maxPacketBytes) throw new DnsFormatError("DNS response exceeds the configured packet bound");
  if (value instanceof Uint8Array) return value;
  return new Uint8Array(value);
}

class PacketReader {
  readonly bytes: Uint8Array;
  offset = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  ensure(length: number, context: string): void {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.bytes.length) {
      throw new DnsFormatError(`DNS packet ends inside ${context}`);
    }
  }

  readUint8(context: string): number {
    this.ensure(1, context);
    const value = this.bytes[this.offset];
    this.offset += 1;
    return value;
  }

  readUint16(context: string): number {
    this.ensure(2, context);
    const value = (this.bytes[this.offset] << 8) | this.bytes[this.offset + 1];
    this.offset += 2;
    return value;
  }

  readUint32(context: string): number {
    this.ensure(4, context);
    const value = (this.bytes[this.offset] * 0x1000000) +
      (this.bytes[this.offset + 1] << 16) +
      (this.bytes[this.offset + 2] << 8) +
      this.bytes[this.offset + 3];
    this.offset += 4;
    return value;
  }

  readUint16At(offset: number, context: string): number {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset + 2 > this.bytes.length) {
      throw new DnsFormatError(`DNS packet ends inside ${context}`);
    }
    return (this.bytes[offset] << 8) | this.bytes[offset + 1];
  }

  copyRange(start: number, end: number, context: string): Uint8Array {
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > this.bytes.length) {
      throw new DnsFormatError(`DNS packet contains invalid ${context}`);
    }
    return this.bytes.slice(start, end);
  }

  readNameAt(start: number, limits: BoundedDnsLimits): { name: string; nextOffset: number } {
    if (!Number.isSafeInteger(start) || start < DNS_HEADER_BYTES || start >= this.bytes.length) {
      throw new DnsFormatError("DNS name starts outside the packet");
    }
    const labels: string[] = [];
    const visitedPointers = new Set<number>();
    let cursor = start;
    let nextOffset = start;
    let jumped = false;
    let pointerHops = 0;
    let expandedBytes = 0;

    while (true) {
      if (cursor >= this.bytes.length) throw new DnsFormatError("DNS name is truncated");
      const lengthOrPointer = this.bytes[cursor];
      if (lengthOrPointer === 0) {
        expandedBytes += 1;
        if (expandedBytes > limits.maxNameBytes) throw new DnsFormatError("DNS name exceeds the configured bound");
        if (!jumped) nextOffset = cursor + 1;
        const name = labels.length ? `${labels.join(".").toLowerCase()}.` : ".";
        return { name, nextOffset };
      }

      const tag = lengthOrPointer & 0xc0;
      if (tag === 0xc0) {
        if (cursor + 1 >= this.bytes.length) throw new DnsFormatError("DNS compression pointer is truncated");
        const pointer = ((lengthOrPointer & 0x3f) << 8) | this.bytes[cursor + 1];
        if (pointer < DNS_HEADER_BYTES || pointer >= this.bytes.length || pointer >= cursor) {
          throw new DnsFormatError("DNS compression pointer must refer backwards inside the packet");
        }
        if (visitedPointers.has(pointer)) throw new DnsFormatError("DNS compression pointer loop detected");
        visitedPointers.add(pointer);
        pointerHops += 1;
        if (pointerHops > limits.maxPointerHops) throw new DnsFormatError("DNS compression pointer chain is too long");
        if (!jumped) {
          nextOffset = cursor + 2;
          jumped = true;
        }
        cursor = pointer;
        continue;
      }
      if (tag !== 0) throw new DnsFormatError("DNS name contains a reserved label marker");

      const labelLength = lengthOrPointer;
      if (labelLength > DNS_MAX_LABEL_BYTES) throw new DnsFormatError("DNS name label is too long");
      if (cursor + 1 + labelLength > this.bytes.length) throw new DnsFormatError("DNS name label is truncated");
      const labelBytes = this.bytes.slice(cursor + 1, cursor + 1 + labelLength);
      let label: string;
      try {
        label = textDecoder.decode(labelBytes);
      } catch {
        throw new DnsFormatError("DNS name label is not valid UTF-8");
      }
      if (!label || label.includes(".") || Array.from(label).some((character) => {
        const codePoint = character.codePointAt(0) ?? 0;
        return codePoint <= 0x20 || codePoint === 0x7f;
      })) {
        throw new DnsFormatError("DNS name label contains an invalid character");
      }
      labels.push(label);
      expandedBytes += 1 + labelLength;
      if (expandedBytes + 1 > limits.maxNameBytes) throw new DnsFormatError("DNS name exceeds the configured bound");
      cursor += 1 + labelLength;
    }
  }

  readName(limits: BoundedDnsLimits): string {
    const decoded = this.readNameAt(this.offset, limits);
    this.offset = decoded.nextOffset;
    return decoded.name;
  }
}

function typeFromCode(code: number): DnsRecordType | null {
  if (code === DNS_RECORD_TYPES.MX) return "MX";
  if (code === DNS_RECORD_TYPES.SRV) return "SRV";
  if (code === DNS_RECORD_TYPES.TXT) return "TXT";
  return null;
}

function parseRecord(
  reader: PacketReader,
  section: DnsRecordSection,
  limits: BoundedDnsLimits,
): DnsRecord {
  const name = reader.readName(limits);
  const typeCode = reader.readUint16("resource record type");
  const classCode = reader.readUint16("resource record class");
  const ttl = reader.readUint32("resource record TTL");
  const rdataLength = reader.readUint16("resource record length");
  if (rdataLength > limits.maxRdataBytes) throw new DnsFormatError("Resource record RDATA exceeds the configured bound");
  reader.ensure(rdataLength, "resource record data");
  const rdataStart = reader.offset;
  const rdataEnd = rdataStart + rdataLength;
  const type = typeFromCode(typeCode);
  const base = { name, classCode, ttl, typeCode, rdataLength, section };

  if (type === "MX") {
    if (rdataLength < 3) throw new DnsFormatError("MX RDATA is too short");
    const preference = reader.readUint16At(rdataStart, "MX preference");
    const exchange = reader.readNameAt(rdataStart + 2, limits);
    if (exchange.nextOffset !== rdataEnd) throw new DnsFormatError("MX RDATA has trailing bytes");
    reader.offset = rdataEnd;
    return { ...base, type, typeCode: DNS_RECORD_TYPES.MX, preference, exchange: exchange.name };
  }

  if (type === "SRV") {
    if (rdataLength < 7) throw new DnsFormatError("SRV RDATA is too short");
    const priority = reader.readUint16At(rdataStart, "SRV priority");
    const weight = reader.readUint16At(rdataStart + 2, "SRV weight");
    const port = reader.readUint16At(rdataStart + 4, "SRV port");
    const target = reader.readNameAt(rdataStart + 6, limits);
    if (target.nextOffset !== rdataEnd) throw new DnsFormatError("SRV RDATA has trailing bytes");
    reader.offset = rdataEnd;
    return { ...base, type, typeCode: DNS_RECORD_TYPES.SRV, priority, weight, port, target: target.name };
  }

  if (type === "TXT") {
    const strings: string[] = [];
    const rawStrings: Uint8Array[] = [];
    let totalTextBytes = 0;
    while (reader.offset < rdataEnd) {
      if (strings.length >= limits.maxTxtStrings) throw new DnsFormatError("TXT record contains too many strings");
      const stringLength = reader.readUint8("TXT string length");
      if (reader.offset + stringLength > rdataEnd) throw new DnsFormatError("TXT string is truncated");
      totalTextBytes += stringLength;
      if (totalTextBytes > limits.maxTxtBytes) throw new DnsFormatError("TXT record exceeds the configured bound");
      const raw = reader.copyRange(reader.offset, reader.offset + stringLength, "TXT string");
      reader.offset += stringLength;
      rawStrings.push(raw);
      strings.push(lenientTextDecoder.decode(raw));
    }
    return {
      ...base,
      type,
      typeCode: DNS_RECORD_TYPES.TXT,
      strings,
      rawStrings,
      text: strings.join(""),
    };
  }

  const rdata = reader.copyRange(rdataStart, rdataEnd, "resource record data");
  reader.offset = rdataEnd;
  return { ...base, type: "UNKNOWN", typeCode, rdata };
}

function parseQuestion(reader: PacketReader, limits: BoundedDnsLimits): DnsQuestion {
  const name = reader.readName(limits);
  const typeCode = reader.readUint16("question type");
  const classCode = reader.readUint16("question class");
  const type = typeFromCode(typeCode);
  if (!type || classCode !== DNS_CLASS_IN) throw new DnsFormatError("DNS response question is not an IN MX, SRV, or TXT question");
  return { name, type, typeCode: recordTypeCode(type), classCode: DNS_CLASS_IN };
}

function expectedQuestion(query: DnsQuery): DnsQuestion {
  const name = normalizeDnsName(query.question.name);
  const typeCode = recordTypeCode(query.question.type);
  const queryName = normalizeDnsName(query.name);
  if (
    queryName !== name
    || query.type !== query.question.type
    || query.question.classCode !== DNS_CLASS_IN
    || query.question.typeCode !== typeCode
  ) {
    throw new DnsFormatError("DNS query metadata is inconsistent");
  }
  return { name, type: query.question.type, typeCode, classCode: DNS_CLASS_IN };
}

function parseFlags(raw: number): DnsResponseFlags {
  return {
    raw,
    qr: (raw & 0x8000) !== 0,
    opcode: (raw >>> 11) & 0x0f,
    authoritative: (raw & 0x0400) !== 0,
    truncated: (raw & 0x0200) !== 0,
    recursionDesired: (raw & 0x0100) !== 0,
    recursionAvailable: (raw & 0x0080) !== 0,
    authenticated: (raw & 0x0020) !== 0,
    checkingDisabled: (raw & 0x0010) !== 0,
    rcode: raw & 0x000f,
  };
}

/** Parses and validates a binary DNS response against the query that produced it. */
export function parseDnsResponse(
  packet: Uint8Array | ArrayBuffer,
  query: DnsQuery,
  options: DnsParserLimits = {},
): DnsResponse {
  const limits = boundedLimits(options);
  const bytes = asPacket(packet, limits.maxPacketBytes);
  if (bytes.length < DNS_HEADER_BYTES) throw new DnsFormatError("DNS response is shorter than its header");
  const reader = new PacketReader(bytes);
  const id = reader.readUint16("DNS response ID");
  const flags = parseFlags(reader.readUint16("DNS response flags"));
  const questionCount = reader.readUint16("question count");
  const answerCount = reader.readUint16("answer count");
  const authorityCount = reader.readUint16("authority count");
  const additionalCount = reader.readUint16("additional count");
  if (id !== checkedTransactionId(query.id)) throw new DnsFormatError("DNS response transaction ID does not match the query");
  if (!flags.qr) throw new DnsFormatError("DNS packet is not a response");
  if (flags.opcode !== 0) throw new DnsFormatError("Only standard DNS responses are supported");
  if ((flags.raw & 0x0040) !== 0) throw new DnsFormatError("DNS response has a reserved header bit set");
  if (questionCount !== 1) throw new DnsFormatError("DNS response must contain exactly one question");
  const totalRecords = answerCount + authorityCount + additionalCount;
  if (totalRecords > limits.maxRecords) throw new DnsFormatError("DNS response contains too many records");

  const question = parseQuestion(reader, limits);
  const expected = expectedQuestion(query);
  if (question.name !== expected.name || question.typeCode !== expected.typeCode || question.classCode !== expected.classCode) {
    throw new DnsFormatError("DNS response question does not match the query");
  }

  const readSection = (count: number, section: DnsRecordSection): DnsRecord[] => {
    const records: DnsRecord[] = [];
    for (let index = 0; index < count; index += 1) records.push(parseRecord(reader, section, limits));
    return records;
  };
  const answers = readSection(answerCount, "answer");
  const authorities = readSection(authorityCount, "authority");
  const additionals = readSection(additionalCount, "additional");
  if (reader.offset !== bytes.length) throw new DnsFormatError("DNS response contains trailing bytes");
  return { id, flags, rcode: flags.rcode, question, answers, authorities, additionals };
}

/** Alias naming the wire-level operation explicitly. */
export function parseDnsWireResponse(
  packet: Uint8Array | ArrayBuffer,
  query: DnsQuery,
  options: DnsParserLimits = {},
): DnsResponse {
  return parseDnsResponse(packet, query, options);
}

export function isMxRecord(record: DnsRecord): record is MxRecord {
  return record.type === "MX";
}

export function isSrvRecord(record: DnsRecord): record is SrvRecord {
  return record.type === "SRV";
}

export function isTxtRecord(record: DnsRecord): record is TxtRecord {
  return record.type === "TXT";
}

/** Returns records of the requested supported type from a response section. */
export function recordsOfType<T extends DnsRecordType>(
  records: DnsRecord[],
  type: T,
): Array<T extends "MX" ? MxRecord : T extends "SRV" ? SrvRecord : TxtRecord> {
  return records.filter((record): record is Extract<DnsRecord, { type: T }> => record.type === type) as Array<T extends "MX" ? MxRecord : T extends "SRV" ? SrvRecord : TxtRecord>;
}

export type SrvRandom = () => number;

function secureRandomUnit(): number {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return value[0] / 0x1_0000_0000;
}

function checkedRandomUnit(random: SrvRandom): number {
  const value = random();
  if (!Number.isFinite(value) || value < 0 || value >= 1) {
    throw new DnsFormatError("SRV selection random source must return a number in [0, 1)");
  }
  return value;
}

/**
 * Selects one RFC 2782 SRV record from the lowest-priority group.
 * Pass a deterministic random source in tests; production defaults to Web Crypto.
 */
export function selectSrvRecord(records: readonly SrvRecord[], random: SrvRandom = secureRandomUnit): SrvRecord | null {
  if (!records.length) return null;
  const priority = Math.min(...records.map((record) => record.priority));
  const eligible = records.filter((record) => record.priority === priority);
  const totalWeight = eligible.reduce((total, record) => total + record.weight, 0);
  const randomValue = checkedRandomUnit(random);
  if (totalWeight === 0) return eligible[Math.min(eligible.length - 1, Math.floor(randomValue * eligible.length))];
  const selected = randomValue * totalWeight;
  let cumulative = 0;
  for (const record of eligible) {
    cumulative += record.weight;
    if (selected < cumulative) return record;
  }
  return eligible[eligible.length - 1];
}

export function selectSrvTarget(records: readonly SrvRecord[], random: SrvRandom = secureRandomUnit): string | null {
  return selectSrvRecord(records, random)?.target ?? null;
}
