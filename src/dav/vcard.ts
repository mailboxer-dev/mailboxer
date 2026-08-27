import type {
  Contact,
  ContactAddress,
  ContactFields,
  ContactInput,
  ContactName,
  ContactValue,
} from "./types";

const MAX_VCARD_LINES = 50_000;

export class VcardParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VcardParseError";
  }
}

interface VcardProperty {
  name: string;
  params: Record<string, string[]>;
  rawValue: string;
  value: string;
}

function splitEscaped(value: string, separator: string): string[] {
  const result: string[] = [];
  let escaped = false;
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === separator) {
      result.push(value.slice(start, index));
      start = index + 1;
    }
  }
  result.push(value.slice(start));
  return result;
}

function findValueSeparator(line: string): number {
  let quote = false;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') {
      quote = !quote;
      continue;
    }
    if (!quote && character === ":") return index;
  }
  return -1;
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) return trimmed.slice(1, -1);
  return trimmed;
}

function unescapeValue(value: string): string {
  return value.replace(/\\([\\,;nN])/gu, (_match, escaped: string) => {
    if (escaped.toLowerCase() === "n") return "\n";
    return escaped;
  });
}

function parseProperty(line: string): VcardProperty {
  const separator = findValueSeparator(line);
  if (separator < 1) throw new VcardParseError("Invalid vCard property");
  const nameAndParameters = splitEscaped(line.slice(0, separator), ";");
  const rawName = nameAndParameters.shift()?.trim().toUpperCase() ?? "";
  if (!/^(?:[A-Z0-9-]+\.)*[A-Z0-9-]+$/u.test(rawName)) throw new VcardParseError("Invalid vCard property name");
  const params: Record<string, string[]> = {};
  for (const parameter of nameAndParameters) {
    const equals = parameter.indexOf("=");
    if (equals < 1) throw new VcardParseError("Invalid vCard parameter");
    const key = parameter.slice(0, equals).trim().toUpperCase();
    if (!/^[A-Z0-9-]+$/u.test(key)) throw new VcardParseError("Invalid vCard parameter name");
    params[key] = splitEscaped(parameter.slice(equals + 1), ",").map(unquote);
  }
  const rawValue = line.slice(separator + 1);
  return {
    name: rawName.slice(rawName.lastIndexOf(".") + 1),
    params,
    rawValue,
    value: unescapeValue(rawValue),
  };
}

function unfoldedLines(raw: string): string[] {
  const normalized = raw.replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
  const physical = normalized.split("\n");
  if (physical.at(-1) === "") physical.pop();
  const lines: string[] = [];
  for (const line of physical) {
    if (/^[ \t]/u.test(line)) {
      const previous = lines.at(-1);
      if (previous === undefined) throw new VcardParseError("vCard starts with a folded line");
      lines[lines.length - 1] = `${previous}${line.slice(1)}`;
    } else {
      lines.push(line);
    }
    if (lines.length > MAX_VCARD_LINES) throw new VcardParseError("vCard contains too many lines");
  }
  if (!lines.length) throw new VcardParseError("vCard is empty");
  return lines;
}

function parseVcard(raw: string): VcardProperty[] {
  const properties: VcardProperty[] = [];
  let began = false;
  let ended = false;
  let version: string | null = null;
  for (const line of unfoldedLines(raw)) {
    const property = parseProperty(line);
    if (property.name === "BEGIN") {
      if (began || property.value.toUpperCase() !== "VCARD") throw new VcardParseError("vCard must contain one VCARD");
      began = true;
    } else if (property.name === "END") {
      if (!began || ended || property.value.toUpperCase() !== "VCARD") throw new VcardParseError("Mismatched vCard boundary");
      ended = true;
    } else {
      if (!began || ended) throw new VcardParseError("vCard property is outside VCARD");
      if (property.name === "VERSION") {
        if (version !== null) throw new VcardParseError("vCard contains duplicate VERSION properties");
        version = property.value;
      }
      properties.push(property);
    }
  }
  if (!began || !ended || (version !== "3.0" && version !== "4.0")) throw new VcardParseError("vCard VERSION 3.0 or 4.0 is required");
  return properties;
}

function first(properties: VcardProperty[], name: string): VcardProperty | undefined {
  return properties.find((candidate) => candidate.name === name);
}

function all(properties: VcardProperty[], name: string): VcardProperty[] {
  return properties.filter((candidate) => candidate.name === name);
}

function preferred(params: Record<string, string[]>): boolean {
  return params.PREF?.some((value) => value === "1" || value.toLowerCase() === "true") === true ||
    params.TYPE?.some((value) => value.toUpperCase() === "PREF" || value.toUpperCase() === "PREFERRED") === true;
}

function types(params: Record<string, string[]>): string[] {
  return [...new Set((params.TYPE ?? []).map((value) => value.toUpperCase()).filter((value) => value !== "PREF" && value !== "PREFERRED"))];
}

function contactValue(candidate: VcardProperty): ContactValue {
  return { value: candidate.value, types: types(candidate.params), preferred: preferred(candidate.params) };
}

function contactAddress(candidate: VcardProperty): ContactAddress {
  const values = splitEscaped(candidate.rawValue, ";").map(unescapeValue);
  return {
    pobox: values[0] || null,
    extended: values[1] || null,
    street: values[2] || null,
    locality: values[3] || null,
    region: values[4] || null,
    postalCode: values[5] || null,
    country: values[6] || null,
    types: types(candidate.params),
    preferred: preferred(candidate.params),
  };
}

function ensureSafeRaw(raw: string, maxBytes: number): void {
  const bytes = new TextEncoder().encode(raw);
  if (bytes.byteLength > maxBytes) throw new VcardParseError("vCard resource is too large");
  if (containsInvalidControl(raw)) {
    throw new VcardParseError("vCard contains an invalid control character");
  }
}

function containsInvalidControl(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code === 0 || (code >= 1 && code <= 8) || code === 11 || code === 12 || (code >= 14 && code <= 31) || code === 127) return true;
  }
  return false;
}

export function parseContactResource(raw: string, href: string, etag: string | null, maxBytes: number): Contact {
  ensureSafeRaw(raw, maxBytes);
  const properties = parseVcard(raw);
  const nameProperty = first(properties, "N");
  const nameParts = nameProperty ? splitEscaped(nameProperty.rawValue, ";").map(unescapeValue) : [];
  const name: ContactName = {
    family: nameParts[0] || null,
    given: nameParts[1] || null,
    additional: nameParts[2] || null,
    prefix: nameParts[3] || null,
    suffix: nameParts[4] || null,
  };
  const organization = first(properties, "ORG");
  if (!first(properties, "FN")) throw new VcardParseError("vCard must contain an FN property");
  const fields: ContactFields = {
    uid: first(properties, "UID")?.value ?? null,
    formattedName: first(properties, "FN")?.value ?? null,
    name,
    organization: organization ? splitEscaped(organization.rawValue, ";").map(unescapeValue).filter(Boolean) : [],
    emails: all(properties, "EMAIL").map(contactValue),
    phones: all(properties, "TEL").map(contactValue),
    addresses: all(properties, "ADR").map(contactAddress),
    birthday: first(properties, "BDAY")?.value ?? null,
    note: first(properties, "NOTE")?.value ?? null,
    urls: all(properties, "URL").map((candidate) => candidate.value),
    categories: all(properties, "CATEGORIES").flatMap((candidate) => splitEscaped(candidate.rawValue, ",").map(unescapeValue).filter(Boolean)),
  };
  return { ...fields, href, etag, rawVcard: raw };
}

function safeValue(value: string, name: string): string {
  if (containsInvalidControl(value)) {
    throw new VcardParseError(`${name} contains an invalid control character`);
  }
  return value;
}

function safeSingleLine(value: string, name: string): string {
  safeValue(value, name);
  if (value.includes("\r") || value.includes("\n")) throw new VcardParseError(`${name} must be a single line`);
  return value;
}

function escapeValue(value: string): string {
  return safeValue(value, "vCard value")
    .replace(/\\/gu, "\\\\")
    .replace(/([,;])/gu, "\\$1")
    .replace(/\r?\n/gu, "\\n");
}

function safeType(value: string): string {
  if (!/^[A-Za-z0-9-]+$/u.test(value)) throw new VcardParseError("vCard type contains unsupported characters");
  return value.toUpperCase();
}

function typeParameters(value: ContactValue | ContactAddress): string {
  const values = value.types.map(safeType);
  if (value.preferred) values.push("PREF");
  return values.length ? `;TYPE=${values.join(",")}` : "";
}

function foldLine(line: string): string {
  const encoder = new TextEncoder();
  let result = "";
  let current = "";
  for (const character of line) {
    if (encoder.encode(`${current}${character}`).byteLength > 75 && current) {
      result += `${current}\r\n`;
      current = ` ${character}`;
    } else {
      current += character;
    }
  }
  return result + current;
}

function addLine(lines: string[], name: string, value: string): void {
  lines.push(foldLine(`${name}:${value}`));
}

export function serializeContact(input: ContactInput): string {
  const uid = safeValue(input.uid ?? crypto.randomUUID(), "UID");
  const contactName = input.name ?? {};
  const formattedName = input.formattedName ?? [contactName.given, contactName.family].filter(Boolean).join(" ");
  if (!formattedName) throw new VcardParseError("formattedName or a name is required");
  const lines = ["BEGIN:VCARD", "VERSION:3.0", "PRODID:-//mailboxer//EN"];
  addLine(lines, "UID", escapeValue(uid));
  addLine(lines, "FN", escapeValue(formattedName));
  addLine(lines, "N", [contactName.family, contactName.given, contactName.additional, contactName.prefix, contactName.suffix]
    .map((value) => escapeValue(value ?? "")).join(";"));
  if (input.organization?.length) addLine(lines, "ORG", input.organization.map(escapeValue).join(";"));
  for (const email of input.emails ?? []) addLine(lines, `EMAIL${typeParameters(email)}`, escapeValue(safeValue(email.value, "Email")));
  for (const phone of input.phones ?? []) addLine(lines, `TEL${typeParameters(phone)}`, escapeValue(safeValue(phone.value, "Telephone")));
  for (const address of input.addresses ?? []) {
    addLine(lines, `ADR${typeParameters(address)}`, [address.pobox, address.extended, address.street, address.locality, address.region, address.postalCode, address.country]
      .map((value) => escapeValue(value ?? "")).join(";"));
  }
  if (input.birthday !== undefined) addLine(lines, "BDAY", safeSingleLine(input.birthday, "Birthday"));
  if (input.note !== undefined) addLine(lines, "NOTE", escapeValue(input.note));
  for (const url of input.urls ?? []) addLine(lines, "URL", safeSingleLine(url, "URL"));
  if (input.categories?.length) addLine(lines, "CATEGORIES", input.categories.map(escapeValue).join(","));
  lines.push("END:VCARD");
  return `${lines.join("\r\n")}\r\n`;
}
