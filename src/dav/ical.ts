import { isIsoDate, isIsoDateTime } from "./date";
import type { CalendarItem, CalendarItemFields, CalendarItemInput, CalendarComponentType } from "./types";

const MAX_ICAL_LINES = 50_000;

export class IcalendarParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IcalendarParseError";
  }
}

interface IcalProperty {
  name: string;
  params: Record<string, string[]>;
  rawValue: string;
  value: string;
}

interface IcalComponent {
  name: string;
  properties: IcalProperty[];
  components: IcalComponent[];
}

function splitOutside(value: string, separator: string): string[] {
  const result: string[] = [];
  let quote = false;
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
    if (character === '"') {
      quote = !quote;
      continue;
    }
    if (!quote && character === separator) {
      result.push(value.slice(start, index));
      start = index + 1;
    }
  }
  if (quote) throw new IcalendarParseError("Unterminated iCalendar parameter quote");
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

function unescapeText(value: string): string {
  return value.replace(/\\([\\,;nN])/gu, (_match, escaped: string) => {
    if (escaped.toLowerCase() === "n") return "\n";
    return escaped;
  });
}

function parseProperty(line: string): IcalProperty {
  const separator = findValueSeparator(line);
  if (separator < 1) throw new IcalendarParseError("Invalid iCalendar property");
  const nameAndParameters = splitOutside(line.slice(0, separator), ";");
  const rawName = nameAndParameters.shift()?.trim().toUpperCase() ?? "";
  if (!/^(?:[A-Z0-9-]+\.)*[A-Z0-9-]+$/u.test(rawName)) throw new IcalendarParseError("Invalid iCalendar property name");
  const propertyName = rawName.slice(rawName.lastIndexOf(".") + 1);
  const params: Record<string, string[]> = {};
  for (const parameter of nameAndParameters) {
    const equals = parameter.indexOf("=");
    if (equals < 1) throw new IcalendarParseError("Invalid iCalendar parameter");
    const key = parameter.slice(0, equals).trim().toUpperCase();
    if (!/^[A-Z0-9-]+$/u.test(key)) throw new IcalendarParseError("Invalid iCalendar parameter name");
    params[key] = splitOutside(parameter.slice(equals + 1), ",").map(unquote);
  }
  const rawValue = line.slice(separator + 1);
  return { name: propertyName, params, rawValue, value: unescapeText(rawValue) };
}

function unfoldedLines(raw: string): string[] {
  const normalized = raw.replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
  const physical = normalized.split("\n");
  if (physical.at(-1) === "") physical.pop();
  const lines: string[] = [];
  for (const line of physical) {
    if (/^[ \t]/u.test(line)) {
      const previous = lines.at(-1);
      if (previous === undefined) throw new IcalendarParseError("iCalendar starts with a folded line");
      lines[lines.length - 1] = `${previous}${line.slice(1)}`;
    } else {
      lines.push(line);
    }
    if (lines.length > MAX_ICAL_LINES) throw new IcalendarParseError("iCalendar contains too many lines");
  }
  if (!lines.length) throw new IcalendarParseError("iCalendar is empty");
  return lines;
}

function parseCalendar(raw: string): IcalComponent {
  const root: IcalComponent = { name: "ROOT", properties: [], components: [] };
  const stack: IcalComponent[] = [root];
  for (const line of unfoldedLines(raw)) {
    const property = parseProperty(line);
    if (property.name === "BEGIN") {
      const component: IcalComponent = { name: property.value.toUpperCase(), properties: [], components: [] };
      stack.at(-1)?.components.push(component);
      stack.push(component);
    } else if (property.name === "END") {
      const current = stack.pop();
      if (!current || current === root || current.name !== property.value.toUpperCase()) {
        throw new IcalendarParseError("Mismatched iCalendar component");
      }
    } else {
      if (stack.length === 1) throw new IcalendarParseError("iCalendar property is outside VCALENDAR");
      stack.at(-1)?.properties.push(property);
    }
  }
  if (stack.length !== 1) throw new IcalendarParseError("Unclosed iCalendar component");
  if (root.components.length !== 1 || root.components[0]?.name !== "VCALENDAR") {
    throw new IcalendarParseError("iCalendar must contain one VCALENDAR component");
  }
  return root.components[0];
}

function property(component: IcalComponent, name: string): IcalProperty | undefined {
  return component.properties.find((candidate) => candidate.name === name);
}

function propertyValue(component: IcalComponent, name: string): string | null {
  return property(component, name)?.value ?? null;
}

function dateValue(item: IcalComponent, name: string): { value: string | null; allDay: boolean } {
  const candidate = property(item, name);
  if (!candidate) return { value: null, allDay: false };
  const date = candidate.value.match(/^(\d{4})(\d{2})(\d{2})$/u);
  if (date) return { value: `${date[1]}-${date[2]}-${date[3]}`, allDay: true };
  const dateTime = candidate.value.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z?)$/u);
  if (dateTime) {
    return {
      value: `${dateTime[1]}-${dateTime[2]}-${dateTime[3]}T${dateTime[4]}:${dateTime[5]}:${dateTime[6]}${dateTime[7]}`,
      allDay: false,
    };
  }
  return { value: candidate.value, allDay: candidate.params.VALUE?.[0]?.toUpperCase() === "DATE" };
}

function numberValue(item: IcalComponent, name: string): number | null {
  const value = propertyValue(item, name);
  if (value === null || !/^\d+$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function listValue(item: IcalComponent, name: string): string[] {
  const candidate = property(item, name);
  if (!candidate) return [];
  return splitOutside(candidate.rawValue, ",").map(unescapeText).filter(Boolean);
}

function ensureSafeRaw(raw: string, maxBytes: number): void {
  const bytes = new TextEncoder().encode(raw);
  if (bytes.byteLength > maxBytes) throw new IcalendarParseError("iCalendar resource is too large");
  if (containsInvalidControl(raw)) {
    throw new IcalendarParseError("iCalendar contains an invalid control character");
  }
}

function containsInvalidControl(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code === 0 || (code >= 1 && code <= 8) || code === 11 || code === 12 || (code >= 14 && code <= 31) || code === 127) return true;
  }
  return false;
}

export function parseCalendarResource(raw: string, href: string, etag: string | null, maxBytes: number): CalendarItem {
  ensureSafeRaw(raw, maxBytes);
  const calendar = parseCalendar(raw);
  if (propertyValue(calendar, "VERSION") !== "2.0") throw new IcalendarParseError("iCalendar VERSION 2.0 is required");
  const item = calendar.components.find((candidate) => candidate.name === "VEVENT" || candidate.name === "VTODO");
  if (!item || calendar.components.filter((candidate) => candidate.name === "VEVENT" || candidate.name === "VTODO").length !== 1) {
    throw new IcalendarParseError("iCalendar must contain one VEVENT or VTODO");
  }
  const start = dateValue(item, "DTSTART");
  const end = dateValue(item, "DTEND");
  const due = dateValue(item, "DUE");
  const completed = dateValue(item, "COMPLETED");
  if (!propertyValue(item, "UID")) throw new IcalendarParseError("iCalendar resource must contain a UID");
  const fields: CalendarItemFields = {
    componentType: item.name as CalendarComponentType,
    uid: propertyValue(item, "UID"),
    summary: propertyValue(item, "SUMMARY"),
    description: propertyValue(item, "DESCRIPTION"),
    start: start.value,
    end: end.value,
    due: due.value,
    allDay: start.allDay || end.allDay || due.allDay,
    location: propertyValue(item, "LOCATION"),
    status: propertyValue(item, "STATUS"),
    priority: numberValue(item, "PRIORITY"),
    percentComplete: numberValue(item, "PERCENT-COMPLETE"),
    completed: completed.value,
    rrule: propertyValue(item, "RRULE"),
    categories: listValue(item, "CATEGORIES"),
    url: propertyValue(item, "URL"),
  };
  return { ...fields, href, etag, rawIcalendar: raw };
}

function safeValue(value: string, name: string): string {
  if (containsInvalidControl(value)) {
    throw new IcalendarParseError(`${name} contains an invalid control character`);
  }
  return value;
}

function safeSingleLine(value: string, name: string): string {
  safeValue(value, name);
  if (value.includes("\r") || value.includes("\n")) throw new IcalendarParseError(`${name} must be a single line`);
  return value;
}

function escapeText(value: string): string {
  return safeValue(value, "iCalendar text")
    .replace(/\\/gu, "\\\\")
    .replace(/([,;])/gu, "\\$1")
    .replace(/\r?\n/gu, "\\n");
}

function icalDate(value: string, allDay: boolean, name: string, allowDate = true): string {
  safeValue(value, name);
  const date = value.match(/^(\d{4})-(\d{2})-(\d{2})$/u);
  if (date || allDay) {
    if (!allowDate) throw new IcalendarParseError(`${name} must be an ISO date-time`);
    const candidate = date ? value : value.slice(0, 10);
    if (!isIsoDate(candidate)) throw new IcalendarParseError(`${name} must be an ISO date`);
    return `${candidate.slice(0, 4)}${candidate.slice(5, 7)}${candidate.slice(8, 10)}`;
  }
  const local = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?(Z|[+-]\d{2}:?\d{2})?$/u);
  if (!local || !isIsoDateTime(value)) throw new IcalendarParseError(`${name} must be an ISO date-time`);
  const timezone = local[7] ?? "";
  if (timezone && timezone !== "Z") {
    const parsed = new Date(value);
    if (!Number.isFinite(parsed.getTime())) throw new IcalendarParseError(`${name} must be an ISO date-time`);
    return parsed.toISOString().replace(/[-:]/gu, "").replace(/\.\d{3}/u, "");
  }
  return `${local[1]}${local[2]}${local[3]}T${local[4]}${local[5]}${local[6] ?? "00"}${timezone}`;
}

function utcStamp(now: Date): string {
  return now.toISOString().replace(/[-:]/gu, "").replace(/\.\d{3}/u, "");
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

function propertyLine(name: string, value: string): string {
  return foldLine(`${name}:${value}`);
}

function validateRrule(value: string): string {
  safeValue(value, "RRULE");
  if (!/^[A-Za-z0-9;=,:+./_-]+$/u.test(value)) throw new IcalendarParseError("RRULE contains unsupported characters");
  return value;
}

export function serializeCalendarItem(input: CalendarItemInput, now = new Date()): string {
  if (input.componentType !== "VEVENT" && input.componentType !== "VTODO") throw new IcalendarParseError("Unsupported calendar component type");
  const uid = safeValue(input.uid ?? crypto.randomUUID(), "UID");
  const lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//icloud-mail-mcp//EN", `BEGIN:${input.componentType}`];
  lines.push(propertyLine("UID", escapeText(uid)), propertyLine("DTSTAMP", utcStamp(now)));
  if (input.start !== undefined) {
    const allDay = input.allDay === true || isIsoDate(input.start);
    lines.push(propertyLine(allDay ? "DTSTART;VALUE=DATE" : "DTSTART", icalDate(input.start, allDay, "start")));
  }
  if (input.end !== undefined) {
    const allDay = input.allDay === true || isIsoDate(input.end);
    lines.push(propertyLine(allDay ? "DTEND;VALUE=DATE" : "DTEND", icalDate(input.end, allDay, "end")));
  }
  if (input.due !== undefined) {
    const allDay = input.allDay === true || isIsoDate(input.due);
    lines.push(propertyLine(allDay ? "DUE;VALUE=DATE" : "DUE", icalDate(input.due, allDay, "due")));
  }
  if (input.summary !== undefined) lines.push(propertyLine("SUMMARY", escapeText(input.summary)));
  if (input.description !== undefined) lines.push(propertyLine("DESCRIPTION", escapeText(input.description)));
  if (input.location !== undefined) lines.push(propertyLine("LOCATION", escapeText(input.location)));
  if (input.status !== undefined) lines.push(propertyLine("STATUS", escapeText(input.status)));
  if (input.priority !== undefined) {
    if (!Number.isInteger(input.priority) || input.priority < 0 || input.priority > 9) throw new IcalendarParseError("Priority must be between 0 and 9");
    lines.push(propertyLine("PRIORITY", String(input.priority)));
  }
  if (input.percentComplete !== undefined) {
    if (!Number.isInteger(input.percentComplete) || input.percentComplete < 0 || input.percentComplete > 100) throw new IcalendarParseError("Percent complete must be between 0 and 100");
    lines.push(propertyLine("PERCENT-COMPLETE", String(input.percentComplete)));
  }
  if (input.completed !== undefined) lines.push(propertyLine("COMPLETED", icalDate(input.completed, false, "completed", false)));
  if (input.rrule !== undefined) lines.push(propertyLine("RRULE", validateRrule(input.rrule)));
  if (input.categories?.length) lines.push(propertyLine("CATEGORIES", input.categories.map((value) => escapeText(value)).join(",")));
  if (input.url !== undefined) lines.push(propertyLine("URL", safeSingleLine(input.url, "URL")));
  lines.push(`END:${input.componentType}`, "END:VCALENDAR");
  return `${lines.join("\r\n")}\r\n`;
}
