import { containsAsciiControl } from "../security";

export type ImapValue = string | null | ImapValue[];

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
] as const;

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64Decode(value: string): Uint8Array {
  const normalized = value.replace(/,/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function encodeModifiedUtf7(value: string): string {
  let output = "";
  let unicode = "";

  const flushUnicode = (): void => {
    if (!unicode) return;
    const bytes = new Uint8Array(unicode.length * 2);
    for (let index = 0; index < unicode.length; index += 1) {
      const code = unicode.charCodeAt(index);
      bytes[index * 2] = (code >> 8) & 0xff;
      bytes[index * 2 + 1] = code & 0xff;
    }
    output += `&${base64Encode(bytes).replace(/=+$/g, "").replace(/\//g, ",")}-`;
    unicode = "";
  };

  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code >= 0x20 && code <= 0x7e) {
      flushUnicode();
      output += character === "&" ? "&-" : character;
    } else {
      unicode += character;
    }
  }
  flushUnicode();
  return output;
}

export function decodeModifiedUtf7(value: string): string {
  let output = "";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character !== "&") {
      output += character;
      continue;
    }
    const end = value.indexOf("-", index + 1);
    if (end < 0) throw new Error("Malformed modified UTF-7 mailbox name");
    const encoded = value.slice(index + 1, end);
    if (!encoded) {
      output += "&";
    } else {
      const bytes = base64Decode(encoded);
      if (bytes.length % 2 !== 0) throw new Error("Malformed modified UTF-7 mailbox name");
      for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 2) {
        output += String.fromCharCode((bytes[byteIndex] << 8) | bytes[byteIndex + 1]);
      }
    }
    index = end;
  }
  return output;
}

function quoteEncodedImapString(value: string): string {
  if (containsAsciiControl(value)) {
    throw new Error("IMAP string contains a control character");
  }
  const encoded = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return `"${encoded}"`;
}

export function quoteImapString(value: string): string {
  return quoteEncodedImapString(value);
}

export function quoteImapMailboxName(value: string): string {
  if (containsAsciiControl(value)) throw new Error("IMAP mailbox name contains a control character");
  return quoteEncodedImapString(encodeModifiedUtf7(value));
}

export function formatImapDate(value: string): string {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) throw new Error("Date must use YYYY-MM-DD");
  const [yearText, monthText, dayText] = value.split("-");
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    throw new Error("Invalid calendar date");
  }
  return `${day}-${MONTHS[month - 1]}-${year}`;
}

export function parseImapValues(input: string): ImapValue[] {
  let index = 0;

  const skipWhitespace = (): void => {
    while (/\s/u.test(input[index] ?? "")) index += 1;
  };

  const parseValue = (): ImapValue => {
    skipWhitespace();
    if (input[index] === "(") {
      index += 1;
      const values: ImapValue[] = [];
      while (true) {
        skipWhitespace();
        if (input[index] === ")") {
          index += 1;
          return values;
        }
        if (index >= input.length) throw new Error("Unterminated IMAP list");
        values.push(parseValue());
      }
    }
    if (input[index] === '"') {
      index += 1;
      let value = "";
      while (index < input.length) {
        const character = input[index];
        index += 1;
        if (character === '"') return value;
        if (character === "\\") {
          if (index >= input.length) throw new Error("Unterminated IMAP quoted string");
          value += input[index];
          index += 1;
        } else {
          value += character;
        }
      }
      throw new Error("Unterminated IMAP quoted string");
    }
    const start = index;
    while (index < input.length && !/[\s()]/u.test(input[index])) index += 1;
    if (start === index) throw new Error("Unexpected IMAP response token");
    const atom = input.slice(start, index);
    return atom.toUpperCase() === "NIL" ? null : atom;
  };

  const values: ImapValue[] = [];
  while (true) {
    skipWhitespace();
    if (index >= input.length) return values;
    values.push(parseValue());
  }
}

export function asString(value: ImapValue | undefined): string | null {
  return typeof value === "string" ? value : null;
}

export function asList(value: ImapValue | undefined): ImapValue[] {
  return Array.isArray(value) ? value : [];
}

export function formatUidSet(uids: number[]): string {
  const normalized = [...new Set(uids)].sort((left, right) => left - right);
  if (!normalized.length) throw new Error("At least one UID is required");
  if (normalized.some((uid) => !Number.isSafeInteger(uid) || uid < 1)) {
    throw new Error("UIDs must be positive integers");
  }
  return normalized.join(",");
}
