import PostalMime, { type Attachment, type Email } from "postal-mime";
import {
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_COUNT,
  MAX_COMPOSED_MESSAGE_BYTES,
  MAX_MESSAGE_BYTES,
  type AttachmentPart,
  type MessageMetadata,
  type ParsedMessage,
} from "./types";
import { containsAsciiControl } from "./security";

export interface ComposeAttachment {
  filename: string;
  mimeType: string;
  contentBase64: string;
  contentId?: string;
}

export interface ComposeInput {
  from: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  replyTo?: string[];
  subject: string;
  text?: string;
  html?: string;
  attachments?: ComposeAttachment[];
  messageId?: string;
  date?: Date;
}

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function encodeBase64(bytes: Uint8Array): string {
  return base64Encode(bytes);
}

export function decodeBase64(value: string): Uint8Array {
  const compact = value.replace(/\s+/gu, "");
  if (!compact || compact.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(compact)) {
    throw new Error("Invalid base64 content");
  }
  const binary = atob(compact);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function normalizeCrlf(value: string): string {
  return value.replace(/\r\n/gu, "\n").replace(/\r/gu, "\n").replace(/\n/gu, "\r\n");
}

function encodeHeader(value: string): string {
  if (containsAsciiControl(value)) throw new Error("Header contains an invalid control character");
  if (/^[\x20-\x7e]*$/u.test(value)) return value;
  return `=?UTF-8?B?${base64Encode(new TextEncoder().encode(value))}?=`;
}

function parseMailbox(value: string): { name: string; address: string } {
  const input = value.trim();
  if (containsAsciiControl(input)) throw new Error("Address contains an injection character");
  const display = input.match(/^(.+?)\s*<([^<>\s]+)>$/u);
  const name = display ? display[1].trim() : "";
  const address = (display ? display[2] : input).trim();
  if (
    address.length > 320 ||
    !/^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/iu.test(address)
  ) {
    throw new Error("Invalid email address");
  }
  if (name && (containsAsciiControl(name) || /[<>]/u.test(name))) throw new Error("Address display name is invalid");
  return { name, address };
}

export function validateAddress(value: string): string {
  const parsed = parseMailbox(value);
  return parsed.address;
}

function formatMailbox(value: string): string {
  const parsed = parseMailbox(value);
  if (!parsed.name) return parsed.address;
  const encodedName = `=?UTF-8?B?${base64Encode(new TextEncoder().encode(parsed.name))}?=`;
  return `${encodedName} <${parsed.address}>`;
}

function normalizeFilename(value: string): string {
  const filename = value.trim();
  if (
    !filename ||
    filename.length > 255 ||
    containsAsciiControl(filename) ||
    filename.includes("/") ||
    filename.includes("\\")
  ) {
    throw new Error("Attachment filename is invalid");
  }
  return filename.replace(/"/gu, "'");
}

function wrapBase64(value: string): string {
  const lines: string[] = [];
  for (let index = 0; index < value.length; index += 76) lines.push(value.slice(index, index + 76));
  return lines.join("\r\n");
}

function bodyPart(contentType: string, content: string, boundary?: string): string {
  const header = boundary
    ? `Content-Type: ${contentType}; boundary="${boundary}"`
    : `Content-Type: ${contentType}; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit`;
  return `${header}\r\n\r\n${content}`;
}

function createBoundary(prefix: string): string {
  return `----mailboxer-${prefix}-${crypto.randomUUID()}`;
}

function composeBody(input: ComposeInput): string {
  const text = input.text === undefined ? null : normalizeCrlf(input.text);
  const html = input.html === undefined ? null : normalizeCrlf(input.html);
  if (text === null && html === null) throw new Error("At least one of text or html is required");
  const attachments = input.attachments ?? [];
  if (attachments.length > MAX_ATTACHMENT_COUNT) throw new Error("Too many attachments");

  let body: string;
  if (text !== null && html !== null) {
    const boundary = createBoundary("alternative");
    body = bodyPart(
      "multipart/alternative",
      `--${boundary}\r\n${bodyPart("text/plain", text)}\r\n--${boundary}\r\n${bodyPart("text/html", html)}\r\n--${boundary}--`,
      boundary,
    );
  } else if (text !== null) {
    body = bodyPart("text/plain", text);
  } else {
    body = bodyPart("text/html", html ?? "");
  }

  if (!attachments.length) return body;
  const mixedBoundary = createBoundary("mixed");
  const parts = [`--${mixedBoundary}\r\n${body}`];
  for (const attachment of attachments) {
    const filename = normalizeFilename(attachment.filename);
    const bytes = decodeBase64(attachment.contentBase64);
    if (bytes.byteLength > MAX_ATTACHMENT_BYTES) {
      throw new Error(`Attachment ${filename} exceeds ${MAX_ATTACHMENT_BYTES} bytes`);
    }
    if (!/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/u.test(attachment.mimeType)) {
      throw new Error(`Attachment ${filename} has an invalid MIME type`);
    }
    const headers = [
      `Content-Type: ${attachment.mimeType}; name="${filename}"`,
      "Content-Transfer-Encoding: base64",
      `Content-Disposition: attachment; filename="${filename}"`,
    ];
    if (attachment.contentId) {
      if (containsAsciiControl(attachment.contentId) || /[<>]/u.test(attachment.contentId)) throw new Error("Attachment content ID is invalid");
      headers.push(`Content-ID: <${attachment.contentId}>`);
    }
    parts.push(`--${mixedBoundary}\r\n${headers.join("\r\n")}\r\n\r\n${wrapBase64(attachment.contentBase64.replace(/\s+/gu, ""))}`);
  }
  parts.push(`--${mixedBoundary}--`);
  return bodyPart("multipart/mixed", parts.join("\r\n"), mixedBoundary);
}

export function composeRfc822(input: ComposeInput): { raw: Uint8Array; messageId: string } {
  const from = formatMailbox(input.from);
  const to = input.to.map(formatMailbox);
  if (!to.length) throw new Error("At least one recipient is required");
  const cc = (input.cc ?? []).map(formatMailbox);
  const bcc = (input.bcc ?? []).map(formatMailbox);
  const replyTo = (input.replyTo ?? []).map(formatMailbox);
  if (input.subject.length > 998 || containsAsciiControl(input.subject)) {
    throw new Error("Subject is invalid or too long");
  }
  const domain = parseMailbox(input.from).address.split("@")[1];
  const messageId = input.messageId ?? `<${crypto.randomUUID()}@${domain}>`;
  if (!/^<[^<>]+>$/u.test(messageId) || containsAsciiControl(messageId)) throw new Error("Message-ID is invalid");
  const headers = [
    `Date: ${(input.date ?? new Date()).toUTCString()}`,
    `Message-ID: ${messageId}`,
    `From: ${from}`,
    `To: ${to.join(", ")}`,
    ...(cc.length ? [`Cc: ${cc.join(", ")}`] : []),
    ...(replyTo.length ? [`Reply-To: ${replyTo.join(", ")}`] : []),
    `Subject: ${encodeHeader(input.subject)}`,
    "MIME-Version: 1.0",
  ];
  const body = composeBody(input);
  const rawText = `${headers.join("\r\n")}\r\n\r\n${body}\r\n`;
  const raw = new TextEncoder().encode(rawText);
  if (raw.byteLength > MAX_COMPOSED_MESSAGE_BYTES) {
    throw new Error(`Composed message exceeds ${MAX_COMPOSED_MESSAGE_BYTES} bytes`);
  }
  // Bcc is deliberately used by SMTP as envelope recipients and is not emitted in RFC822.
  void bcc;
  return { raw, messageId };
}

export function smtpRecipients(input: ComposeInput): string[] {
  return [...input.to, ...(input.cc ?? []), ...(input.bcc ?? [])].map(validateAddress);
}

export function dotStuffForSmtp(raw: Uint8Array): Uint8Array {
  const text = new TextDecoder().decode(raw).replace(/\r\n/gu, "\n").replace(/\r/gu, "\n");
  const normalized = text
    .split("\n")
    .map((line) => (line.startsWith(".") ? `.${line}` : line))
    .join("\r\n");
  const withTerminator = normalized.endsWith("\r\n") ? normalized : `${normalized}\r\n`;
  return new TextEncoder().encode(withTerminator);
}

function contentToBase64(content: Attachment["content"]): string {
  if (typeof content === "string") return content.replace(/\s+/gu, "");
  if (content instanceof Uint8Array) return base64Encode(content);
  if (content instanceof ArrayBuffer) return base64Encode(new Uint8Array(content));
  return "";
}

export async function parseRfc822(
  raw: Uint8Array,
  metadata: MessageMetadata,
  attachmentParts: AttachmentPart[],
): Promise<ParsedMessage> {
  if (raw.byteLength > MAX_MESSAGE_BYTES) throw new Error(`Message exceeds ${MAX_MESSAGE_BYTES} bytes`);
  const email: Email = await PostalMime.parse(raw, {
    attachmentEncoding: "base64",
    maxHeadersSize: 128 * 1024,
    maxNestingDepth: 20,
    maxRfc822NestingDepth: 5,
  });
  const attachments = email.attachments.slice(0, MAX_ATTACHMENT_COUNT).map((attachment, index) => {
    const contentBase64 = contentToBase64(attachment.content);
    const size = (() => {
      try {
        return decodeBase64(contentBase64).byteLength;
      } catch {
        throw new Error("Parsed attachment did not have valid base64 content");
      }
    })();
    if (size > MAX_ATTACHMENT_BYTES) throw new Error("Parsed attachment exceeds the safety limit");
    const part = attachmentParts[index];
    return {
      part: part?.part ?? null,
      filename: attachment.filename,
      mimeType: attachment.mimeType,
      disposition: attachment.disposition,
      contentBase64,
      size,
    };
  });
  return {
    metadata,
    headers: email.headers.slice(0, 200).map((header) => ({ key: header.key, value: header.value.slice(0, 8192) })),
    text: email.text ?? null,
    html: email.html ?? null,
    attachments,
  };
}

export function decodeContentTransfer(raw: Uint8Array, encoding: string): Uint8Array {
  const normalized = encoding.toLowerCase();
  if (normalized === "base64") return decodeBase64(new TextDecoder().decode(raw));
  if (normalized !== "quoted-printable") return raw;
  const bytes: number[] = [];
  for (let index = 0; index < raw.length; index += 1) {
    if (raw[index] !== 0x3d) {
      bytes.push(raw[index]);
      continue;
    }
    if (raw[index + 1] === 0x0d && raw[index + 2] === 0x0a) {
      index += 2;
      continue;
    }
    if (raw[index + 1] === 0x0a) {
      index += 1;
      continue;
    }
    const first = raw[index + 1];
    const second = raw[index + 2];
    const hex = String.fromCharCode(first ?? 0, second ?? 0);
    if (!/^[0-9a-f]{2}$/iu.test(hex)) throw new Error("Invalid quoted-printable content");
    bytes.push(Number.parseInt(hex, 16));
    index += 2;
  }
  return Uint8Array.from(bytes);
}
