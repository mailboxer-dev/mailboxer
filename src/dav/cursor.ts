export class DavCursorError extends Error {
  constructor(message = "Invalid pagination cursor") {
    super(message);
    this.name = "DavCursorError";
  }
}

interface CursorPayload {
  v: 1;
  domain: string;
  fingerprint: string;
  afterHref: string;
}

function validDomain(domain: string): boolean {
  return /^(?:caldav|contacts|p\d+-caldav|p\d+-contacts)\.icloud\.com$/u.test(domain);
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

function base64UrlDecode(value: string): Uint8Array {
  try {
    const padded = value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - (value.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  } catch {
    throw new DavCursorError();
  }
}

async function sign(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(new TextEncoder().encode(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(signature));
}

async function verify(value: string, signature: string, secret: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      asArrayBuffer(new TextEncoder().encode(secret)),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "HMAC",
      key,
      asArrayBuffer(base64UrlDecode(signature)),
      new TextEncoder().encode(value),
    );
  } catch {
    return false;
  }
}

export async function cursorFingerprint(value: unknown): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(value)));
  return base64UrlEncode(new Uint8Array(digest));
}

export async function encodeDavCursor(
  domain: string,
  fingerprint: string,
  afterHref: string,
  secret: string,
): Promise<string> {
  if (!validDomain(domain)) throw new DavCursorError();
  const payload: CursorPayload = { v: 1, domain, fingerprint, afterHref };
  const encoded = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  return `${encoded}.${await sign(encoded, secret)}`;
}

export async function decodeDavCursor(
  value: string,
  domain: string,
  fingerprint: string,
  secret: string,
): Promise<string> {
  if (!validDomain(domain)) throw new DavCursorError();
  if (!/^[A-Za-z0-9_-]{20,4096}\.[A-Za-z0-9_-]{40,100}$/u.test(value)) throw new DavCursorError();
  const separator = value.lastIndexOf(".");
  const encoded = value.slice(0, separator);
  const signature = value.slice(separator + 1);
  if (!(await verify(encoded, signature, secret))) throw new DavCursorError();
  try {
    const parsed = JSON.parse(new TextDecoder().decode(base64UrlDecode(encoded))) as Partial<CursorPayload>;
    if (parsed.v !== 1 || parsed.domain !== domain || parsed.fingerprint !== fingerprint || typeof parsed.afterHref !== "string") {
      throw new DavCursorError();
    }
    return parsed.afterHref;
  } catch (error) {
    if (error instanceof DavCursorError) throw error;
    throw new DavCursorError();
  }
}
