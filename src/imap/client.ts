import { connect } from "cloudflare:sockets";
import {
  formatUidSet,
  quoteImapMailboxName,
  quoteImapString,
} from "./codec";
import { parseFetchMetadata, parseListLine, parseSearchResponse } from "./parsers";
import {
  MAX_ATTACHMENT_BYTES,
  MAX_MESSAGE_BYTES,
  type Mailbox,
  type MessageMetadata,
} from "../types";
import type { MailConfig } from "../types";
import { SocketConnection, withTimeout, type SocketLike } from "../network";
import { compileSearch, type SearchFilters } from "./search";

const IMAP_TIMEOUT_MS = 30_000;
const MAX_PROTOCOL_LITERAL_BYTES = MAX_MESSAGE_BYTES;

export class ImapProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImapProtocolError";
  }
}

export class MessageTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MessageTooLargeError";
  }
}

export interface ImapResponse {
  tag: string;
  status: "OK" | "NO" | "BAD" | "UNKNOWN";
  lines: string[];
  literals: Uint8Array[];
}

export type ImapConnector = (config: MailConfig) => Promise<SocketLike>;

async function defaultConnector(config: MailConfig): Promise<SocketLike> {
  const socket = connect(
    { hostname: config.imapHost, port: config.imapPort },
    { secureTransport: "on", allowHalfOpen: false },
  );
  if (socket.opened) await socket.opened;
  return socket;
}

function statusFromLine(line: string, tag: string): ImapResponse["status"] {
  const match = line.match(new RegExp(`^${tag}\\s+(OK|NO|BAD)\\b`, "iu"));
  if (!match) return "UNKNOWN";
  return match[1].toUpperCase() as ImapResponse["status"];
}

function capabilityTokens(lines: string[]): Set<string> {
  const capabilities = new Set<string>();
  for (const line of lines) {
    const match = line.match(/^\*\s+CAPABILITY\s+(.+)$/iu);
    if (!match) continue;
    for (const capability of match[1].split(/\s+/u)) capabilities.add(capability.toUpperCase());
  }
  return capabilities;
}

function flagList(flags: string[]): string {
  if (!flags.length) throw new Error("At least one flag is required");
  return `(${flags.join(" ")})`;
}

export class ImapClient {
  private readonly connection: SocketConnection;
  private readonly config: MailConfig;
  private tagNumber = 0;
  private selectedMailbox: string | null = null;
  private selectedReadOnly = true;
  private capabilities = new Set<string>();

  private constructor(connection: SocketConnection, config: MailConfig) {
    this.connection = connection;
    this.config = config;
  }

  static async open(config: MailConfig, connector: ImapConnector = defaultConnector): Promise<ImapClient> {
    const socket = await connector(config);
    const client = new ImapClient(new SocketConnection(socket), config);
    try {
      await client.initialize();
      return client;
    } catch (error) {
      client.close();
      throw error;
    }
  }

  private nextTag(): string {
    this.tagNumber += 1;
    return `A${this.tagNumber.toString(16).padStart(4, "0")}`;
  }

  private async initialize(): Promise<void> {
    const greeting = await withTimeout(this.connection.readLine(), IMAP_TIMEOUT_MS, "IMAP greeting");
    if (!/^\*\s+(?:OK|PREAUTH)\b/iu.test(greeting)) {
      throw new ImapProtocolError("iCloud IMAP server did not provide an OK greeting");
    }
    if (!/^\*\s+PREAUTH\b/iu.test(greeting)) {
      await this.command(`LOGIN ${quoteImapString(this.config.imapUser)} ${quoteImapString(this.config.password)}`);
    }
    const response = await this.command("CAPABILITY");
    this.capabilities = capabilityTokens(response.lines);
  }

  private async readResponse(tag: string, maxLiteralBytes: number): Promise<ImapResponse> {
    const lines: string[] = [];
    const literals: Uint8Array[] = [];
    while (true) {
      let line = await withTimeout(this.connection.readLine(), IMAP_TIMEOUT_MS, "IMAP response");
      while (true) {
        lines.push(line);
        const literal = line.match(/\{(\d+)(?:\+)?\}$/u);
        if (!literal) break;
        const length = Number(literal[1]);
        if (!Number.isSafeInteger(length)) throw new ImapProtocolError("Invalid IMAP literal length");
        if (length > maxLiteralBytes) {
          throw new MessageTooLargeError(`IMAP literal exceeds ${maxLiteralBytes} bytes`);
        }
        literals.push(
          await withTimeout(
            this.connection.readExactly(length),
            IMAP_TIMEOUT_MS,
            "IMAP literal",
          ),
        );
        line = await withTimeout(this.connection.readLine(), IMAP_TIMEOUT_MS, "IMAP literal suffix");
      }
      const responseStatus = statusFromLine(line, tag);
      if (responseStatus !== "UNKNOWN") {
        return { tag, status: responseStatus, lines, literals };
      }
    }
  }

  private async command(command: string, maxLiteralBytes = MAX_PROTOCOL_LITERAL_BYTES): Promise<ImapResponse> {
    const tag = this.nextTag();
    await this.connection.writeText(`${tag} ${command}\r\n`);
    const response = await this.readResponse(tag, maxLiteralBytes);
    if (response.status !== "OK") {
      throw new ImapProtocolError(`IMAP ${response.status} response for ${command.split(" ")[0]}`);
    }
    return response;
  }

  private async selectMailbox(mailbox: string, readOnly: boolean): Promise<void> {
    if (this.selectedMailbox === mailbox && (!this.selectedReadOnly || readOnly)) return;
    await this.command(`${readOnly ? "EXAMINE" : "SELECT"} ${quoteImapMailboxName(mailbox)}`);
    this.selectedMailbox = mailbox;
    this.selectedReadOnly = readOnly;
  }

  private supports(capability: string): boolean {
    return this.capabilities.has(capability.toUpperCase());
  }

  async listMailboxes(subscribedOnly = false): Promise<Mailbox[]> {
    const response = await this.command(`${subscribedOnly ? "LSUB" : "LIST"} "" "*"`);
    return response.lines.flatMap((line) => {
      const mailbox = parseListLine(line);
      return mailbox ? [mailbox] : [];
    });
  }

  async search(mailbox: string, filters: SearchFilters): Promise<number[]> {
    await this.selectMailbox(mailbox, true);
    const response = await this.command(`UID SEARCH ${compileSearch(filters)}`);
    return parseSearchResponse(response.lines);
  }

  async fetchMetadata(mailbox: string, uid: number): Promise<MessageMetadata> {
    if (!Number.isSafeInteger(uid) || uid < 1) throw new Error("UID must be a positive integer");
    await this.selectMailbox(mailbox, true);
    const response = await this.command(
      `UID FETCH ${uid} (UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODYSTRUCTURE)`,
      512 * 1024,
    );
    const metadata = parseFetchMetadata(response.lines);
    if (!metadata) throw new ImapProtocolError("IMAP response did not contain message metadata");
    return metadata;
  }

  async fetchRaw(mailbox: string, uid: number, expectedSize?: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(uid) || uid < 1) throw new Error("UID must be a positive integer");
    if (expectedSize !== undefined && expectedSize > MAX_MESSAGE_BYTES) {
      throw new MessageTooLargeError(`Message exceeds ${MAX_MESSAGE_BYTES} bytes`);
    }
    await this.selectMailbox(mailbox, true);
    const response = await this.command(
      `UID FETCH ${uid} (UID RFC822.SIZE BODY.PEEK[])`,
      MAX_MESSAGE_BYTES,
    );
    const raw = response.literals[0];
    if (!raw) throw new ImapProtocolError("IMAP response did not contain message content");
    if (raw.byteLength > MAX_MESSAGE_BYTES) {
      throw new MessageTooLargeError(`Message exceeds ${MAX_MESSAGE_BYTES} bytes`);
    }
    return raw;
  }

  async fetchBodyPart(mailbox: string, uid: number, part: string, expectedSize?: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(uid) || uid < 1) throw new Error("UID must be a positive integer");
    if (!/^\d+(?:\.\d+)*$/u.test(part)) throw new Error("Invalid IMAP body part");
    if (expectedSize !== undefined && expectedSize > MAX_ATTACHMENT_BYTES) {
      throw new MessageTooLargeError(`Attachment exceeds ${MAX_ATTACHMENT_BYTES} bytes`);
    }
    await this.selectMailbox(mailbox, true);
    const response = await this.command(
      `UID FETCH ${uid} (UID BODY.PEEK[${part}])`,
      MAX_ATTACHMENT_BYTES * 2,
    );
    const raw = response.literals[0];
    if (!raw) throw new ImapProtocolError("IMAP response did not contain attachment content");
    return raw;
  }

  async setFlags(mailbox: string, uids: number[], add: string[], remove: string[]): Promise<void> {
    await this.selectMailbox(mailbox, false);
    const uidSet = formatUidSet(uids);
    if (add.length) await this.command(`UID STORE ${uidSet} +FLAGS.SILENT ${flagList(add)}`);
    if (remove.length) await this.command(`UID STORE ${uidSet} -FLAGS.SILENT ${flagList(remove)}`);
  }

  async moveMessages(source: string, destination: string, uids: number[]): Promise<void> {
    const uidSet = formatUidSet(uids);
    await this.selectMailbox(source, false);
    if (this.supports("MOVE")) {
      await this.command(`UID MOVE ${uidSet} ${quoteImapMailboxName(destination)}`);
      return;
    }
    if (!this.supports("UIDPLUS")) {
      throw new ImapProtocolError("The iCloud IMAP server does not advertise MOVE or UIDPLUS");
    }
    await this.command(`UID COPY ${uidSet} ${quoteImapMailboxName(destination)}`);
    await this.command(`UID STORE ${uidSet} +FLAGS.SILENT (\\Deleted)`);
    await this.command(`UID EXPUNGE ${uidSet}`);
  }

  async deleteMessages(mailbox: string, uids: number[], permanent: boolean): Promise<string> {
    const uidSet = formatUidSet(uids);
    if (permanent) {
      await this.selectMailbox(mailbox, false);
      if (!this.supports("UIDPLUS")) {
        throw new ImapProtocolError("Permanent deletion requires IMAP UIDPLUS support");
      }
      await this.command(`UID STORE ${uidSet} +FLAGS.SILENT (\\Deleted)`);
      await this.command(`UID EXPUNGE ${uidSet}`);
      return mailbox;
    }

    const trash = (await this.listMailboxes()).find((candidate) => candidate.specialUse?.toLowerCase() === "\\trash");
    if (!trash) throw new ImapProtocolError("No IMAP mailbox advertised with the \\Trash special-use flag");
    if (trash.name.toLowerCase() === mailbox.toLowerCase()) {
      await this.selectMailbox(mailbox, false);
      await this.command(`UID STORE ${uidSet} +FLAGS.SILENT (\\Deleted)`);
      return trash.name;
    }
    await this.moveMessages(mailbox, trash.name, uids);
    return trash.name;
  }

  async appendToSent(raw: Uint8Array): Promise<string> {
    const sent = (await this.listMailboxes()).find((candidate) => candidate.specialUse?.toLowerCase() === "\\sent");
    if (!sent) throw new ImapProtocolError("No IMAP mailbox advertised with the \\Sent special-use flag");
    if (raw.byteLength > MAX_MESSAGE_BYTES) throw new MessageTooLargeError("Sent message is too large");
    const tag = this.nextTag();
    await this.connection.writeText(
      `${tag} APPEND ${quoteImapMailboxName(sent.name)} (\\Seen) {${raw.byteLength}}\r\n`,
    );
    const continuation = await withTimeout(this.connection.readLine(), IMAP_TIMEOUT_MS, "IMAP APPEND continuation");
    if (!/^\+/u.test(continuation)) throw new ImapProtocolError("IMAP server rejected APPEND literal");
    await this.connection.writeBytes(raw);
    await this.connection.writeText("\r\n");
    const response = await this.readResponse(tag, 64 * 1024);
    if (response.status !== "OK") throw new ImapProtocolError("IMAP APPEND failed");
    return sent.name;
  }

  close(): void {
    this.connection.close();
  }

  static async fromConfig(config: MailConfig): Promise<ImapClient> {
    return ImapClient.open(config);
  }
}

export async function withImapConfig<T>(config: MailConfig, operation: (client: ImapClient) => Promise<T>): Promise<T> {
  const client = await ImapClient.fromConfig(config);
  try {
    return await operation(client);
  } finally {
    client.close();
  }
}
