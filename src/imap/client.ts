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
import { protocolCommandName, withSpan } from "../tracing";

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
    return withSpan(
      "mail.imap.open",
      {
        "server.address": config.imapHost,
        "server.port": config.imapPort,
      },
      async (span) => {
        const socket = await connector(config);
        const client = new ImapClient(new SocketConnection(socket), config);
        try {
          await client.initialize();
          span.setAttribute("mail.imap.capability_count", client.capabilities.size);
          return client;
        } catch (error) {
          client.close();
          throw error;
        }
      },
    );
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
    return withSpan(
      "mail.imap.command",
      {
        "mail.imap.command_name": protocolCommandName(command),
        "mail.imap.max_literal_bytes": maxLiteralBytes,
      },
      async (span) => {
        const tag = this.nextTag();
        await this.connection.writeText(`${tag} ${command}\r\n`);
        const response = await this.readResponse(tag, maxLiteralBytes);
        span.setAttribute("mail.imap.response_status", response.status);
        span.setAttribute("mail.imap.literal_count", response.literals.length);
        if (response.status !== "OK") {
          throw new ImapProtocolError(`IMAP ${response.status} response for ${command.split(" ")[0]}`);
        }
        return response;
      },
    );
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
    return withSpan(
      "mail.imap.list_mailboxes",
      { "mail.imap.subscribed_only": subscribedOnly },
      async (span) => {
        const response = await this.command(`${subscribedOnly ? "LSUB" : "LIST"} "" "*"`);
        const mailboxes = response.lines.flatMap((line) => {
          const mailbox = parseListLine(line);
          return mailbox ? [mailbox] : [];
        });
        span.setAttribute("mail.imap.mailbox_count", mailboxes.length);
        return mailboxes;
      },
    );
  }

  async search(mailbox: string, filters: SearchFilters): Promise<number[]> {
    return withSpan(
      "mail.imap.search",
      {
        "mail.imap.search_filter_count": Object.values(filters).filter((value) => value !== undefined).length,
      },
      async (span) => {
        await this.selectMailbox(mailbox, true);
        const response = await this.command(`UID SEARCH ${compileSearch(filters)}`);
        const uids = parseSearchResponse(response.lines);
        span.setAttribute("mail.imap.result_uid_count", uids.length);
        return uids;
      },
    );
  }

  async fetchMetadata(mailbox: string, uid: number): Promise<MessageMetadata> {
    if (!Number.isSafeInteger(uid) || uid < 1) throw new Error("UID must be a positive integer");
    return withSpan("mail.imap.fetch_metadata", {}, async (span) => {
      await this.selectMailbox(mailbox, true);
      const response = await this.command(
        `UID FETCH ${uid} (UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODYSTRUCTURE)`,
        512 * 1024,
      );
      const metadata = parseFetchMetadata(response.lines);
      if (!metadata) throw new ImapProtocolError("IMAP response did not contain message metadata");
      span.setAttribute("mail.imap.message_size_bytes", metadata.size);
      span.setAttribute("mail.imap.attachment_count", metadata.attachments.length);
      return metadata;
    });
  }

  async fetchRaw(mailbox: string, uid: number, expectedSize?: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(uid) || uid < 1) throw new Error("UID must be a positive integer");
    if (expectedSize !== undefined && expectedSize > MAX_MESSAGE_BYTES) {
      throw new MessageTooLargeError(`Message exceeds ${MAX_MESSAGE_BYTES} bytes`);
    }
    return withSpan(
      "mail.imap.fetch_message",
      { "mail.imap.expected_size_bytes": expectedSize },
      async (span) => {
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
        span.setAttribute("mail.imap.bytes", raw.byteLength);
        return raw;
      },
    );
  }

  async fetchBodyPart(mailbox: string, uid: number, part: string, expectedSize?: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(uid) || uid < 1) throw new Error("UID must be a positive integer");
    if (!/^\d+(?:\.\d+)*$/u.test(part)) throw new Error("Invalid IMAP body part");
    if (expectedSize !== undefined && expectedSize > MAX_ATTACHMENT_BYTES) {
      throw new MessageTooLargeError(`Attachment exceeds ${MAX_ATTACHMENT_BYTES} bytes`);
    }
    return withSpan(
      "mail.imap.fetch_attachment",
      { "mail.imap.expected_size_bytes": expectedSize },
      async (span) => {
        await this.selectMailbox(mailbox, true);
        const response = await this.command(
          `UID FETCH ${uid} (UID BODY.PEEK[${part}])`,
          MAX_ATTACHMENT_BYTES * 2,
        );
        const raw = response.literals[0];
        if (!raw) throw new ImapProtocolError("IMAP response did not contain attachment content");
        span.setAttribute("mail.imap.bytes", raw.byteLength);
        return raw;
      },
    );
  }

  async setFlags(mailbox: string, uids: number[], add: string[], remove: string[]): Promise<void> {
    return withSpan(
      "mail.imap.set_flags",
      {
        "mail.imap.uid_count": uids.length,
        "mail.imap.add_flag_count": add.length,
        "mail.imap.remove_flag_count": remove.length,
      },
      async () => {
        await this.selectMailbox(mailbox, false);
        const uidSet = formatUidSet(uids);
        if (add.length) await this.command(`UID STORE ${uidSet} +FLAGS.SILENT ${flagList(add)}`);
        if (remove.length) await this.command(`UID STORE ${uidSet} -FLAGS.SILENT ${flagList(remove)}`);
      },
    );
  }

  async moveMessages(source: string, destination: string, uids: number[]): Promise<void> {
    return withSpan(
      "mail.imap.move_messages",
      { "mail.imap.uid_count": uids.length },
      async (span) => {
        const uidSet = formatUidSet(uids);
        await this.selectMailbox(source, false);
        if (this.supports("MOVE")) {
          span.setAttribute("mail.imap.move_strategy", "move");
          await this.command(`UID MOVE ${uidSet} ${quoteImapMailboxName(destination)}`);
          return;
        }
        if (!this.supports("UIDPLUS")) {
          throw new ImapProtocolError("The iCloud IMAP server does not advertise MOVE or UIDPLUS");
        }
        span.setAttribute("mail.imap.move_strategy", "copy_delete");
        await this.command(`UID COPY ${uidSet} ${quoteImapMailboxName(destination)}`);
        await this.command(`UID STORE ${uidSet} +FLAGS.SILENT (\\Deleted)`);
        await this.command(`UID EXPUNGE ${uidSet}`);
      },
    );
  }

  async deleteMessages(mailbox: string, uids: number[], permanent: boolean): Promise<string> {
    return withSpan(
      "mail.imap.delete_messages",
      { "mail.imap.uid_count": uids.length, "mail.imap.permanent": permanent },
      async (span) => {
        const uidSet = formatUidSet(uids);
        if (permanent) {
          await this.selectMailbox(mailbox, false);
          if (!this.supports("UIDPLUS")) {
            throw new ImapProtocolError("Permanent deletion requires IMAP UIDPLUS support");
          }
          span.setAttribute("mail.imap.delete_strategy", "permanent");
          await this.command(`UID STORE ${uidSet} +FLAGS.SILENT (\\Deleted)`);
          await this.command(`UID EXPUNGE ${uidSet}`);
          return mailbox;
        }

        const trash = (await this.listMailboxes()).find((candidate) => candidate.specialUse?.toLowerCase() === "\\trash");
        if (!trash) throw new ImapProtocolError("No IMAP mailbox advertised with the \\Trash special-use flag");
        if (trash.name.toLowerCase() === mailbox.toLowerCase()) {
          await this.selectMailbox(mailbox, false);
          span.setAttribute("mail.imap.delete_strategy", "trash_flag");
          await this.command(`UID STORE ${uidSet} +FLAGS.SILENT (\\Deleted)`);
          return trash.name;
        }
        span.setAttribute("mail.imap.delete_strategy", "trash_move");
        await this.moveMessages(mailbox, trash.name, uids);
        return trash.name;
      },
    );
  }

  async appendToSent(raw: Uint8Array): Promise<string> {
    return withSpan(
      "mail.imap.append_sent",
      { "mail.imap.bytes": raw.byteLength },
      async (span) => {
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
        span.setAttribute("mail.imap.response_status", response.status);
        span.setAttribute("mail.imap.literal_count", response.literals.length);
        if (response.status !== "OK") throw new ImapProtocolError("IMAP APPEND failed");
        return sent.name;
      },
    );
  }

  close(): void {
    this.connection.close();
  }

  static async fromConfig(config: MailConfig): Promise<ImapClient> {
    return ImapClient.open(config);
  }
}

export async function withImapConfig<T>(config: MailConfig, operation: (client: ImapClient) => Promise<T>): Promise<T> {
  return withSpan("mail.imap.session", {}, async () => {
    const client = await ImapClient.fromConfig(config);
    try {
      return await operation(client);
    } finally {
      client.close();
    }
  });
}
