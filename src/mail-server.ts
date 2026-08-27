import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { MailCredentialError, getMailConfigForCredential } from "./credentials";
import { ImapProtocolError, MessageTooLargeError, withImapConfig, type ImapClient } from "./imap/client";
import { parseRfc822, decodeContentTransfer, encodeBase64 } from "./mime";
import { SmtpClient, SmtpProtocolError } from "./smtp/client";
import {
  DEFAULT_PAGE_SIZE,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_COUNT,
  type MailAuthProps,
  type MessageMetadata,
  type AppEnv,
} from "./types";

const MAILBOX_LIMIT = 512;
const MAX_UIDS_PER_MUTATION = 50;
const VALID_SYSTEM_FLAGS = new Set(["\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft"]);

const searchShape = {
  from: z.string().max(256).optional(),
  to: z.string().max(256).optional(),
  subject: z.string().max(256).optional(),
  text: z.string().max(256).optional(),
  since: z.string().regex(/^\d{4}-\d{2}-\d{2}$/u).optional(),
  before: z.string().regex(/^\d{4}-\d{2}-\d{2}$/u).optional(),
  unread: z.boolean().optional(),
  flagged: z.boolean().optional(),
  answered: z.boolean().optional(),
  draft: z.boolean().optional(),
};

const mailboxSchema = z.string().min(1).max(MAILBOX_LIMIT);
const uidSchema = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const uidListSchema = z.array(uidSchema).min(1).max(MAX_UIDS_PER_MUTATION);

function textResult(value: unknown, isError = false): { content: [{ type: "text"; text: string }]; isError?: boolean } {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    ...(isError ? { isError: true } : {}),
  };
}

function publicError(error: unknown): string {
  if (error instanceof MessageTooLargeError) return error.message;
  if (error instanceof ImapProtocolError || error instanceof SmtpProtocolError) return error.message;
  if (error instanceof MailCredentialError) return error.message;
  if (error instanceof Error && error.message.startsWith("Missing Worker")) return "Mail credentials are not configured";
  if (error instanceof z.ZodError) return "Input failed validation";
  return "Mail operation failed";
}

function safeUidList(values: number[]): number[] {
  return [...new Set(uidListSchema.parse(values))];
}

function safeFlags(flags: string[]): string[] {
  if (flags.length > 20) throw new Error("Too many flags");
  return [...new Set(flags)].map((flag) => {
    if (VALID_SYSTEM_FLAGS.has(flag)) return flag;
    if (/^\$[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u.test(flag)) return flag;
    if (/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(flag)) return flag;
    throw new Error("Invalid IMAP flag");
  });
}

function requireScope(props: MailAuthProps, scope: "mail.read" | "mail.write"): void {
  if (!props?.userId || props.userId !== props.credentialId || !props.credentialId || !props.scopes.includes(scope)) {
    throw new Error(`Missing required scope: ${scope}`);
  }
}

async function withUserImap<T>(env: AppEnv, props: MailAuthProps, operation: (imap: ImapClient) => Promise<T>): Promise<T> {
  const config = await getMailConfigForCredential(env, props.credentialId);
  return withImapConfig(config, operation);
}

function pageUids(uids: number[], beforeUid: number | undefined, limit: number): { selected: number[]; hasMore: boolean } {
  const filtered = [...new Set(uids)]
    .filter((uid) => beforeUid === undefined || uid < beforeUid)
    .sort((left, right) => right - left);
  return { selected: filtered.slice(0, limit), hasMore: filtered.length > limit };
}

function metadataSummary(metadata: MessageMetadata): MessageMetadata {
  return metadata;
}

export function createMailServer(env: AppEnv, props: MailAuthProps): McpServer {
  const server = new McpServer({ name: "icloud-mail-mcp", version: "0.1.0" });

  server.registerTool(
    "list_mailboxes",
    {
      description: "List live iCloud IMAP mailboxes and their special-use roles.",
      inputSchema: { subscribedOnly: z.boolean().optional().default(false) },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ subscribedOnly }) => {
      try {
        requireScope(props, "mail.read");
        const mailboxes = await withUserImap(env, props, (imap) => imap.listMailboxes(subscribedOnly));
        return textResult({ mailboxes });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    },
  );

  server.registerTool(
    "list_messages",
    {
      description: "List a bounded page of live messages from an iCloud IMAP mailbox using UID cursors.",
      inputSchema: {
        mailbox: mailboxSchema.optional().default("INBOX"),
        beforeUid: uidSchema.optional(),
        limit: z.number().int().min(1).max(DEFAULT_PAGE_SIZE).optional().default(DEFAULT_PAGE_SIZE),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ mailbox, beforeUid, limit }) => {
      try {
        requireScope(props, "mail.read");
        const page = await withUserImap(env, props, async (imap) => {
          const uids = await imap.search(mailbox, {});
          const selected = pageUids(uids, beforeUid, limit);
          const messages: MessageMetadata[] = [];
          for (const uid of selected.selected) messages.push(await imap.fetchMetadata(mailbox, uid));
          return {
            mailbox,
            messages: messages.map(metadataSummary),
            nextBeforeUid: selected.hasMore ? messages.at(-1)?.uid ?? null : null,
          };
        });
        return textResult(page);
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    },
  );

  server.registerTool(
    "search_messages",
    {
      description: "Search live iCloud IMAP messages with structured sender, recipient, subject, text, date, and flag filters.",
      inputSchema: {
        mailbox: mailboxSchema.optional().default("INBOX"),
        beforeUid: uidSchema.optional(),
        limit: z.number().int().min(1).max(DEFAULT_PAGE_SIZE).optional().default(DEFAULT_PAGE_SIZE),
        ...searchShape,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ mailbox, beforeUid, limit, ...filters }) => {
      try {
        requireScope(props, "mail.read");
        const page = await withUserImap(env, props, async (imap) => {
          const uids = await imap.search(mailbox, filters);
          const selected = pageUids(uids, beforeUid, limit);
          const messages: MessageMetadata[] = [];
          for (const uid of selected.selected) messages.push(await imap.fetchMetadata(mailbox, uid));
          return {
            mailbox,
            filters,
            messages: messages.map(metadataSummary),
            nextBeforeUid: selected.hasMore ? messages.at(-1)?.uid ?? null : null,
          };
        });
        return textResult(page);
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    },
  );

  server.registerTool(
    "get_message",
    {
      description: "Fetch one live iCloud message by UID, parse its RFC822 content, and return bounded structured MIME data.",
      inputSchema: {
        mailbox: mailboxSchema.optional().default("INBOX"),
        uid: uidSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ mailbox, uid }) => {
      try {
        requireScope(props, "mail.read");
        const message = await withUserImap(env, props, async (imap) => {
          const metadata = await imap.fetchMetadata(mailbox, uid);
          const raw = await imap.fetchRaw(mailbox, uid, metadata.size);
          return parseRfc822(raw, metadata, metadata.attachments);
        });
        return textResult(message);
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    },
  );

  server.registerTool(
    "get_attachment",
    {
      description: "Fetch one bounded attachment body from a live iCloud IMAP message by UID and BODY part number.",
      inputSchema: {
        mailbox: mailboxSchema.optional().default("INBOX"),
        uid: uidSchema,
        part: z.string().regex(/^\d+(?:\.\d+)*$/u),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ mailbox, uid, part }) => {
      try {
        requireScope(props, "mail.read");
        const attachment = await withUserImap(env, props, async (imap) => {
          const metadata = await imap.fetchMetadata(mailbox, uid);
          const descriptor = metadata.attachments.find((candidate) => candidate.part === part);
          if (!descriptor) throw new Error("Attachment part was not found in BODYSTRUCTURE");
          const encoded = await imap.fetchBodyPart(mailbox, uid, part, descriptor.size);
          const content = decodeContentTransfer(encoded, descriptor.encoding);
          if (content.byteLength > MAX_ATTACHMENT_BYTES) throw new MessageTooLargeError("Attachment exceeds the safety limit");
          return {
            uid,
            part,
            filename: descriptor.filename,
            mimeType: descriptor.mimeType,
            contentBase64: encodeBase64(content),
            size: content.byteLength,
          };
        });
        return textResult(attachment);
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    },
  );

  server.registerTool(
    "set_message_flags",
    {
      description: "Add or remove bounded IMAP flags on live messages by UID.",
      inputSchema: {
        mailbox: mailboxSchema.optional().default("INBOX"),
        uids: uidListSchema,
        add: z.array(z.string().max(64)).max(20).optional().default([]),
        remove: z.array(z.string().max(64)).max(20).optional().default([]),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ mailbox, uids, add, remove }) => {
      try {
        requireScope(props, "mail.write");
        const normalizedAdd = safeFlags(add);
        const normalizedRemove = safeFlags(remove);
        if (!normalizedAdd.length && !normalizedRemove.length) throw new Error("At least one flag change is required");
        const normalizedUids = safeUidList(uids);
        await withUserImap(env, props, (imap) => imap.setFlags(mailbox, normalizedUids, normalizedAdd, normalizedRemove));
        return textResult({ mailbox, uids: normalizedUids, added: normalizedAdd, removed: normalizedRemove });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    },
  );

  server.registerTool(
    "move_messages",
    {
      description: "Move live iCloud messages by UID to another mailbox using MOVE or a UIDPLUS-safe fallback.",
      inputSchema: {
        sourceMailbox: mailboxSchema.optional().default("INBOX"),
        destinationMailbox: mailboxSchema,
        uids: uidListSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ sourceMailbox, destinationMailbox, uids }) => {
      try {
        requireScope(props, "mail.write");
        const normalizedUids = safeUidList(uids);
        await withUserImap(env, props, (imap) => imap.moveMessages(sourceMailbox, destinationMailbox, normalizedUids));
        return textResult({ sourceMailbox, destinationMailbox, uids: normalizedUids, moved: true });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    },
  );

  server.registerTool(
    "delete_messages",
    {
      description: "Move live messages to the IMAP \\Trash mailbox by default; permanent deletion requires explicit confirmation and UIDPLUS.",
      inputSchema: {
        mailbox: mailboxSchema.optional().default("INBOX"),
        uids: uidListSchema,
        permanent: z.boolean().optional().default(false),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ mailbox, uids, permanent }) => {
      try {
        requireScope(props, "mail.write");
        const normalizedUids = safeUidList(uids);
        const destination = await withUserImap(env, props, (imap) => imap.deleteMessages(mailbox, normalizedUids, permanent));
        return textResult({ mailbox, uids: normalizedUids, permanent, destination });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    },
  );

  server.registerTool(
    "send_email",
    {
      description: "Compose and deliver a bounded email over iCloud SMTP STARTTLS, then append the exact RFC822 bytes to iCloud Sent.",
      inputSchema: {
        to: z.array(z.string().max(320)).min(1).max(50),
        cc: z.array(z.string().max(320)).max(50).optional().default([]),
        bcc: z.array(z.string().max(320)).max(50).optional().default([]),
        replyTo: z.array(z.string().max(320)).max(10).optional().default([]),
        subject: z.string().max(998),
        text: z.string().max(1_000_000).optional(),
        html: z.string().max(1_000_000).optional(),
        attachments: z.array(z.object({
          filename: z.string().min(1).max(255),
          mimeType: z.string().min(3).max(128),
          contentBase64: z.string().max(2_000_000),
          contentId: z.string().max(320).optional(),
        })).max(MAX_ATTACHMENT_COUNT).optional().default([]),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ to, cc, bcc, replyTo, subject, text, html, attachments }) => {
      try {
        requireScope(props, "mail.write");
        if (text === undefined && html === undefined) throw new Error("At least one of text or html is required");
        const config = await getMailConfigForCredential(env, props.credentialId);
        const composed = await SmtpClient.sendWithConfig(config, {
          from: config.email,
          to,
          cc,
          bcc,
          replyTo,
          subject,
          text,
          html,
          attachments,
        });
        try {
          const sentMailbox = await withImapConfig(config, (imap) => imap.appendToSent(composed.raw));
          return textResult({ delivery: "sent", sentSaved: true, sentMailbox, messageId: composed.messageId });
        } catch (error) {
          return textResult({
            delivery: "sent",
            sentSaved: false,
            sentSaveError: publicError(error),
            messageId: composed.messageId,
          }, true);
        }
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    },
  );

  return server;
}

export const TOOL_NAMES = [
  "list_mailboxes",
  "list_messages",
  "search_messages",
  "get_message",
  "get_attachment",
  "set_message_flags",
  "move_messages",
  "delete_messages",
  "send_email",
] as const;
