import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { listAccountsForUser, resolveAccount } from "./accounts";
import { MessageTooLargeError, withImapConfig, type ImapClient } from "./imap/client";
import { parseRfc822, decodeContentTransfer, encodeBase64 } from "./mime";
import { SmtpClient } from "./smtp/client";
import { registerDavTools } from "./dav-server";
import { publicError, requireScope, textResult, withToolSpan } from "./mcp-helpers";
import {
  DEFAULT_PAGE_SIZE,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENT_COUNT,
  type MailAuthProps,
  type MessageMetadata,
  type AppEnv,
  type AccountSummary,
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
const accountIdSchema = z.string().regex(/^acct_[A-Za-z0-9_-]{22}$|^icloud-[A-Za-z0-9_-]{43}$/u).optional();

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

async function withUserImap<T>(
  env: AppEnv,
  props: MailAuthProps,
  accountId: string | undefined,
  operation: (imap: ImapClient) => Promise<T>,
): Promise<{ value: T; account: AccountSummary }> {
  const selected = await resolveAccount(env, props, accountId, "mail");
  return { value: await withImapConfig(selected.account.config, operation), account: selected.summary };
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
  const server = new McpServer({ name: "email-mcp", version: "0.1.0" });

  server.registerTool(
    "list_accounts",
    {
      description: "List the configured email accounts and identify the default account. Credentials and server details are never returned.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () => withToolSpan("list_accounts", async () => {
      try {
        if (!props?.userId) throw new Error("Missing authenticated user");
        return textResult(await listAccountsForUser(env, props));
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "list_mailboxes",
    {
      description: "List live IMAP mailboxes and their special-use roles for one configured account.",
      inputSchema: { accountId: accountIdSchema, subscribedOnly: z.boolean().optional().default(false) },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ accountId, subscribedOnly }) => withToolSpan("list_mailboxes", async () => {
      try {
        requireScope(props, "mail.read");
        const result = await withUserImap(env, props, accountId, (imap) => imap.listMailboxes(subscribedOnly));
        return textResult({ mailboxes: result.value, account: result.account });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "list_messages",
    {
      description: "List a bounded page of live messages from one account's IMAP mailbox using UID cursors.",
      inputSchema: {
        accountId: accountIdSchema,
        mailbox: mailboxSchema.optional().default("INBOX"),
        beforeUid: uidSchema.optional(),
        limit: z.number().int().min(1).max(DEFAULT_PAGE_SIZE).optional().default(DEFAULT_PAGE_SIZE),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ accountId, mailbox, beforeUid, limit }) => withToolSpan("list_messages", async () => {
      try {
        requireScope(props, "mail.read");
        const result = await withUserImap(env, props, accountId, async (imap) => {
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
        return textResult({ ...result.value, account: result.account });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "search_messages",
    {
      description: "Search one account's live IMAP messages with structured sender, recipient, subject, text, date, and flag filters.",
      inputSchema: {
        accountId: accountIdSchema,
        mailbox: mailboxSchema.optional().default("INBOX"),
        beforeUid: uidSchema.optional(),
        limit: z.number().int().min(1).max(DEFAULT_PAGE_SIZE).optional().default(DEFAULT_PAGE_SIZE),
        ...searchShape,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ accountId, mailbox, beforeUid, limit, ...filters }) => withToolSpan("search_messages", async () => {
      try {
        requireScope(props, "mail.read");
        const result = await withUserImap(env, props, accountId, async (imap) => {
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
        return textResult({ ...result.value, account: result.account });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "get_message",
    {
      description: "Fetch one live IMAP message by UID, parse its RFC822 content, and return bounded structured MIME data.",
      inputSchema: {
        accountId: accountIdSchema,
        mailbox: mailboxSchema.optional().default("INBOX"),
        uid: uidSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ accountId, mailbox, uid }) => withToolSpan("get_message", async () => {
      try {
        requireScope(props, "mail.read");
        const result = await withUserImap(env, props, accountId, async (imap) => {
          const metadata = await imap.fetchMetadata(mailbox, uid);
          const raw = await imap.fetchRaw(mailbox, uid, metadata.size);
          return parseRfc822(raw, metadata, metadata.attachments);
        });
        return textResult({ ...result.value, account: result.account });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "get_attachment",
    {
      description: "Fetch one bounded attachment body from a live IMAP message by UID and BODY part number.",
      inputSchema: {
        accountId: accountIdSchema,
        mailbox: mailboxSchema.optional().default("INBOX"),
        uid: uidSchema,
        part: z.string().regex(/^\d+(?:\.\d+)*$/u),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ accountId, mailbox, uid, part }) => withToolSpan("get_attachment", async () => {
      try {
        requireScope(props, "mail.read");
        const result = await withUserImap(env, props, accountId, async (imap) => {
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
        return textResult({ ...result.value, account: result.account });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "set_message_flags",
    {
      description: "Add or remove bounded IMAP flags on live messages by UID.",
      inputSchema: {
        accountId: accountIdSchema,
        mailbox: mailboxSchema.optional().default("INBOX"),
        uids: uidListSchema,
        add: z.array(z.string().max(64)).max(20).optional().default([]),
        remove: z.array(z.string().max(64)).max(20).optional().default([]),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ accountId, mailbox, uids, add, remove }) => withToolSpan("set_message_flags", async () => {
      try {
        requireScope(props, "mail.write");
        const normalizedAdd = safeFlags(add);
        const normalizedRemove = safeFlags(remove);
        if (!normalizedAdd.length && !normalizedRemove.length) throw new Error("At least one flag change is required");
        const normalizedUids = safeUidList(uids);
        const result = await withUserImap(env, props, accountId, (imap) => imap.setFlags(mailbox, normalizedUids, normalizedAdd, normalizedRemove));
        return textResult({ mailbox, uids: normalizedUids, added: normalizedAdd, removed: normalizedRemove, account: result.account });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "move_messages",
    {
      description: "Move live messages within one account by UID using MOVE or a UIDPLUS-safe fallback.",
      inputSchema: {
        accountId: accountIdSchema,
        sourceMailbox: mailboxSchema.optional().default("INBOX"),
        destinationMailbox: mailboxSchema,
        uids: uidListSchema,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ accountId, sourceMailbox, destinationMailbox, uids }) => withToolSpan("move_messages", async () => {
      try {
        requireScope(props, "mail.write");
        const normalizedUids = safeUidList(uids);
        const result = await withUserImap(env, props, accountId, (imap) => imap.moveMessages(sourceMailbox, destinationMailbox, normalizedUids));
        return textResult({ sourceMailbox, destinationMailbox, uids: normalizedUids, moved: true, account: result.account });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "delete_messages",
    {
      description: "Move live messages to the IMAP \\Trash mailbox by default; permanent deletion requires explicit confirmation and UIDPLUS.",
      inputSchema: {
        accountId: accountIdSchema,
        mailbox: mailboxSchema.optional().default("INBOX"),
        uids: uidListSchema,
        permanent: z.boolean().optional().default(false),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ accountId, mailbox, uids, permanent }) => withToolSpan("delete_messages", async () => {
      try {
        requireScope(props, "mail.write");
        const normalizedUids = safeUidList(uids);
        const result = await withUserImap(env, props, accountId, (imap) => imap.deleteMessages(mailbox, normalizedUids, permanent));
        return textResult({ mailbox, uids: normalizedUids, permanent, destination: result.value, account: result.account });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "send_email",
    {
      description: "Compose and deliver a bounded email through one account's SMTP server, then append the exact RFC822 bytes to its Sent mailbox.",
      inputSchema: {
        accountId: accountIdSchema,
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
    async ({ accountId, to, cc, bcc, replyTo, subject, text, html, attachments }) => withToolSpan("send_email", async () => {
      try {
        requireScope(props, "mail.write");
        if (text === undefined && html === undefined) throw new Error("At least one of text or html is required");
        const selected = await resolveAccount(env, props, accountId, "mail");
        const config = selected.account.config;
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
          return textResult({ delivery: "sent", sentSaved: true, sentMailbox, messageId: composed.messageId, account: selected.summary });
        } catch (error) {
          return textResult({
            delivery: "sent",
            sentSaved: false,
            sentSaveError: publicError(error),
            messageId: composed.messageId,
            account: selected.summary,
          }, true);
        }
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  registerDavTools(server, env, props);

  return server;
}

export const TOOL_NAMES = [
  "list_accounts",
  "list_mailboxes",
  "list_messages",
  "search_messages",
  "get_message",
  "get_attachment",
  "set_message_flags",
  "move_messages",
  "delete_messages",
  "send_email",
  "list_calendars",
  "list_calendar_items",
  "get_calendar_item",
  "create_calendar_item",
  "update_calendar_item",
  "delete_calendar_item",
  "list_address_books",
  "list_contacts",
  "get_contact",
  "create_contact",
  "update_contact",
  "delete_contact",
] as const;
