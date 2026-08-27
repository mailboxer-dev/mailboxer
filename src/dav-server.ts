import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { getCredentialsEncryptionSecret, getDavConfig } from "./config";
import { getMailConfigForCredential } from "./credentials";
import {
  MAX_DAV_PAGE_SIZE,
  MAX_DAV_RESOURCE_BYTES,
  DavClient,
} from "./dav/client";
import { cursorFingerprint, decodeDavCursor, encodeDavCursor } from "./dav/cursor";
import { publicError, requireScope, textResult, withToolSpan } from "./mcp-helpers";
import type { AppEnv, AuthProps } from "./types";
import type { CalendarItemInput, ContactInput } from "./dav/types";
import { isIsoDateOrDateTime, isUtcIsoDateOrDateTime } from "./dav/date";

const HREF_MAX = 2_048;
const ETAG_MAX = 1_024;
const TEXT_MAX = 64 * 1_024;
const QUERY_MAX = 256;

function hasInvalidControl(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code === 0 || (code >= 1 && code <= 8) || code === 11 || code === 12 || (code >= 14 && code <= 31) || code === 127) return true;
  }
  return false;
}

function hasHeaderControl(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

const hrefSchema = z.string().min(1).max(HREF_MAX).refine((value) => !hasHeaderControl(value), "Invalid href");
const etagSchema = z.string().min(1).max(ETAG_MAX).refine((value) => value.trim() !== "*" && !hasHeaderControl(value), "Invalid ETag");
const isoDateSchema = z.string().max(64).refine(isIsoDateOrDateTime, "Invalid ISO date or date-time");
const calendarTextSchema = z.string().max(TEXT_MAX).refine((value) => !hasInvalidControl(value), "Invalid calendar text");

const calendarInputSchema = z.object({
  componentType: z.enum(["VEVENT", "VTODO"]),
  uid: calendarTextSchema.max(512).optional(),
  summary: calendarTextSchema.max(4_096).optional(),
  description: calendarTextSchema.max(TEXT_MAX).optional(),
  start: isoDateSchema.optional(),
  end: isoDateSchema.optional(),
  due: isoDateSchema.optional(),
  allDay: z.boolean().optional(),
  location: calendarTextSchema.max(4_096).optional(),
  status: calendarTextSchema.max(128).optional(),
  priority: z.number().int().min(0).max(9).optional(),
  percentComplete: z.number().int().min(0).max(100).optional(),
  completed: isoDateSchema.optional(),
  rrule: calendarTextSchema.max(4_096).optional(),
  categories: z.array(calendarTextSchema.max(256)).max(100).optional(),
  url: z.string().max(2_048).refine((value) => !hasHeaderControl(value), "Invalid URL").optional(),
  rawIcalendar: z.string().max(MAX_DAV_RESOURCE_BYTES).refine((value) => !hasInvalidControl(value), "Invalid iCalendar").optional(),
});

const contactTextSchema = z.string().max(TEXT_MAX).refine((value) => !hasInvalidControl(value), "Invalid contact text");
const contactValueSchema = z.object({
  value: contactTextSchema.max(4_096),
  types: z.array(z.string().max(32).regex(/^[A-Za-z0-9-]+$/u)).max(20).default([]),
  preferred: z.boolean().default(false),
});
const contactAddressSchema = z.object({
  pobox: contactTextSchema.max(512).nullable().default(null),
  extended: contactTextSchema.max(512).nullable().default(null),
  street: contactTextSchema.max(2_048).nullable().default(null),
  locality: contactTextSchema.max(512).nullable().default(null),
  region: contactTextSchema.max(512).nullable().default(null),
  postalCode: contactTextSchema.max(128).nullable().default(null),
  country: contactTextSchema.max(512).nullable().default(null),
  types: z.array(z.string().max(32).regex(/^[A-Za-z0-9-]+$/u)).max(20).default([]),
  preferred: z.boolean().default(false),
});
const contactNameSchema = z.object({
  family: contactTextSchema.max(512).optional(),
  given: contactTextSchema.max(512).optional(),
  additional: contactTextSchema.max(512).optional(),
  prefix: contactTextSchema.max(128).optional(),
  suffix: contactTextSchema.max(128).optional(),
}).partial();
const contactInputSchema = z.object({
  uid: contactTextSchema.max(512).optional(),
  formattedName: contactTextSchema.max(4_096).optional(),
  name: contactNameSchema.optional(),
  organization: z.array(contactTextSchema.max(1_024)).max(50).optional(),
  emails: z.array(contactValueSchema).max(50).optional(),
  phones: z.array(contactValueSchema).max(50).optional(),
  addresses: z.array(contactAddressSchema).max(50).optional(),
  birthday: contactTextSchema.max(64).optional(),
  note: contactTextSchema.max(TEXT_MAX).optional(),
  urls: z.array(z.string().max(2_048).refine((value) => !hasHeaderControl(value), "Invalid URL")).max(50).optional(),
  categories: z.array(contactTextSchema.max(256)).max(100).optional(),
  rawVcard: z.string().max(MAX_DAV_RESOURCE_BYTES).refine((value) => !hasInvalidControl(value), "Invalid vCard").optional(),
});

const listLimitSchema = z.number().int().min(1).max(MAX_DAV_PAGE_SIZE).optional().default(MAX_DAV_PAGE_SIZE);
const utcIsoDateSchema = z.string().max(64).refine(isUtcIsoDateOrDateTime, "Invalid UTC ISO date or date-time");
const deleteConfirmationSchema = z.literal("delete");

async function withUserDav<T>(env: AppEnv, props: AuthProps, operation: (client: DavClient) => Promise<T>): Promise<T> {
  const config = await getMailConfigForCredential(env, props.credentialId);
  return operation(new DavClient(config, getDavConfig(env)));
}

function serviceDomain(env: AppEnv, service: "calendar" | "contacts"): string {
  const config = getDavConfig(env);
  return new URL(service === "calendar" ? config.caldavUrl : config.carddavUrl).hostname.toLowerCase();
}

function normalized(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed || undefined;
}

async function cursorAfter(
  cursor: string | undefined,
  domain: string,
  fingerprint: string,
  secret: string,
): Promise<string | undefined> {
  return cursor ? decodeDavCursor(cursor, domain, fingerprint, secret) : undefined;
}

export function registerDavTools(server: McpServer, env: AppEnv, props: AuthProps): void {
  server.registerTool(
    "list_calendars",
    {
      description: "List live iCloud CalDAV calendars and their supported event/reminder component types.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () => withToolSpan("list_calendars", async () => {
      try {
        requireScope(props, "calendar.read");
        return textResult({ calendars: await withUserDav(env, props, (client) => client.listCalendars()) });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "list_calendar_items",
    {
      description: "List live iCloud CalDAV VEVENT and VTODO resources with bounded structured fields and signed stateless cursors.",
      inputSchema: {
        calendarHref: hrefSchema.optional(),
        componentType: z.enum(["VEVENT", "VTODO", "any"]).optional().default("any"),
        text: z.string().max(QUERY_MAX).refine((value) => !hasHeaderControl(value), "Invalid text").optional(),
        start: utcIsoDateSchema.optional(),
        end: utcIsoDateSchema.optional(),
        cursor: z.string().max(4_200).optional(),
        limit: listLimitSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ calendarHref, componentType, text, start, end, cursor, limit }) => withToolSpan("list_calendar_items", async () => {
      try {
        requireScope(props, "calendar.read");
        const query = {
          calendarHref: normalized(calendarHref),
          componentType,
          text: normalized(text),
          start,
          end,
        };
        const fingerprint = await cursorFingerprint({ ...query, limit });
        const secret = getCredentialsEncryptionSecret(env);
        const domain = serviceDomain(env, "calendar");
        const afterHref = await cursorAfter(cursor, domain, fingerprint, secret);
        const page = await withUserDav(env, props, (client) => client.listCalendarItems(query, afterHref, limit));
        const nextCursor = page.hasMore && page.lastHref
          ? await encodeDavCursor(domain, fingerprint, page.lastHref, secret)
          : null;
        return textResult({ items: page.items, errors: page.errors, nextCursor });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "get_calendar_item",
    {
      description: "Fetch one live iCloud CalDAV VEVENT or VTODO resource by canonical href.",
      inputSchema: { href: hrefSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ href }) => withToolSpan("get_calendar_item", async () => {
      try {
        requireScope(props, "calendar.read");
        return textResult(await withUserDav(env, props, (client) => client.getCalendarItem(href)));
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "create_calendar_item",
    {
      description: "Create a VEVENT or VTODO in a live iCloud CalDAV calendar; an optional raw iCalendar body is authoritative.",
      inputSchema: {
        calendarHref: hrefSchema,
        ...calendarInputSchema.shape,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ calendarHref, ...input }) => withToolSpan("create_calendar_item", async () => {
      try {
        requireScope(props, "calendar.write");
        return textResult(await withUserDav(env, props, (client) => client.createCalendarItem(calendarHref, input as CalendarItemInput)));
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "update_calendar_item",
    {
      description: "Update a live iCloud CalDAV resource with a required current ETag; stale writes are rejected.",
      inputSchema: {
        href: hrefSchema,
        etag: etagSchema,
        ...calendarInputSchema.shape,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ href, etag, ...input }) => withToolSpan("update_calendar_item", async () => {
      try {
        requireScope(props, "calendar.write");
        if (!input.rawIcalendar && !input.uid) throw new Error("An update requires rawIcalendar or uid");
        return textResult(await withUserDav(env, props, (client) => client.updateCalendarItem(href, etag, input as CalendarItemInput)));
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "delete_calendar_item",
    {
      description: "Delete a live iCloud CalDAV resource only with its current ETag and explicit delete confirmation.",
      inputSchema: { href: hrefSchema, etag: etagSchema, confirm: deleteConfirmationSchema },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ href, etag }) => withToolSpan("delete_calendar_item", async () => {
      try {
        requireScope(props, "calendar.write");
        await withUserDav(env, props, (client) => client.deleteCalendarItem(href, etag));
        return textResult({ deleted: true, href });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "list_address_books",
    {
      description: "List live iCloud CardDAV address books and supported vCard versions.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () => withToolSpan("list_address_books", async () => {
      try {
        requireScope(props, "contacts.read");
        return textResult({ addressBooks: await withUserDav(env, props, (client) => client.listAddressBooks()) });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "list_contacts",
    {
      description: "List live iCloud CardDAV contacts with bounded structured fields and signed stateless cursors.",
      inputSchema: {
        addressBookHref: hrefSchema.optional(),
        query: z.string().max(QUERY_MAX).refine((value) => !hasHeaderControl(value), "Invalid query").optional(),
        cursor: z.string().max(4_200).optional(),
        limit: listLimitSchema,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ addressBookHref, query, cursor, limit }) => withToolSpan("list_contacts", async () => {
      try {
        requireScope(props, "contacts.read");
        const normalizedQuery = {
          addressBookHref: normalized(addressBookHref),
          query: normalized(query),
        };
        const fingerprint = await cursorFingerprint({ ...normalizedQuery, limit });
        const secret = getCredentialsEncryptionSecret(env);
        const domain = serviceDomain(env, "contacts");
        const afterHref = await cursorAfter(cursor, domain, fingerprint, secret);
        const page = await withUserDav(env, props, (client) => client.listContacts(normalizedQuery, afterHref, limit));
        const nextCursor = page.hasMore && page.lastHref
          ? await encodeDavCursor(domain, fingerprint, page.lastHref, secret)
          : null;
        return textResult({ contacts: page.items, errors: page.errors, nextCursor });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "get_contact",
    {
      description: "Fetch one live iCloud CardDAV contact by canonical href.",
      inputSchema: { href: hrefSchema },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ href }) => withToolSpan("get_contact", async () => {
      try {
        requireScope(props, "contacts.read");
        return textResult(await withUserDav(env, props, (client) => client.getContact(href)));
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "create_contact",
    {
      description: "Create a live iCloud CardDAV contact; an optional raw vCard body is authoritative.",
      inputSchema: {
        addressBookHref: hrefSchema,
        ...contactInputSchema.shape,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ addressBookHref, ...input }) => withToolSpan("create_contact", async () => {
      try {
        requireScope(props, "contacts.write");
        return textResult(await withUserDav(env, props, (client) => client.createContact(addressBookHref, input as ContactInput)));
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "update_contact",
    {
      description: "Update a live iCloud CardDAV contact with a required current ETag; stale writes are rejected.",
      inputSchema: {
        href: hrefSchema,
        etag: etagSchema,
        ...contactInputSchema.shape,
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ href, etag, ...input }) => withToolSpan("update_contact", async () => {
      try {
        requireScope(props, "contacts.write");
        if (!input.rawVcard && !input.uid && !input.formattedName && !input.name) throw new Error("An update requires rawVcard or contact fields");
        return textResult(await withUserDav(env, props, (client) => client.updateContact(href, etag, input as ContactInput)));
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );

  server.registerTool(
    "delete_contact",
    {
      description: "Delete a live iCloud CardDAV contact only with its current ETag and explicit delete confirmation.",
      inputSchema: { href: hrefSchema, etag: etagSchema, confirm: deleteConfirmationSchema },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ href, etag }) => withToolSpan("delete_contact", async () => {
      try {
        requireScope(props, "contacts.write");
        await withUserDav(env, props, (client) => client.deleteContact(href, etag));
        return textResult({ deleted: true, href });
      } catch (error) {
        return textResult({ error: publicError(error) }, true);
      }
    }),
  );
}
