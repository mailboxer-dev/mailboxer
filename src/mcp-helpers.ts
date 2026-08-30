import { AccountVaultError } from "./accounts";
import { MailCredentialError } from "./credentials";
import { DavPayloadTooLargeError, DavProtocolError } from "./dav/client";
import { DavCursorError } from "./dav/cursor";
import { IcalendarParseError } from "./dav/ical";
import { VcardParseError } from "./dav/vcard";
import { ImapProtocolError, MessageTooLargeError } from "./imap/client";
import { SmtpProtocolError } from "./smtp/client";
import { withSpan, type TraceAttributes } from "./tracing";
import type { AuthProps, ResourceScope } from "./types";
import { z } from "zod";

export function textResult(value: unknown, isError = false): { content: [{ type: "text"; text: string }]; isError?: boolean } {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    ...(isError ? { isError: true } : {}),
  };
}

export function publicError(error: unknown): string {
  if (error instanceof MessageTooLargeError || error instanceof DavPayloadTooLargeError) return error.message;
  if (error instanceof ImapProtocolError || error instanceof SmtpProtocolError || error instanceof DavProtocolError) return error.message;
  if (error instanceof IcalendarParseError || error instanceof VcardParseError || error instanceof DavCursorError) return error.message;
  if (error instanceof MailCredentialError) return error.message;
  if (error instanceof AccountVaultError) return error.message;
  if (error instanceof Error && error.message.startsWith("Missing Worker")) return "Account credentials are not configured";
  if (error instanceof Error && error.message.startsWith("Missing required scope:")) return error.message;
  if (error instanceof z.ZodError) return "Input failed validation";
  return "Email account operation failed";
}

export function requireScope(props: AuthProps, scope: ResourceScope): void {
  if (!props?.userId || !props.scopes.includes(scope)) {
    throw new Error(`Missing required scope: ${scope}`);
  }
}

export interface ToolCorrelation {
  accountId?: string;
  mailbox?: string;
  uid?: number;
  part?: string;
  calendarHref?: string;
}

async function correlationKey(field: string, value: string | undefined): Promise<string | undefined> {
  if (!value) return undefined;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${field}\u0000${value}`));
  return Array.from(new Uint8Array(digest).slice(0, 12), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function correlationAttributes(values: ToolCorrelation): Promise<TraceAttributes> {
  const [accountKey, mailboxKey, calendarHrefKey] = await Promise.all([
    correlationKey("account", values.accountId),
    correlationKey("mailbox", values.mailbox),
    correlationKey("calendar-href", values.calendarHref),
  ]);
  return {
    "mcp.tool.invocation_id": crypto.randomUUID(),
    "mcp.tool.account_key": accountKey,
    "mcp.tool.mailbox_key": mailboxKey,
    "mcp.tool.uid": values.uid,
    "mcp.tool.part": values.part,
    "mcp.tool.calendar_href_key": calendarHrefKey,
  };
}

export async function withToolSpan<T>(
  name: string,
  operation: () => Promise<T>,
  correlation: ToolCorrelation = {},
): Promise<T> {
  return withSpan(`mcp.tool.${name}`, {
    "mcp.tool.name": name,
    ...await correlationAttributes(correlation),
  }, operation);
}
