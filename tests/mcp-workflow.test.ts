import { createMcpHandler } from "agents/mcp/server";
import { describe, expect, it, vi } from "vitest";
import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { addDraftAccount, commitAccountDraft, newAccountDraft, setDraftDefault } from "../src/accounts";
import { ImapClient } from "../src/imap/client";
import { createMailServer } from "../src/mail-server";
import { encodeBase64 } from "../src/mime";
import type { AppEnv, MailAuthProps, MessageMetadata, StoredMailAccount } from "../src/types";

const accountId = "acct_wMp16sTzQ7Tq9TPZN3doYw";
const fallbackAccountId = "acct_fallback_account_12345";
const mailbox = "INBOX";
const uid = 61514;
const attachmentPart = "2";

interface AccountResult {
  account: { accountId: string };
}

interface MessageResult extends AccountResult {
  metadata: MessageMetadata;
  text: string | null;
  attachments: Array<{ part: string | null; filename: string | null; contentBase64: string }>;
}

interface AttachmentResult extends AccountResult {
  uid: number;
  part: string;
  filename: string | null;
  contentBase64: string;
  size: number;
}

interface CalendarsResult extends AccountResult {
  calendars: Array<{ href: string; displayName: string | null; componentTypes: string[] }>;
}

interface CalendarItemResult extends AccountResult {
  componentType: string;
  uid: string | null;
  start: string | null;
  end: string | null;
  location: string | null;
  rawIcalendar: string;
  requestedAttachmentPreserved: boolean;
}

class MemoryKv {
  private readonly values = new Map<string, string>();

  async put(key: string, value: string): Promise<void> {
    this.values.set(key, value);
  }

  async get(key: string): Promise<unknown> {
    return this.values.get(key) ?? null;
  }

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }
}

function testEnv(kv = new MemoryKv()): AppEnv {
  return {
    OAUTH_KV: kv as unknown as KVNamespace,
    OAUTH_PROVIDER: {} as OAuthHelpers,
    MAIL_CREDENTIALS_ENCRYPTION_KEY: "workflow-regression-test-key-with-at-least-32-chars",
  };
}

function account(
  id: string,
  label: string,
  email: string,
  capabilities: StoredMailAccount["capabilities"],
  preset: StoredMailAccount["preset"] = "custom",
): StoredMailAccount {
  return {
    accountId: id,
    label,
    preset,
    address: email,
    capabilities,
    config: {
      email,
      imapUser: email.split("@", 1)[0] ?? email,
      password: "workflow-password",
      imapHost: "imap.example.com",
      imapPort: 993,
      imapTlsMode: "implicit",
      smtpHost: "smtp.example.com",
      smtpPort: 587,
      smtpTlsMode: "starttls",
      smtpUser: email,
      smtpPassword: "workflow-password",
    },
  };
}

function xmlResponse(body: string): Response {
  return new Response(body, { status: 207, headers: { "Content-Type": "application/xml" } });
}

function principalResponse(): Response {
  return xmlResponse(
    `<d:multistatus xmlns:d="DAV:"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><d:current-user-principal><d:href>/principal/</d:href></d:current-user-principal></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`,
  );
}

function homeResponse(): Response {
  return xmlResponse(
    `<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><c:calendar-home-set><d:href>/calendars/</d:href></c:calendar-home-set></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`,
  );
}

function calendarsResponse(): Response {
  return xmlResponse(
    `<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/calendars/hospices/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/><c:calendar/></d:resourcetype><d:displayname>Hospices visits</d:displayname><c:supported-calendar-component-set><c:comp name="VEVENT"/></c:supported-calendar-component-set></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`,
  );
}

function context(): ExecutionContext {
  return {
    waitUntil() {
      // No background state is used by this test.
    },
    passThroughOnException() {
      // No-op test context.
    },
  } as unknown as ExecutionContext;
}

async function rpc(
  handler: ReturnType<typeof createMcpHandler>,
  body: unknown,
  environment: AppEnv,
): Promise<Response> {
  return handler(
    new Request("https://mcp.example/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify(body),
    }),
    environment,
    context(),
  );
}

async function sseJson(response: Response): Promise<unknown> {
  const body = await response.text();
  const dataLine = body.split("\n").find((line) => line.startsWith("data: "));
  if (!dataLine) throw new Error(`MCP response did not contain an SSE data frame: ${body}`);
  return JSON.parse(dataLine.slice("data: ".length)) as unknown;
}

async function callTool<T extends object = Record<string, unknown>>(
  handler: ReturnType<typeof createMcpHandler>,
  id: number,
  name: string,
  args: Record<string, unknown>,
  environment: AppEnv,
): Promise<T> {
  const response = await rpc(handler, {
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name, arguments: args },
  }, environment);
  expect(response.status).toBe(200);
  const payload = await sseJson(response) as { result?: { isError?: boolean; content?: Array<{ text?: string }> } };
  expect(payload.result?.isError).not.toBe(true);
  const text = payload.result?.content?.[0]?.text;
  if (!text) throw new Error(`MCP tool ${name} did not return JSON content`);
  return JSON.parse(text) as T;
}

describe("MCP email-to-calendar workflow regression", () => {
  it("chains the identified message and ticket into an ATTACH-enabled calendar event", async () => {
    const environment = testEnv();
    const ticket = new TextEncoder().encode("%PDF-1.7\nHospices de Beaune ticket\n");
    const ticketBase64 = encodeBase64(ticket);
    const rawMessage = [
      "From: Hospices de Beaune <bookings@hospices.example>",
      "To: owner@icloud.com",
      "Subject: Booking confirmation — Hospices de Beaune",
      "Date: Sun, 30 Aug 2026 09:00:00 GMT",
      "Message-ID: <booking-61514@hospices.example>",
      "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=mailboxer-workflow",
      "",
      "--mailboxer-workflow",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Visit date: 2026-09-14",
      "Visit time: 10:30 Europe/Paris",
      "Location: Hospices de Beaune",
      "--mailboxer-workflow",
      "Content-Type: application/pdf; name=\"hospices-ticket.pdf\"",
      "Content-Disposition: attachment; filename=\"hospices-ticket.pdf\"",
      "Content-Transfer-Encoding: base64",
      "",
      ticketBase64,
      "--mailboxer-workflow--",
      "",
    ].join("\r\n");
    const composed = { raw: new TextEncoder().encode(rawMessage) };
    const metadata: MessageMetadata = {
      uid,
      flags: [],
      size: composed.raw.byteLength,
      internalDate: "2026-08-30T09:00:00Z",
      subject: "Booking confirmation — Hospices de Beaune",
      from: [{ name: "Hospices de Beaune", address: "bookings@hospices.example" }],
      sender: [{ name: "Hospices de Beaune", address: "bookings@hospices.example" }],
      replyTo: [],
      to: [{ name: "", address: "owner@icloud.com" }],
      cc: [],
      bcc: [],
      inReplyTo: null,
      messageId: "<booking-61514@hospices.example>",
      attachments: [{
        part: attachmentPart,
        filename: "hospices-ticket.pdf",
        mimeType: "application/pdf",
        disposition: "attachment",
        encoding: "base64",
        size: ticket.byteLength,
      }],
    };
    const fetchMetadata = vi.fn(async (requestedMailbox: string, requestedUid: number) => {
      expect(requestedMailbox).toBe(mailbox);
      expect(requestedUid).toBe(uid);
      return metadata;
    });
    const fetchRaw = vi.fn(async (requestedMailbox: string, requestedUid: number, expectedSize?: number) => {
      expect(requestedMailbox).toBe(mailbox);
      expect(requestedUid).toBe(uid);
      expect(expectedSize).toBe(composed.raw.byteLength);
      return composed.raw;
    });
    const fetchBodyPart = vi.fn(async (requestedMailbox: string, requestedUid: number, part: string, expectedSize?: number) => {
      expect(requestedMailbox).toBe(mailbox);
      expect(requestedUid).toBe(uid);
      expect(part).toBe(attachmentPart);
      expect(expectedSize).toBe(ticket.byteLength);
      return new TextEncoder().encode(ticketBase64);
    });
    const imap = {
      fetchMetadata,
      fetchRaw,
      fetchBodyPart,
      close: vi.fn(),
    };
    const fromConfig = vi.spyOn(ImapClient, "fromConfig").mockResolvedValue(imap as unknown as ImapClient);

    const target = account(accountId, "iCloud", "owner@icloud.com", { mail: true, calendar: true, contacts: false }, "icloud");
    const fallback = account(fallbackAccountId, "Mail-only fallback", "fallback@example.com", { mail: true, calendar: false, contacts: false });
    const vault = await commitAccountDraft(environment, setDraftDefault(addDraftAccount(newAccountDraft(target), fallback), fallbackAccountId));
    const props: MailAuthProps = {
      userId: vault.userId,
      scopes: ["mail.read", "calendar.read", "calendar.write"],
    };
    const handler = createMcpHandler(
      () => createMailServer(environment, props),
      { route: "/mcp", legacy: "stateless", authContext: { props: { ...props } } },
    );

    const eventRaw = [
      "BEGIN:VCALENDAR",
      "VERSION:2.0",
      "PRODID:-//Mailboxer//Workflow Regression//EN",
      "BEGIN:VEVENT",
      "UID:hospices-61514@example.test",
      "DTSTAMP:20260831T080000Z",
      "DTSTART;TZID=Europe/Paris:20260914T103000",
      "DTEND;TZID=Europe/Paris:20260914T113000",
      "SUMMARY:Visit to Hospices de Beaune",
      "LOCATION:Hospices de Beaune\\, Rue de l'Hôtel-Dieu",
      "ATTACH;FMTTYPE=application/pdf;ENCODING=BASE64;VALUE=BINARY:" + ticketBase64,
      "END:VEVENT",
      "END:VCALENDAR",
      "",
    ].join("\r\n");
    const davCalls: Array<{ method: string; url: string; body: string }> = [];
    const davResponses = [principalResponse(), homeResponse(), calendarsResponse()];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const body = typeof init?.body === "string" ? init.body : "";
      const url = String(input);
      davCalls.push({ method, url, body });
      if (method === "PROPFIND") {
        const next = davResponses.shift();
        if (!next) throw new Error("DAV discovery transcript exhausted");
        return next;
      }
      if (method === "PUT") return new Response(null, { status: 204, headers: { ETag: '"created-event"' } });
      if (method === "GET") return new Response(eventRaw, { status: 200, headers: { ETag: '"created-event"' } });
      throw new Error(`Unexpected DAV method ${method}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    try {
      const message = await callTool<MessageResult>(handler, 1, "get_message", { accountId, mailbox, uid }, environment);
      expect(message.account).toMatchObject({ accountId });
      expect(message.metadata).toMatchObject({ uid, attachments: [{ part: attachmentPart, filename: "hospices-ticket.pdf" }] });
      expect(message.text).toContain("2026-09-14");
      expect(message.text).toContain("10:30 Europe/Paris");
      expect(message.text).toContain("Hospices de Beaune");
      expect(message.attachments).toEqual([expect.objectContaining({ part: attachmentPart, filename: "hospices-ticket.pdf", contentBase64: ticketBase64 })]);

      const attachment = await callTool<AttachmentResult>(handler, 2, "get_attachment", { accountId, mailbox, uid, part: attachmentPart }, environment);
      expect(attachment).toMatchObject({ account: { accountId }, uid, part: attachmentPart, filename: "hospices-ticket.pdf", contentBase64: ticketBase64, size: ticket.byteLength });
      expect(fetchMetadata).toHaveBeenCalledTimes(2);
      expect(fetchRaw).toHaveBeenCalledTimes(1);
      expect(fetchBodyPart).toHaveBeenCalledTimes(1);

      const calendars = await callTool<CalendarsResult>(handler, 3, "list_calendars", { accountId }, environment);
      expect(calendars.account).toMatchObject({ accountId });
      expect(calendars.calendars).toEqual([expect.objectContaining({
        href: "https://caldav.icloud.com/calendars/hospices/",
        displayName: "Hospices visits",
        componentTypes: ["VEVENT"],
      })]);
      const calendarHref = calendars.calendars[0].href as string;

      const created = await callTool<CalendarItemResult>(handler, 4, "create_calendar_item", {
        accountId,
        calendarHref,
        componentType: "VEVENT",
        rawIcalendar: eventRaw,
      }, environment);
      expect(created.account).toMatchObject({ accountId });
      expect(created).toMatchObject({
        componentType: "VEVENT",
        uid: "hospices-61514@example.test",
        start: "2026-09-14T10:30:00",
        end: "2026-09-14T11:30:00",
        location: "Hospices de Beaune, Rue de l'Hôtel-Dieu",
        rawIcalendar: eventRaw,
        requestedAttachmentPreserved: true,
      });

      expect(davCalls.filter((call) => call.method === "PROPFIND")).toHaveLength(3);
      const put = davCalls.find((call) => call.method === "PUT");
      expect(put?.url).toMatch(/^https:\/\/caldav\.icloud\.com\/calendars\/hospices\/[0-9a-f-]+\.ics$/u);
      expect(put?.body).toBe(eventRaw);
      expect(put?.body).toContain("ATTACH;FMTTYPE=application/pdf;ENCODING=BASE64;VALUE=BINARY:");
      expect(put?.body).toContain(ticketBase64);
      expect(davCalls.filter((call) => call.method === "GET")).toHaveLength(1);
      expect(davResponses).toHaveLength(0);
      expect(fromConfig).toHaveBeenCalledTimes(2);
      expect(fromConfig.mock.calls.every(([config]) => config.email === "owner@icloud.com")).toBe(true);
    } finally {
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
    }
  });
});
