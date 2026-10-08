import { createMcpHandler } from "agents/mcp/server";
import { describe, expect, it, vi } from "vitest";
import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { commitAccountDraft, newAccountDraft } from "../src/accounts";
import { storeMailCredentials } from "../src/credentials";
import { createMailServer, TOOL_NAMES } from "../src/mail-server";
import type { AppEnv, MailAuthProps } from "../src/types";

class MemoryKv {
  private readonly values = new Map<string, string>();

  async put(key: string, value: string): Promise<void> {
    this.values.set(key, value);
  }

  async get(key: string, type?: "json"): Promise<unknown> {
    const value = this.values.get(key);
    if (value === undefined) return null;
    return type === "json" ? JSON.parse(value) as unknown : value;
  }

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }
}

function testEnv(kv: KVNamespace = new MemoryKv() as unknown as KVNamespace): AppEnv {
  return {
    OAUTH_KV: kv,
    OAUTH_PROVIDER: {} as OAuthHelpers,
    MAIL_CREDENTIALS_ENCRYPTION_KEY: "a-secure-test-encryption-key-with-32-chars",
  };
}

const props: MailAuthProps = {
  userId: "icloud-test-id",
  credentialId: "icloud-test-id",
  scopes: ["mail.read", "mail.write"],
};

function context(): ExecutionContext {
  return {
    waitUntil() {
      // The handler has no background state to persist.
    },
    passThroughOnException() {
      // No-op test context.
    },
  } as unknown as ExecutionContext;
}

async function rpc(handler: ReturnType<typeof createMcpHandler>, body: unknown, environment = testEnv()): Promise<Response> {
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

describe("stateless MCP handler", () => {
  it("creates a fresh server per request and never emits an MCP session ID", async () => {
    const handler = createMcpHandler(
      () => createMailServer(testEnv(), props),
      { route: "/mcp", legacy: "stateless", authContext: { props: { ...props } } },
    );
    const initialized = await rpc(handler, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "stateless-test", version: "1.0.0" },
      },
    });
    expect(initialized.status).toBe(200);
    expect(initialized.headers.get("Mcp-Session-Id")).toBeNull();
    const initialization = await sseJson(initialized) as { result?: { serverInfo?: { name?: string } } };
    expect(initialization.result?.serverInfo?.name).toBe("email-mcp");

    const tools = await rpc(handler, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    expect(tools.status).toBe(200);
    expect(tools.headers.get("Mcp-Session-Id")).toBeNull();
    const listing = await sseJson(tools) as { result?: { tools?: Array<{ name: string }> } };
    expect(listing.result?.tools?.map((tool) => tool.name)).toEqual([...TOOL_NAMES]);
  });

  it("advertises DAV tool annotations and enforces dedicated scopes", async () => {
    const handler = createMcpHandler(
      () => createMailServer(testEnv(), props),
      { route: "/mcp", legacy: "stateless", authContext: { props: { ...props } } },
    );
    const listing = await sseJson(await rpc(handler, { jsonrpc: "2.0", id: 3, method: "tools/list", params: {} })) as {
      result?: { tools?: Array<{ name: string; annotations?: Record<string, unknown> }> };
    };
    const tools = listing.result?.tools ?? [];
    expect(tools.find((tool) => tool.name === "get_account")?.annotations).toMatchObject({ readOnlyHint: true });
    expect(tools.find((tool) => tool.name === "send_email")?.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, openWorldHint: true });
    expect(tools.find((tool) => tool.name === "list_calendars")?.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false });
    expect(tools.find((tool) => tool.name === "create_calendar_item")?.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false });
    expect(tools.find((tool) => tool.name === "delete_contact")?.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true });

    const mailOnlyHandler = createMcpHandler(
      () => createMailServer(testEnv(), props),
      { route: "/mcp", legacy: "stateless", authContext: { props: { ...props, scopes: ["mail.read"] } } },
    );
    const denied = await sseJson(await rpc(mailOnlyHandler, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "list_calendars", arguments: {} },
    })) as { result?: { isError?: boolean; content?: Array<{ text?: string }> } };
    expect(denied.result?.isError).toBe(true);
    expect(denied.result?.content?.[0]?.text).toContain("Missing required scope: calendar.read");
  });

  it("omits account selection and returns the connected account", async () => {
    const kv = new MemoryKv();
    const environment = testEnv(kv as unknown as KVNamespace);
    const configured = {
      accountId: "acct_aaaaaaaaaaaaaaaaaaaaaa",
      label: "Personal",
      preset: "icloud" as const,
      address: "owner@icloud.com",
      capabilities: { mail: true, calendar: true, contacts: true },
      config: {
        email: "owner@icloud.com",
        imapUser: "owner",
        password: "app-password",
        imapHost: "imap.mail.me.com",
        imapPort: 993,
        imapTlsMode: "implicit" as const,
        smtpHost: "smtp.mail.me.com",
        smtpPort: 587,
        smtpTlsMode: "starttls" as const,
        smtpUser: "owner@icloud.com",
        smtpPassword: "app-password",
      },
    };
    const record = await commitAccountDraft(environment, newAccountDraft(configured));
    const accountProps = { userId: record.userId, accountVersion: 3 as const, scopes: ["mail.read", "calendar.read", "contacts.read"] };
    const handler = createMcpHandler(
      () => createMailServer(environment, accountProps),
      { route: "/mcp", legacy: "stateless", authContext: { props: { ...accountProps } } },
    );
    const listing = await sseJson(await rpc(handler, { jsonrpc: "2.0", id: 20, method: "tools/list", params: {} }, environment)) as {
      result?: { tools?: Array<{ name: string; inputSchema?: { properties?: Record<string, unknown> } }> };
    };
    for (const tool of listing.result?.tools ?? []) {
      expect(tool.inputSchema?.properties ?? {}).not.toHaveProperty("accountId");
    }

    const response = await rpc(handler, {
      jsonrpc: "2.0",
      id: 21,
      method: "tools/call",
      params: { name: "get_account", arguments: {} },
    }, environment);
    const result = await sseJson(response) as { result?: { content?: Array<{ text?: string }> } };
    const value = JSON.parse(result.result?.content?.[0]?.text ?? "{}") as { accountId?: string; label?: string };
    expect(value.accountId).toBe(configured.accountId);
    expect(value.label).toBe("Personal");
    expect(JSON.stringify(value)).not.toContain("app-password");
  });

  it("invokes a DAV tool through the stateless handler with the encrypted credential record", async () => {
    const kv = new MemoryKv();
    const environment = testEnv(kv as unknown as KVNamespace);
    const draft = (await import("../src/accounts")).findAccountDraftByEmail;
    await storeMailCredentials(environment, { email: "owner@icloud.com", imapUser: "owner", appPassword: "app-password" });
    const saved = await draft(environment, "owner@icloud.com");
    const record = await commitAccountDraft(environment, saved!);
    const userProps: MailAuthProps = { userId: record.userId, accountVersion: 3, scopes: ["calendar.read"] };
    const responses = [
      new Response(`<d:multistatus xmlns:d="DAV:"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><d:current-user-principal><d:href>/principal/</d:href></d:current-user-principal></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
      new Response(`<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/principal/</d:href><d:propstat><d:prop><c:calendar-home-set><d:href>/calendars/</d:href></c:calendar-home-set></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
      new Response(`<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:response><d:href>/calendars/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/><c:calendar/></d:resourcetype><d:displayname>Personal</d:displayname></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`),
    ];
    const fetchMock = vi.fn(async () => {
      const next = responses.shift();
      if (!next) throw new Error("DAV transcript exhausted");
      return next;
    });
    vi.stubGlobal("fetch", fetchMock);
    try {
      const handler = createMcpHandler(
        () => createMailServer(environment, userProps),
        { route: "/mcp", legacy: "stateless", authContext: { props: { ...userProps } } },
      );
      const response = await rpc(handler, {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: { name: "list_calendars", arguments: {} },
      }, environment);
      expect(response.status).toBe(200);
      expect(response.headers.get("Mcp-Session-Id")).toBeNull();
      const result = await sseJson(response) as { result?: { isError?: boolean; content?: Array<{ text?: string }> } };
      expect(result.result?.isError).not.toBe(true);
      expect(result.result?.content?.[0]?.text).toContain("Personal");
      expect(fetchMock).toHaveBeenCalledTimes(3);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

async function sseJson(response: Response): Promise<unknown> {
  const body = await response.text();
  const dataLine = body.split("\n").find((line) => line.startsWith("data: "));
  if (!dataLine) throw new Error(`MCP response did not contain an SSE data frame: ${body}`);
  return JSON.parse(dataLine.slice("data: ".length)) as unknown;
}
