import { createMcpHandler } from "agents/mcp/server";
import { describe, expect, it } from "vitest";
import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { createMailServer, TOOL_NAMES } from "../src/mail-server";
import type { AppEnv, MailAuthProps } from "../src/types";

function testEnv(): AppEnv {
  return {
    OAUTH_KV: {} as KVNamespace,
    MAIL_CREDENTIALS_KV: {} as KVNamespace,
    OAUTH_PROVIDER: {} as OAuthHelpers,
    IMAP_HOST: "imap.mail.me.com",
    IMAP_PORT: "993",
    SMTP_HOST: "smtp.mail.me.com",
    SMTP_PORT: "587",
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

async function rpc(handler: ReturnType<typeof createMcpHandler>, body: unknown): Promise<Response> {
  return handler(
    new Request("https://mcp.example/mcp", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify(body),
    }),
    testEnv(),
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
    expect(initialization.result?.serverInfo?.name).toBe("icloud-mail-mcp");

    const tools = await rpc(handler, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    expect(tools.status).toBe(200);
    expect(tools.headers.get("Mcp-Session-Id")).toBeNull();
    const listing = await sseJson(tools) as { result?: { tools?: Array<{ name: string }> } };
    expect(listing.result?.tools?.map((tool) => tool.name)).toEqual([...TOOL_NAMES]);
  });
});

async function sseJson(response: Response): Promise<unknown> {
  const body = await response.text();
  const dataLine = body.split("\n").find((line) => line.startsWith("data: "));
  if (!dataLine) throw new Error(`MCP response did not contain an SSE data frame: ${body}`);
  return JSON.parse(dataLine.slice("data: ".length)) as unknown;
}
