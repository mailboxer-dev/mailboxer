import { describe, expect, it } from "vitest";
import type { AppEnv } from "../src/types";
import worker from "../src/index";

const env = {
  OAUTH_KV: {} as KVNamespace,
  MAIL_CREDENTIALS_ENCRYPTION_KEY: "a-secure-test-encryption-key-with-32-chars",
} as unknown as AppEnv;

const context = {} as unknown as ExecutionContext;

describe("OAuth provider discovery", () => {
  it("advertises the protected resource and RFC 8414 endpoints", async () => {
    const unauthorized = await worker.fetch(new Request("https://mcp.example/mcp"), env, context);
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get("WWW-Authenticate")).toContain("oauth-protected-resource/mcp");

    const protectedResource = await worker.fetch(
      new Request("https://mcp.example/.well-known/oauth-protected-resource/mcp"),
      env,
      context,
    );
    expect(await protectedResource.json()).toMatchObject({
      resource: "https://mcp.example/mcp",
      authorization_servers: ["https://mcp.example"],
      scopes_supported: ["mail.read", "mail.write", "calendar.read", "calendar.write", "contacts.read", "contacts.write"],
    });

    const authorizationServer = await worker.fetch(
      new Request("https://mcp.example/.well-known/oauth-authorization-server"),
      env,
      context,
    );
    expect(await authorizationServer.json()).toMatchObject({
      issuer: "https://mcp.example",
      authorization_endpoint: "https://mcp.example/authorize",
      token_endpoint: "https://mcp.example/oauth/token",
      code_challenge_methods_supported: ["S256"],
    });
  });
});
