import { WorkerEntrypoint } from "cloudflare:workers";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import { credentialAuthHandler } from "./auth";
import { createMailServer } from "./mail-server";
import { withSpan } from "./tracing";
import { restrictPropsToTokenScope, RESOURCE_SCOPES, type AppEnv, type AuthProps } from "./types";

export class MailMcpApi extends WorkerEntrypoint<AppEnv, AuthProps> {
  fetch(request: Request): Promise<Response> {
    const props = this.ctx.props;
    const handler = createMcpHandler(
      () => createMailServer(this.env, props),
      {
        route: "/mcp",
        legacy: "stateless",
        authContext: { props: { ...props } },
      },
    );
    return withSpan(
      "mcp.request",
      {
        "http.request.method": request.method,
        "url.path": new URL(request.url).pathname,
      },
      () => handler(request, this.env, this.ctx),
    );
  }
}

export default new OAuthProvider<AppEnv>({
  apiRoute: "/mcp",
  apiHandler: MailMcpApi,
  defaultHandler: credentialAuthHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register",
  scopesSupported: [...RESOURCE_SCOPES, "offline_access"],
  allowPlainPKCE: false,
  refreshTokenTTL: 30 * 24 * 60 * 60,
  tokenExchangeCallback: async ({ props, requestedScope }) => ({
    accessTokenProps: restrictPropsToTokenScope(props, requestedScope),
  }),
  clientIdMetadataDocumentEnabled: true,
  resourceMetadata: {
    scopes_supported: [...RESOURCE_SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: "Email MCP server with Mail, Calendar, and Contacts access",
  },
});
