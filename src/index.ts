import { WorkerEntrypoint } from "cloudflare:workers";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import { credentialAuthHandler } from "./auth";
import { createMailServer } from "./mail-server";
import { restrictMailPropsToTokenScope, type AppEnv, type MailAuthProps } from "./types";

export class MailMcpApi extends WorkerEntrypoint<AppEnv, MailAuthProps> {
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
    return handler(request, this.env, this.ctx);
  }
}

export default new OAuthProvider<AppEnv>({
  apiRoute: "/mcp",
  apiHandler: MailMcpApi,
  defaultHandler: credentialAuthHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register",
  scopesSupported: ["mail.read", "mail.write", "offline_access"],
  allowPlainPKCE: false,
  refreshTokenTTL: 30 * 24 * 60 * 60,
  tokenExchangeCallback: async ({ props, requestedScope }) => ({
    accessTokenProps: restrictMailPropsToTokenScope(props, requestedScope),
  }),
  clientIdMetadataDocumentEnabled: true,
  resourceMetadata: {
    scopes_supported: ["mail.read", "mail.write"],
    bearer_methods_supported: ["header"],
    resource_name: "iCloud Mail MCP server",
  },
});
