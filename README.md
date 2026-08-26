# iCloud Mail MCP on Cloudflare Workers

This project is a single, stateless Cloudflare Worker that exposes an authenticated MCP endpoint at `/mcp`. Every mail read, search, mutation, attachment fetch, SMTP delivery, and Sent-mail append uses a fresh live connection to iCloud Mail.

The Worker does not use Durable Objects, D1, R2, a search index, a mailbox cache, or a persistent IMAP/SMTP connection. `OAUTH_KV` is the only persistence: the OAuth provider uses it for clients, short-lived authorization state, grants, access tokens, and refresh tokens. Mail content never enters KV.

## Runtime and protocol

- IMAP: `imap.mail.me.com:993` over TLS.
- SMTP: `smtp.mail.me.com:587` with mandatory STARTTLS. Cloudflare Workers does not permit outbound port 25.
- Authentication: Cloudflare Access for SaaS / OIDC, bridged through `@cloudflare/workers-oauth-provider`.
- MCP: SDK v2 through `createMcpHandler` from `agents/mcp/server`.
- OAuth scopes: `mail.read`, `mail.write`, and `offline_access` for refresh-token clients.
- Pagination: descending IMAP UIDs with an explicit `beforeUid` cursor.
- Defaults: 50 messages/page, 2 MiB/message, 1 MiB/attachment, 10 attachments/message.

The WorkerEntrypoint creates a new MCP server factory for each authorized request. No `Mcp-Session-Id` is issued and no MCP transport/session state is persisted. Legacy MCP POST clients are served through the SDK v2 stateless compatibility lane; HTTP GET and DELETE are not session endpoints.

## MCP tools

| Tool | Scope | Behavior |
| --- | --- | --- |
| `list_mailboxes` | `mail.read` | Live `LIST`/`LSUB`, including `\\Sent` and `\\Trash` roles. |
| `list_messages` | `mail.read` | Bounded metadata page from a mailbox, using UID cursors. |
| `search_messages` | `mail.read` | Structured IMAP search filters: sender, recipient, subject, text, dates, unread, flagged, answered, and draft. |
| `get_message` | `mail.read` | Fetches one RFC822 message by UID and returns bounded parsed headers, text/HTML, and attachment data. |
| `get_attachment` | `mail.read` | Fetches one `BODY.PEEK[part]` attachment by UID and returns base64 content. |
| `set_message_flags` | `mail.write` | Adds/removes validated standard or keyword flags by UID. |
| `move_messages` | `mail.write` | Uses IMAP `MOVE`, or a UIDPLUS-safe copy/delete fallback. |
| `delete_messages` | `mail.write` | Moves to detected `\\Trash` by default. Permanent deletion requires `permanent: true` and UIDPLUS. |
| `send_email` | `mail.write` | Composes bounded RFC822, sends through SMTP STARTTLS, then appends the exact bytes to detected `\\Sent`. |

All write tools are annotated as non-read-only MCP actions. `send_email` reports `delivery` and `sentSaved` separately if SMTP succeeds but the Sent append fails.

## Local setup

```sh
npm install
npm run cf-typegen
cp .dev.vars.example .dev.vars
```

Fill `.dev.vars` with the Access/OIDC values and the iCloud account values. Use an Apple app-specific password, not the normal Apple Account password. Apple documents the iCloud Mail settings at [support.apple.com](https://support.apple.com/en-la/102525).

The checked-in Wrangler config contains a zero-valued KV ID so local Miniflare can start. Replace it before any real deployment:

```sh
npx wrangler kv namespace create OAUTH_KV
# Put the returned 32-character ID in wrangler.jsonc, binding OAUTH_KV.
```

Start the Worker:

```sh
npx wrangler dev
```

The unauthenticated health response is at `http://127.0.0.1:8787/` (Wrangler may choose another port). `/mcp` is protected and requires the OAuth configuration below. MCP Inspector can connect to the endpoint with:

```sh
npx @modelcontextprotocol/inspector http://127.0.0.1:8787/mcp
```

## Cloudflare Access and deployment

1. Create an Access for SaaS OIDC application for the Worker.
2. Add `https://<worker-hostname>/callback` as the upstream callback URL.
3. Copy the Access client ID, client secret, authorization URL, token URL, and JWKS URL.
4. Set `MCP_ALLOWED_EMAIL` to the exact same address as `ICLOUD_EMAIL`. The callback verifies the ID-token signature, issuer, audience, expiration, OIDC nonce, and this allowlist before creating a grant; mail access is intentionally limited to the configured mailbox owner.
5. Store secrets with Wrangler. The relevant names are:

   - `ACCESS_CLIENT_ID`
   - `ACCESS_CLIENT_SECRET`
   - `ACCESS_AUTHORIZATION_URL`
   - `ACCESS_TOKEN_URL`
   - `ACCESS_JWKS_URL`
   - `COOKIE_ENCRYPTION_KEY`
   - `MCP_ALLOWED_EMAIL`
   - `ICLOUD_EMAIL`
   - `ICLOUD_IMAP_USER`
   - `ICLOUD_APP_PASSWORD`

   For example:

```sh
npx wrangler secret put ACCESS_CLIENT_ID
npx wrangler secret put ACCESS_CLIENT_SECRET
npx wrangler secret put ACCESS_AUTHORIZATION_URL
npx wrangler secret put ACCESS_TOKEN_URL
npx wrangler secret put ACCESS_JWKS_URL
npx wrangler secret put COOKIE_ENCRYPTION_KEY
npx wrangler secret put MCP_ALLOWED_EMAIL
npx wrangler secret put ICLOUD_EMAIL
npx wrangler secret put ICLOUD_IMAP_USER
npx wrangler secret put ICLOUD_APP_PASSWORD
```

`ICLOUD_IMAP_USER` is commonly the iCloud local part; if Apple requires it for the account, use the full address. SMTP authentication always uses the full `ICLOUD_EMAIL` address in this Worker.

Validate the bundle without publishing:

```sh
npm run type-check
npm run lint
npm test
npx wrangler deploy --dry-run
```

After replacing the KV ID and setting the secrets, deploy with:

```sh
npx wrangler deploy
```

The OAuth provider publishes the standard authorization-server and protected-resource discovery documents. External MCP clients should be given the deployed `/mcp` URL and allowed to complete OAuth with PKCE/S256. Refresh tokens are generated and rotated by the OAuth provider; they are not handled by the mail code.

## Sending and deletion safety

`send_email` validates addresses and header values against CRLF/NUL injection, bounds all body and attachment inputs, emits no `Bcc` header, and dot-stuffs SMTP DATA lines. It delivers first and then uses IMAP `APPEND` to save the same RFC822 bytes to `\\Sent`.

`delete_messages` is intentionally soft by default: it detects the mailbox advertised with IMAP special-use `\\Trash` and moves messages there. Permanent deletion is a separate explicit path and is refused unless iCloud advertises UIDPLUS.

## Testing

The tests include transcript-backed fake sockets and cover:

- modified UTF-7 mailbox names;
- IMAP literals split at arbitrary chunk boundaries;
- tagged IMAP responses, UID sets, metadata parsing, and structured search escaping;
- MIME parsing, transfer decoding, attachment bounds, and header/address injection defenses;
- SMTP multiline replies, STARTTLS sequencing, authentication, and dot-stuffing;
- stateless MCP initialization/tool listing without `Mcp-Session-Id`;
- Access PKCE, nonce-bound state, signed callback cookies, ID-token issuer/signature validation, email allowlisting, per-token scope narrowing, and requested read/offline scopes.

Live iCloud testing should begin with read-only mailbox listing/search/message fetches. Before enabling general recipients, test `send_email` only to the owner address.

## Client availability

The endpoint is a normal remote MCP server and can be used by external MCP clients. OpenAI's current custom MCP app support is for ChatGPT Business, Enterprise, and Edu on the web; custom MCP apps are not available in native ChatGPT mobile apps. The Worker itself does not depend on a particular client.
