# iCloud Mail MCP on Cloudflare Workers

This project is a single, stateless Cloudflare Worker that exposes an authenticated MCP endpoint at `/mcp`. Every mail read, search, mutation, attachment fetch, SMTP delivery, and Sent-mail append uses a fresh live connection to iCloud Mail.

The Worker does not use Durable Objects, D1, R2, a search index, a mailbox cache, or a persistent IMAP/SMTP connection. `OAUTH_KV` stores only the bundled OAuth provider's clients, short-lived authorization state, grants, access tokens, and refresh tokens. `MAIL_CREDENTIALS_KV` stores encrypted per-account iCloud credentials. Mail content and search state never enter KV.

## Runtime and protocol

- IMAP: `imap.mail.me.com:993` over TLS.
- SMTP: `smtp.mail.me.com:587` with mandatory STARTTLS. Cloudflare Workers does not permit outbound port 25.
- Authentication: a bundled OAuth authorization page using `@cloudflare/workers-oauth-provider`; no external identity provider is required. The page collects each user's iCloud email and Apple app-specific password, verifies both IMAP and SMTP access, and stores the credentials encrypted in `MAIL_CREDENTIALS_KV`.
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

Fill `.dev.vars` with a random `MAIL_CREDENTIALS_ENCRYPTION_KEY`. iCloud credentials are entered through the `/authorize` page, not Worker variables. Use an Apple app-specific password, not the normal Apple Account password. Apple documents the iCloud Mail settings at [support.apple.com](https://support.apple.com/en-us/102525).

The checked-in Wrangler config is connected to the two KV namespaces for the maintained deployment. For a fork or a separate account, create both namespaces and replace the IDs before deploying:

```sh
npx wrangler kv namespace create OAUTH_KV
npx wrangler kv namespace create MAIL_CREDENTIALS_KV
# Put each returned 32-character ID in wrangler.jsonc under its matching binding.
```

Start the Worker:

```sh
npx wrangler dev
```

The unauthenticated health response is at `http://127.0.0.1:8787/` (Wrangler may choose another port). `/mcp` is protected and requires the OAuth configuration below. MCP Inspector can connect to the endpoint with:

```sh
npx @modelcontextprotocol/inspector http://127.0.0.1:8787/mcp
```

## OAuth and deployment

The Worker is its own OAuth authorization server. When ChatGPT or another MCP client follows the protected-resource metadata, it opens `/authorize`. The Worker shows a local consent form, verifies the submitted iCloud account by opening fresh IMAP and SMTP connections, encrypts the resulting credential record, and then delegates authorization-code, PKCE, access-token, refresh-token, and revocation handling to `@cloudflare/workers-oauth-provider`.

Configure one high-entropy encryption secret and keep it out of Git:

```sh
npx wrangler secret put MAIL_CREDENTIALS_ENCRYPTION_KEY
```

Generate the encryption key with:

```sh
openssl rand -hex 32
```

The authorization form asks for the full iCloud email address and an Apple app-specific password. The Worker tries the email local part and full email as the IMAP username, then uses the full email address for SMTP authentication. Credentials are encrypted with AES-GCM before being written to `MAIL_CREDENTIALS_KV`; OAuth props contain only an opaque credential ID and the granted mail scopes. Reauthorizing the same email overwrites its encrypted record. Rotating `MAIL_CREDENTIALS_ENCRYPTION_KEY` intentionally invalidates existing records, so every account must authorize again after a rotation.

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

The OAuth provider publishes the standard authorization-server and protected-resource discovery documents. In ChatGPT web, add the deployed `/mcp` URL and select **OAuth**; the browser will show the Worker’s login page. Do not select **No Authentication**, because every mail tool is private. Refresh tokens are generated and rotated by the OAuth provider; they are not handled by the mail code.

## One-click Cloudflare deployment

The repository includes Deploy to Cloudflare binding descriptions in `package.json` and a placeholder KV namespace ID. Cloudflare can provision the OAuth KV namespace and present the values from `.dev.vars.example` during deployment. See the [Deploy to Cloudflare documentation](https://developers.cloudflare.com/workers/platform/deploy-buttons/).

The source repository must be public for Cloudflare’s deploy button. Once this repository is published publicly, add this snippet to the project page:

```md
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/<owner>/icloud-mail-mcp)
```

The deployer supplies only the encryption key during deployment. Each user enters their own iCloud email and app-specific password on the Worker’s OAuth page. The deployed Worker then works with ChatGPT’s **OAuth** option without creating a separate Access application.

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
- OAuth PKCE, signed one-time state cookies, bounded authorization forms, credential verification failures and retry limits, encrypted credential storage, per-token scope narrowing, and requested read/offline scopes.

Live iCloud testing should begin with read-only mailbox listing/search/message fetches. Before enabling general recipients, test `send_email` only to the owner address.

## Client availability

The endpoint is a normal remote MCP server and can be used by external MCP clients. OpenAI's current custom MCP app support is for ChatGPT Business, Enterprise, and Edu on the web; custom MCP apps are not available in native ChatGPT mobile apps. The Worker itself does not depend on a particular client.
