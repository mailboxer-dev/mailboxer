# iCloud Mail, Calendar, and Contacts MCP on Cloudflare Workers

This project is a single, stateless Cloudflare Worker that exposes an authenticated MCP endpoint at `/mcp`. Every mail operation uses a fresh live IMAP/SMTP connection, and every calendar or contact operation uses a fresh live CalDAV/CardDAV HTTPS request to iCloud.

The Worker does not use Durable Objects, D1, R2, a search index, a mailbox/calendar/contact cache, DAV sync state, or a persistent protocol connection. `OAUTH_KV` stores only the bundled OAuth provider's clients, short-lived authorization state, grants, access tokens, and refresh tokens. `MAIL_CREDENTIALS_KV` stores encrypted per-account iCloud credentials. Mail, calendar, contact, and search data never enter KV.

## Runtime and protocol

- IMAP: `imap.mail.me.com:993` over TLS.
- SMTP: `smtp.mail.me.com:587` with mandatory STARTTLS. Cloudflare Workers does not permit outbound port 25.
- CalDAV: `https://caldav.icloud.com/` over HTTPS, with bounded principal/home-set/collection discovery and `PROPFIND`/`REPORT`/`GET`/`PUT`/`DELETE` requests.
- CardDAV: `https://contacts.icloud.com/` over HTTPS, with the same request-local discovery and bounds.
- Authentication: a bundled OAuth authorization page using `@cloudflare/workers-oauth-provider`; no external identity provider is required. The page collects each user's iCloud email and Apple app-specific password, verifies only the services requested by the grant, and stores the credentials encrypted in `MAIL_CREDENTIALS_KV`.
- MCP: SDK v2 through `createMcpHandler` from `agents/mcp/server`.
- OAuth scopes: `mail.read`, `mail.write`, `calendar.read`, `calendar.write`, `contacts.read`, `contacts.write`, and `offline_access` for refresh-token clients.
- Pagination: descending IMAP UIDs with an explicit `beforeUid` cursor.
- DAV pagination: sorted canonical hrefs with signed, versioned, stateless cursors containing only the service domain, query fingerprint, and last href.
- Defaults: 50 results/page, 2 MiB/message, 1 MiB/attachment, 512 KiB per calendar/contact resource, 4 MiB per DAV response, and 256 KiB per DAV request body.

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
| `list_calendars` | `calendar.read` | Discovers and lists live CalDAV calendars and supported `VEVENT`/`VTODO` types. |
| `list_calendar_items` | `calendar.read` | Queries live events/reminders with component, text, UTC date-range, href, limit, and signed cursor filters. |
| `get_calendar_item` | `calendar.read` | Fetches and parses one bounded live iCalendar resource. |
| `create_calendar_item` | `calendar.write` | Creates a `VEVENT` or `VTODO` from structured fields or an authoritative raw iCalendar body. |
| `update_calendar_item` | `calendar.write` | Updates with `If-Match` and a required current ETag. |
| `delete_calendar_item` | `calendar.write` | Deletes only with a current ETag and `confirm: "delete"`; DAV has no Trash mailbox. |
| `list_address_books` | `contacts.read` | Discovers and lists live CardDAV address books and vCard versions. |
| `list_contacts` | `contacts.read` | Queries live contacts with text, address-book, limit, and signed cursor filters. |
| `get_contact` | `contacts.read` | Fetches and parses one bounded live vCard resource. |
| `create_contact` | `contacts.write` | Creates a contact from structured fields or an authoritative raw vCard body. |
| `update_contact` | `contacts.write` | Updates with `If-Match` and a required current ETag. |
| `delete_contact` | `contacts.write` | Deletes only with a current ETag and `confirm: "delete"`. |

All write tools are annotated as non-read-only MCP actions. `send_email` reports `delivery` and `sentSaved` separately if SMTP succeeds but the Sent append fails. Calendar/contact resources return canonical href, ETag, UID, normalized common fields, and bounded original iCalendar/vCard text. Structured create/update fields are serialized as iCalendar 2.0 or vCard 3.0; a supplied raw body is authoritative after validation.

## Local setup

```sh
npm install
npm run cf-typegen
cp .dev.vars.example .dev.vars
```

Fill `.dev.vars` with a random `MAIL_CREDENTIALS_ENCRYPTION_KEY`. iCloud credentials are entered through the `/authorize` page, not Worker variables. Use an Apple app-specific password, not the normal Apple Account password. Apple documents the iCloud Mail settings at [support.apple.com](https://support.apple.com/en-us/102525). `CALDAV_URL` and `CARDDAV_URL` are optional and default to the iCloud service URLs above; they are restricted to approved HTTPS iCloud hosts.

The checked-in Wrangler config intentionally contains no account-specific KV IDs. Current Wrangler versions automatically provision the two KV namespaces for local development and deployment. This keeps forks and one-click deployments isolated to the deployer's Cloudflare account.

Start the Worker:

```sh
npx wrangler dev
```

The unauthenticated health response is at `http://127.0.0.1:8787/` (Wrangler may choose another port). `/mcp` is protected and requires the OAuth configuration below. MCP Inspector can connect to the endpoint with:

```sh
npx @modelcontextprotocol/inspector http://127.0.0.1:8787/mcp
```

## OAuth and deployment

The Worker is its own OAuth authorization server. When ChatGPT or another MCP client follows the protected-resource metadata, it opens `/authorize`. The Worker shows a local consent form, verifies the submitted iCloud account against only the selected services, encrypts the resulting credential record, and then delegates authorization-code, PKCE, access-token, refresh-token, and revocation handling to `@cloudflare/workers-oauth-provider`. The form displays all supported scopes; permissions disabled as “Not requested by this client” cannot be added to an existing OAuth request. Reconnect or reauthorize the MCP client after refreshing its OAuth metadata to request newly added scopes—OAuth refresh tokens cannot widen an existing grant.

Configure one high-entropy encryption secret and keep it out of Git:

```sh
npx wrangler secret put MAIL_CREDENTIALS_ENCRYPTION_KEY
```

Generate the encryption key with:

```sh
openssl rand -hex 32
```

The authorization form asks for the full iCloud email address and an Apple app-specific password. For a mail grant, the Worker tries the email local part and full email as the IMAP username, then uses the full email address for SMTP authentication. For calendar/contact-only grants, it verifies the requested CalDAV/CardDAV service without probing IMAP or SMTP. Credentials are encrypted with AES-GCM before being written to `MAIL_CREDENTIALS_KV`; OAuth props contain only an opaque credential ID and the granted resource scopes. Reauthorizing the same email overwrites its encrypted record. Rotating `MAIL_CREDENTIALS_ENCRYPTION_KEY` intentionally invalidates existing records, so every account must authorize again after a rotation.

Validate the bundle without publishing:

```sh
npm run type-check
npm run lint
npm test
npx wrangler deploy --dry-run
```

For a terminal deployment, set the one required Worker secret and deploy. Wrangler creates the KV namespaces because their IDs are omitted from `wrangler.jsonc`:

```sh
npx wrangler secret put MAIL_CREDENTIALS_ENCRYPTION_KEY
npx wrangler deploy
```

The OAuth provider publishes the standard authorization-server and protected-resource discovery documents. In ChatGPT web, add the deployed `/mcp` URL and select **OAuth**; the browser will show the Worker’s login page. Do not select **No Authentication**, because every resource tool is private. Refresh tokens are generated and rotated by the OAuth provider; they are not handled by the mail code.

## Observability

Invocation logs remain disabled. Workers Logs are enabled only for explicit structured failures and persist in the Cloudflare dashboard; the application emits no routine success or debug logs. Failure records include a bounded event, service/operation, error type, and protocol status where available, with credentials, email addresses, URLs, hrefs, message/calendar/contact content, and raw protocol responses redacted or omitted. Cloudflare tracing is enabled at a 100% head-sampling rate and persists traces in the Cloudflare dashboard. Cloudflare automatically instruments the Worker handler and KV calls; those binding spans (for example, successful KV operations) are trace telemetry rather than application logs and are intentionally retained. The Worker adds custom spans for MCP requests and tools, credential verification, IMAP/SMTP sessions, DAV discovery, each DAV request/report, resource parsing, protocol commands, and bounded message/resource/recipient counts and byte sizes. See Cloudflare’s [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/), [Workers tracing](https://developers.cloudflare.com/workers/observability/traces/), and [custom spans](https://developers.cloudflare.com/workers/observability/traces/custom-spans/) documentation.

## One-click Cloudflare deployment

Use the Cloudflare button to clone, configure, and deploy the Worker into your own Cloudflare account:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/antoninguyot/icloud-mail-mcp)

The source repository must be public for the button to work. This repository is currently private, so publish it before sharing the button with other users. Cloudflare’s flow clones the repository into the deployer’s GitHub or GitLab account, lets the deployer choose the Worker and resource names, automatically provisions `OAUTH_KV` and `MAIL_CREDENTIALS_KV`, and configures Workers Builds for later pushes. See the [Deploy to Cloudflare documentation](https://developers.cloudflare.com/workers/platform/deploy-buttons/).

The deployer supplies the one required secret when prompted. The DAV variables are already configured with safe iCloud defaults and normally need no changes:

| Binding | Configure at deploy time |
| --- | --- |
| `MAIL_CREDENTIALS_ENCRYPTION_KEY` | Generate a unique value with `openssl rand -hex 32`. |
| `OAUTH_KV` | Automatically provisioned; stores OAuth state and tokens only. |
| `MAIL_CREDENTIALS_KV` | Automatically provisioned; stores encrypted iCloud credentials only. |
| `CALDAV_URL` | Optional; defaults to `https://caldav.icloud.com/`. |
| `CARDDAV_URL` | Optional; defaults to `https://contacts.icloud.com/`. |

The binding descriptions in `package.json` and the example secret in `.dev.vars.example` are used to explain the deployment inputs. No iCloud email or app-specific password is required during deployment: each user enters their own credentials later on the Worker’s OAuth page.

After deployment, connect the deployed `https://<worker-name>.<account>.workers.dev/mcp` URL to the MCP client using **OAuth**. Do not select **No Authentication**: the mail, calendar, and contact tools are private.

## Sending and deletion safety

`send_email` validates addresses and header values against CRLF/NUL injection, bounds all body and attachment inputs, emits no `Bcc` header, and dot-stuffs SMTP DATA lines. It delivers first and then uses IMAP `APPEND` to save the same RFC822 bytes to `\\Sent`.

`delete_messages` is intentionally soft by default: it detects the mailbox advertised with IMAP special-use `\\Trash` and moves messages there. Permanent deletion is a separate explicit path and is refused unless iCloud advertises UIDPLUS. CalDAV/CardDAV deletes have no Trash equivalent, so they require both the current ETag and an explicit `confirm: "delete"` value.

## Testing

The tests include transcript-backed fake sockets and cover:

- modified UTF-7 mailbox names;
- IMAP literals split at arbitrary chunk boundaries;
- tagged IMAP responses, UID sets, metadata parsing, and structured search escaping;
- MIME parsing, transfer decoding, attachment bounds, and header/address injection defenses;
- SMTP multiline replies, STARTTLS sequencing, authentication, and dot-stuffing;
- DAV redirect allowlisting, Basic-auth isolation, principal/home-set discovery, CalDAV/CardDAV reports and multigets, per-resource multistatus errors, ETag conditional writes, HTTP failure mapping, bounded XML, and request/response bodies;
- iCalendar and vCard folding, escaping, Unicode, dates, VTODOs, recurrence preservation, and injection defenses;
- signed stateless DAV cursor validation and query mismatch rejection;
- stateless MCP initialization/tool listing without `Mcp-Session-Id`;
- OAuth PKCE, signed one-time state cookies, bounded authorization forms, conditional service verification, credential verification failures and retry limits, encrypted credential storage, per-token scope narrowing, and requested read/offline scopes.

Live iCloud testing should begin with read-only mailbox listing/search/message fetches. Before enabling general recipients, test `send_email` only to the owner address.

## Client availability

The endpoint is a normal remote MCP server and can be used by external MCP clients. OpenAI's current custom MCP app support is for ChatGPT Business, Enterprise, and Edu on the web; custom MCP apps are not available in native ChatGPT mobile apps. The Worker itself does not depend on a particular client.
