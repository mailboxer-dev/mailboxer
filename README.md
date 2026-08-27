# Email, Calendar, and Contacts MCP on Cloudflare Workers

This project is a single, stateless Cloudflare Worker that exposes an authenticated MCP endpoint at `/mcp`. Every mail operation uses a fresh live IMAP/SMTP connection for the selected account, and every calendar or contact operation uses a fresh live CalDAV/CardDAV HTTPS request for an iCloud account.

iCloud is the built-in provider preset. Each OAuth user can configure up to 10 accounts, using either the iCloud preset or a custom IMAP/SMTP provider. Account management is available only through the OAuth reconnect flow; there is no account-management MCP tool. Calls never fan out across accounts: select an account with `accountId`, or omit it to use the configured default.

The Worker does not use Durable Objects, D1, R2, a search index, a mailbox/calendar/contact cache, DAV sync state, or a persistent protocol connection. `OAUTH_KV` stores only the bundled OAuth provider's clients, short-lived authorization state, grants, access tokens, and refresh tokens. `MAIL_CREDENTIALS_KV` stores encrypted multi-account vaults and short-lived encrypted reconnect drafts. Mail, calendar, contact, and search data never enter KV.

## Runtime and protocol

- iCloud preset IMAP: `imap.mail.me.com:993` over implicit TLS.
- iCloud preset SMTP: `smtp.mail.me.com:587` with mandatory STARTTLS. Cloudflare Workers does not permit outbound port 25.
- iCloud preset CalDAV: `https://caldav.icloud.com/` over HTTPS, with bounded principal/home-set/collection discovery and `PROPFIND`/`REPORT`/`GET`/`PUT`/`DELETE` requests.
- iCloud preset CardDAV: `https://contacts.icloud.com/` over HTTPS, with the same request-local discovery and bounds.
- Custom mail providers: IMAP `993` with implicit TLS or `143` with mandatory STARTTLS; SMTP `465` with implicit TLS or `587`/`2525` with mandatory STARTTLS. Hostnames are validated and port 25 is rejected. Custom providers do not supply CalDAV or CardDAV endpoints.
- Authentication: a bundled OAuth server using `@cloudflare/workers-oauth-provider`; no external identity provider is required. Its React/shadcn authorization UI creates or manages account profiles, collects the selected provider credentials, verifies enabled services, and stores credentials encrypted in `MAIL_CREDENTIALS_KV`. Permissions are not shown as a second consent step: every supported scope requested by the OAuth client is granted automatically.
- MCP: SDK v2 through `createMcpHandler` from `agents/mcp/server`.
- OAuth scopes: `mail.read`, `mail.write`, `calendar.read`, `calendar.write`, `contacts.read`, `contacts.write`, and `offline_access` for refresh-token clients.
- Pagination: descending IMAP UIDs with an explicit `beforeUid` cursor.
- DAV pagination: sorted canonical hrefs with signed, versioned, stateless cursors containing only the service domain, query fingerprint, and last href.
- Defaults: 50 results/page, 2 MiB/message, 1 MiB/attachment, 512 KiB per calendar/contact resource, 4 MiB per DAV response, and 256 KiB per DAV request body.

The WorkerEntrypoint creates a new MCP server factory for each authorized request. No `Mcp-Session-Id` is issued and no MCP transport/session state is persisted. Legacy MCP POST clients are served through the SDK v2 stateless compatibility lane; HTTP GET and DELETE are not session endpoints.

## MCP tools

`list_accounts` returns the current OAuth user's account metadata. Every other tool accepts an optional `accountId`; when omitted, the default account is used. Account IDs are opaque and account operations are deliberately single-account—there is no cross-account fanout. Successful resource operations include a summary of the selected account.

| Tool | Scope | Behavior |
| --- | --- | --- |
| `list_accounts` | authenticated | Lists configured account summaries, capabilities, and the default account without contacting an upstream provider. |
| `list_mailboxes` | `mail.read` | Live `LIST`/`LSUB` on the selected account, including `\\Sent` and `\\Trash` roles where advertised. |
| `list_messages` | `mail.read` | Bounded metadata page from the selected account's mailbox, using UID cursors. |
| `search_messages` | `mail.read` | Structured IMAP search filters: sender, recipient, subject, text, dates, unread, flagged, answered, and draft. |
| `get_message` | `mail.read` | Fetches one RFC822 message by UID from the selected account and returns bounded parsed headers, text/HTML, and attachment data. |
| `get_attachment` | `mail.read` | Fetches one `BODY.PEEK[part]` attachment by UID from the selected account and returns base64 content. |
| `set_message_flags` | `mail.write` | Adds/removes validated standard or keyword flags by UID on the selected account. |
| `move_messages` | `mail.write` | Uses IMAP `MOVE`, or a UIDPLUS-safe copy/delete fallback, on the selected account. |
| `delete_messages` | `mail.write` | Moves to detected `\\Trash` by default. Permanent deletion requires `permanent: true` and UIDPLUS. |
| `send_email` | `mail.write` | Composes bounded RFC822, sends through the selected account's SMTP transport, then appends the exact bytes to detected `\\Sent`. |
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

## Accounts and providers

The OAuth wizard starts by asking which email address to configure. It recognizes `icloud.com`, `me.com`, and `mac.com` addresses as iCloud accounts and otherwise opens the custom IMAP/SMTP form; the provider can be overridden for custom-domain iCloud accounts. After the submitted credentials are verified, the Worker securely looks up the corresponding encrypted profile. It opens account management when that account already exists and starts a new profile when it does not. This avoids exposing account existence before credential verification.

Reconnect is the account-management entry point after authorization. It can add, edit, test, remove, and choose the default account; it cannot remove the final account. The MCP surface exposes account selection and account metadata only, not account credentials or management actions.

The iCloud preset uses an Apple app-specific password and provides the iCloud Mail, Calendar, and Contacts services. Its mail endpoints and DAV services are fixed to the iCloud service defaults documented above. Capabilities can be enabled per account, but a capability also requires the corresponding OAuth scope (`mail.*`, `calendar.*`, or `contacts.*`) in the current grant.

Custom profiles support mail only. Configure an IMAP and SMTP hostname, username, password, and one of these exact transport combinations:

| Service | Supported endpoint modes |
| --- | --- |
| IMAP | Port `993` with implicit TLS, or port `143` with mandatory STARTTLS |
| SMTP | Port `465` with implicit TLS, or port `587` or `2525` with mandatory STARTTLS |

Custom hosts must be public DNS hostnames; IP literals, local/internal names, controls, mismatched port/TLS pairs, and SMTP port 25 are rejected. SMTP authentication uses PLAIN or LOGIN only after TLS. Custom CalDAV/CardDAV endpoints are not supported; calendar and contact tools are available only for accounts using the iCloud preset.

The encrypted multi-account vault is stored in the existing `MAIL_CREDENTIALS_KV`. No mailbox, calendar, contact, search, or synchronization data is stored there. Existing legacy single-account records and grants remain usable; reconnect lazily migrates them into the multi-account profile without requiring a new upstream login.

## Local setup

```sh
npm install
npm run cf-typegen
cp .dev.vars.example .dev.vars
```

Fill `.dev.vars` with a random `MAIL_CREDENTIALS_ENCRYPTION_KEY`. Account credentials are entered through the `/authorize` page, not Worker variables. The iCloud preset uses an Apple app-specific password, not the normal Apple Account password. Custom profiles use their own IMAP/SMTP credentials. Apple documents the iCloud Mail settings at [support.apple.com](https://support.apple.com/en-us/102525). `CALDAV_URL` and `CARDDAV_URL` are optional deployment-level iCloud discovery overrides; they do not enable custom DAV endpoints for custom accounts.

The checked-in Wrangler config intentionally contains no account-specific KV IDs. Current Wrangler versions automatically provision the two KV namespaces for local development and deployment. This keeps forks and one-click deployments isolated to the deployer's Cloudflare account.

Start the Worker:

```sh
npm run dev
```

The unauthenticated health response is at `http://127.0.0.1:8787/` (Wrangler may choose another port). `/mcp` is protected and requires the OAuth configuration below. MCP Inspector can connect to the endpoint with:

```sh
npx @modelcontextprotocol/inspector http://127.0.0.1:8787/mcp
```

## OAuth and deployment

The Worker is its own OAuth authorization server. When ChatGPT or another MCP client follows the protected-resource metadata, it opens `/authorize`. The React setup screen asks for an email address first, detects the likely provider, verifies the enabled services, and automatically opens the matching profile or starts a new one. It encrypts the resulting account vault and then delegates authorization-code, PKCE, access-token, refresh-token, and revocation handling to `@cloudflare/workers-oauth-provider`. The page does not expose permission controls: the Worker grants every supported scope included in the client's authorization request. Reconnect or reauthorize after the client refreshes its OAuth metadata to request newly added scopes, because refresh tokens cannot widen an existing grant.

Configure one high-entropy encryption secret and keep it out of Git:

```sh
npx wrangler secret put MAIL_CREDENTIALS_ENCRYPTION_KEY
```

Generate the encryption key with:

```sh
openssl rand -hex 32
```

The authorization form asks for the selected provider's credentials. For the iCloud preset, it asks for the full iCloud email address and an Apple app-specific password, and verifies only the enabled services. For custom profiles, it verifies the configured IMAP and SMTP endpoints after their required TLS handshake. Credentials are encrypted with AES-GCM before being written to the existing `MAIL_CREDENTIALS_KV`; OAuth props contain only an opaque user identity and granted resource scopes. Rotating `MAIL_CREDENTIALS_ENCRYPTION_KEY` intentionally invalidates existing vault records, so every account must be authorized again after a rotation.

Validate the bundle without publishing:

```sh
npm run type-check
npm run lint
npm test
npm run deploy:dry
```

For a terminal deployment, set the one required Worker secret and deploy. Wrangler creates the KV namespaces because their IDs are omitted from `wrangler.jsonc`:

```sh
npx wrangler secret put MAIL_CREDENTIALS_ENCRYPTION_KEY
npm run deploy
```

The OAuth provider publishes the standard authorization-server and protected-resource discovery documents. In ChatGPT web, add the deployed `/mcp` URL and select **OAuth**; the browser will show the Worker’s login page. Do not select **No Authentication**, because every resource tool is private. Refresh tokens are generated and rotated by the OAuth provider; they are not handled by the mail code.

## Observability

Invocation logs remain disabled. Workers Logs are enabled only for explicit structured failures and persist in the Cloudflare dashboard; the application emits no routine success or debug logs. Failure records include a bounded event, service/operation, error type, and protocol status where available, with credentials, email addresses, URLs, hrefs, message/calendar/contact content, and raw protocol responses redacted or omitted. Cloudflare tracing is enabled at a 100% head-sampling rate and persists traces in the Cloudflare dashboard. Cloudflare automatically instruments the Worker handler and KV calls; those binding spans (for example, successful KV operations) are trace telemetry rather than application logs and are intentionally retained. The Worker adds custom spans for MCP requests and tools, credential verification, IMAP/SMTP sessions, DAV discovery, each DAV request/report, resource parsing, protocol commands, and bounded message/resource/recipient counts and byte sizes. See Cloudflare’s [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/), [Workers tracing](https://developers.cloudflare.com/workers/observability/traces/), and [custom spans](https://developers.cloudflare.com/workers/observability/traces/custom-spans/) documentation.

Trace data includes only provider preset, capability, TLS-mode, and account-count metadata; it excludes account IDs, usernames, endpoint hosts, addresses, credentials, and message/calendar/contact content.

## One-click Cloudflare deployment

Use the Cloudflare button to clone, configure, and deploy the Worker into your own Cloudflare account:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/antoninguyot/icloud-mail-mcp)

The source repository must be public for the button to work. This repository is currently private, so publish it before sharing the button with other users. Cloudflare’s flow clones the repository into the deployer’s GitHub or GitLab account, lets the deployer choose the Worker and resource names, automatically provisions `OAUTH_KV` and `MAIL_CREDENTIALS_KV`, and configures Workers Builds for later pushes. See the [Deploy to Cloudflare documentation](https://developers.cloudflare.com/workers/platform/deploy-buttons/).

The deployer supplies the one required secret when prompted. Account credentials are collected later through OAuth, so no iCloud or custom-provider credentials are needed during deployment. The DAV variables are already configured with safe iCloud defaults and normally need no changes:

| Binding | Configure at deploy time |
| --- | --- |
| `MAIL_CREDENTIALS_ENCRYPTION_KEY` | Generate a unique value with `openssl rand -hex 32`. |
| `OAUTH_KV` | Automatically provisioned; stores OAuth state and tokens only. |
| `MAIL_CREDENTIALS_KV` | Automatically provisioned; stores the encrypted multi-account vault only. |
| `CALDAV_URL` | Optional; defaults to `https://caldav.icloud.com/`. |
| `CARDDAV_URL` | Optional; defaults to `https://contacts.icloud.com/`. |

The binding descriptions in `package.json` and the example secret in `.dev.vars.example` are used to explain the deployment inputs. No iCloud email or app-specific password is required during deployment: each user enters their own credentials later on the Worker's OAuth page.

Custom IMAP/SMTP hostnames and credentials are entered per account in that OAuth flow; they are not additional Wrangler variables or secrets. There is no custom DAV configuration and no additional KV namespace, database, Durable Object, R2 bucket, or cache.

After deployment, connect the deployed `https://<worker-name>.<account>.workers.dev/mcp` URL to the MCP client using **OAuth**. Do not select **No Authentication**: the mail, calendar, and contact tools are private.

## Sending and deletion safety

`send_email` validates addresses and header values against CRLF/NUL injection, bounds all body and attachment inputs, emits no `Bcc` header, and dot-stuffs SMTP DATA lines. It uses the selected account's SMTP transport, delivers first, and then uses that account's IMAP `APPEND` to save the same RFC822 bytes to `\\Sent`.

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
- multi-account selection, default-account routing, account summaries, custom IMAP/SMTP endpoint validation, reconnect-only account management, legacy-record migration, and absence of cross-account fanout;
- stateless MCP initialization/tool listing without `Mcp-Session-Id`;
- OAuth PKCE, signed one-time state cookies, bounded authorization forms, automatic granting of all client-requested supported scopes, conditional service verification, credential verification failures and retry limits, encrypted credential storage, and per-token scope narrowing.

Live iCloud testing should begin with read-only mailbox listing/search/message fetches. Before enabling general recipients, test `send_email` only to the owner address.

## Client availability

The endpoint is a normal remote MCP server and can be used by external MCP clients. OpenAI's current custom MCP app support is for ChatGPT Business, Enterprise, and Edu on the web; custom MCP apps are not available in native ChatGPT mobile apps. The Worker itself does not depend on a particular client.
