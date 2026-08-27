<img src="./ui/public/mailboxer-logo.png" alt="mailboxer" width="240">

# mailboxer

mailboxer connects your email, calendars, contacts, and reminders to any agent through an always-on MCP. It is designed for people who want to use their own accounts without deploying and configuring several separate services. iCloud works out of the box, and custom IMAP/SMTP accounts are supported for email.

## Deploy it yourself

Deploy mailboxer to your own Cloudflare account with the button below. Cloudflare provisions the Worker and its private storage; you only need to provide a unique encryption secret. Email credentials are added later through mailboxer’s sign-in page and are never committed to the repository.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mailboxer-dev/mailboxer)

## Technical overview

mailboxer is a stateless TypeScript Cloudflare Worker with a bundled OAuth server and MCP endpoint. It stores OAuth records and encrypted account settings in Cloudflare KV, while messages, searches, calendars, and contacts are always fetched live from IMAP, SMTP, CalDAV, or CardDAV. It uses no database, mailbox cache, search index, Durable Object, or persistent protocol connection.
