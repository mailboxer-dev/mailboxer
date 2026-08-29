import { annotateSpanFailure, logFailure } from "../diagnostics";
import { withSpan } from "../tracing";
import type { DiscoveryFetcher } from "./types";

export const MAX_DISCOVERY_RESPONSE_BYTES = 256 * 1024;
const MAX_DISCOVERY_REDIRECTS = 3;
const DISCOVERY_TIMEOUT_MS = 5_000;

export class DiscoveryHttpError extends Error {
  readonly status: number | undefined;
  readonly expectedMiss: boolean;

  constructor(message: string, status?: number, expectedMiss = false) {
    super(message);
    this.name = "DiscoveryHttpError";
    this.status = status;
    this.expectedMiss = expectedMiss;
  }
}

export function publicHttpsUrl(value: string | URL): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new DiscoveryHttpError("Discovery returned an invalid URL");
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/u, "");
  const validHostname = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(hostname);
  if (
    url.protocol !== "https:"
    || url.username
    || url.password
    || url.hash
    || (url.port && url.port !== "443")
    || !validHostname
    || /^(?:localhost|\d{1,3}(?:\.\d{1,3}){3})$/u.test(hostname)
    || /(?:^|\.)(?:local|internal|home|lan|test|invalid)$/u.test(hostname)
  ) {
    throw new DiscoveryHttpError("Discovery returned an unsafe URL");
  }
  url.hostname = hostname;
  return url;
}

async function discard(response: Response): Promise<void> {
  if (response.body) await response.body.cancel().catch(() => undefined);
}

async function boundedBytes(response: Response): Promise<Uint8Array> {
  const declared = Number(response.headers.get("Content-Length") ?? "");
  if (Number.isFinite(declared) && declared > MAX_DISCOVERY_RESPONSE_BYTES) {
    await discard(response);
    throw new DiscoveryHttpError("Discovery response is too large");
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > MAX_DISCOVERY_RESPONSE_BYTES) {
        await reader.cancel();
        throw new DiscoveryHttpError("Discovery response is too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

export interface DiscoveryHttpResponse {
  url: URL;
  status: number;
  headers: Headers;
  body: Uint8Array;
  redirects: number;
}

export async function discoveryFetch(
  source: string,
  target: URL,
  fetcher: DiscoveryFetcher = globalThis.fetch,
  accept = "application/xml, text/xml;q=0.9, */*;q=0.1",
): Promise<DiscoveryHttpResponse> {
  return withSpan("account.discovery.http", { "discovery.source": source }, async (span) => {
    let redirects = 0;
    try {
      let url = publicHttpsUrl(target);
      while (true) {
        const response = await fetcher(url, {
          method: "GET",
          headers: {
            Accept: accept,
            "Cache-Control": "no-store",
            "User-Agent": "mailboxer/0.1",
          },
          cache: "no-store",
          redirect: "manual",
          signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
        });
        span.setAttribute("discovery.http_status", response.status);
        if (response.status >= 300 && response.status < 400) {
          if (redirects >= MAX_DISCOVERY_REDIRECTS) {
            await discard(response);
            throw new DiscoveryHttpError("Discovery redirected too many times");
          }
          const location = response.headers.get("Location");
          await discard(response);
          if (!location) throw new DiscoveryHttpError("Discovery redirect omitted its destination");
          url = publicHttpsUrl(new URL(location, url));
          redirects += 1;
          continue;
        }
        if (response.status === 404 || response.status === 410) {
          await discard(response);
          throw new DiscoveryHttpError("Discovery settings were not found", response.status, true);
        }
        if (response.status < 200 || response.status >= 300) {
          await discard(response);
          throw new DiscoveryHttpError("Discovery request failed", response.status);
        }
        const body = await boundedBytes(response);
        span.setAttribute("discovery.response_bytes", body.byteLength);
        span.setAttribute("discovery.redirect_count", redirects);
        return { url, status: response.status, headers: response.headers, body, redirects };
      }
    } catch (error) {
      annotateSpanFailure(span, error);
      if (!(error instanceof DiscoveryHttpError && error.expectedMiss)) {
        logFailure("account_discovery_request_failed", { source, redirect_count: redirects }, error);
      }
      throw error;
    }
  });
}

export function decodeDiscoveryText(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new DiscoveryHttpError("Discovery response is not valid UTF-8");
  }
}

export async function resolveDavWellKnown(
  source: string,
  target: URL,
  fetcher: DiscoveryFetcher = globalThis.fetch,
): Promise<URL | undefined> {
  return withSpan("account.discovery.dav_well_known", { "discovery.source": source }, async (span) => {
    let url = publicHttpsUrl(target);
    let redirects = 0;
    try {
      while (true) {
        const response = await fetcher(url, {
          method: "GET",
          headers: { Accept: "application/xml, */*;q=0.1", "Cache-Control": "no-store", "User-Agent": "mailboxer/0.1" },
          cache: "no-store",
          redirect: "manual",
          signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
        });
        span.setAttribute("discovery.http_status", response.status);
        if (response.status >= 300 && response.status < 400) {
          if (redirects >= MAX_DISCOVERY_REDIRECTS) {
            await discard(response);
            throw new DiscoveryHttpError("DAV discovery redirected too many times");
          }
          const location = response.headers.get("Location");
          await discard(response);
          if (!location) throw new DiscoveryHttpError("DAV discovery redirect omitted its destination");
          url = publicHttpsUrl(new URL(location, url));
          redirects += 1;
          continue;
        }
        const advertised = response.headers.has("DAV");
        await discard(response);
        span.setAttribute("discovery.redirect_count", redirects);
        if (response.status === 404 || response.status === 410) return undefined;
        if ([401, 403, 405, 207].includes(response.status) || (response.status >= 200 && response.status < 300 && (advertised || redirects > 0))) {
          return url;
        }
        return undefined;
      }
    } catch (error) {
      annotateSpanFailure(span, error);
      logFailure("account_dav_discovery_failed", { source, redirect_count: redirects }, error);
      return undefined;
    }
  });
}
