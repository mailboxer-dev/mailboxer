import { annotateSpanFailure, logFailure } from "../diagnostics";
import { withSpan } from "../tracing";
import {
  buildDohRequest,
  createDnsQuery,
  DnsFormatError,
  parseDnsResponse,
  recordsOfType,
  selectSrvRecord,
  type DnsRecordType,
  type MxRecord,
  type SrvRecord,
  type TxtRecord,
} from "./dns";
import type { DiscoveryFetcher } from "./types";

const MAX_DNS_RESPONSE_BYTES = 65_535;
const DNS_TIMEOUT_MS = 5_000;

export interface DnsLookupResult {
  rcode: number;
  mx: MxRecord[];
  srv: SrvRecord[];
  txt: TxtRecord[];
}

async function boundedDnsBody(response: Response): Promise<Uint8Array> {
  const declared = Number(response.headers.get("Content-Length") ?? "");
  if (Number.isFinite(declared) && declared > MAX_DNS_RESPONSE_BYTES) {
    if (response.body) await response.body.cancel().catch(() => undefined);
    throw new DnsFormatError("DNS response is too large");
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
      if (total > MAX_DNS_RESPONSE_BYTES) {
        await reader.cancel();
        throw new DnsFormatError("DNS response is too large");
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

export async function lookupDns(
  name: string,
  type: DnsRecordType,
  fetcher: DiscoveryFetcher = globalThis.fetch,
): Promise<DnsLookupResult> {
  return withSpan("account.discovery.dns", { "discovery.dns_type": type }, async (span) => {
    const query = createDnsQuery(name, type);
    try {
      const request = buildDohRequest(query);
      const response = await fetcher(request, { signal: AbortSignal.timeout(DNS_TIMEOUT_MS) });
      span.setAttribute("discovery.http_status", response.status);
      if (response.status !== 200 || response.redirected) {
        if (response.body) await response.body.cancel().catch(() => undefined);
        throw new DnsFormatError("DNS-over-HTTPS request failed");
      }
      const contentType = response.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
      if (contentType !== "application/dns-message") {
        if (response.body) await response.body.cancel().catch(() => undefined);
        throw new DnsFormatError("DNS-over-HTTPS returned an unexpected content type");
      }
      const body = await boundedDnsBody(response);
      const parsed = parseDnsResponse(body, query, {
        maxPacketBytes: MAX_DNS_RESPONSE_BYTES,
        maxRecords: 64,
        maxRdataBytes: 4_096,
        maxTxtBytes: 2_048,
        maxTxtStrings: 16,
      });
      span.setAttribute("discovery.response_bytes", body.byteLength);
      span.setAttribute("discovery.dns_rcode", parsed.rcode);
      if (parsed.flags.truncated) throw new DnsFormatError("DNS response was truncated");
      if (parsed.rcode !== 0 && parsed.rcode !== 3) throw new DnsFormatError(`DNS lookup failed with response code ${parsed.rcode}`);
      return {
        rcode: parsed.rcode,
        mx: recordsOfType(parsed.answers, "MX"),
        srv: recordsOfType(parsed.answers, "SRV"),
        txt: recordsOfType(parsed.answers, "TXT"),
      };
    } catch (error) {
      annotateSpanFailure(span, error);
      logFailure("account_dns_discovery_failed", { dns_type: type }, error);
      throw error;
    }
  });
}

export async function optionalDnsLookup(
  name: string,
  type: DnsRecordType,
  fetcher: DiscoveryFetcher,
): Promise<DnsLookupResult> {
  try {
    return await lookupDns(name, type, fetcher);
  } catch {
    return { rcode: 2, mx: [], srv: [], txt: [] };
  }
}

export function selectedSrv(records: readonly SrvRecord[], random: () => number): SrvRecord | undefined {
  const usable = records.filter((record) => record.target !== ".");
  return selectSrvRecord(usable, random) ?? undefined;
}
