import { describe, expect, it } from "vitest";
import {
  buildDohRequest,
  createDnsQuery,
  DnsFormatError,
  encodeDnsName,
  encodeDnsQuery,
  isMxRecord,
  isSrvRecord,
  isTxtRecord,
  normalizeDnsName,
  parseDnsResponse,
  recordsOfType,
  selectSrvRecord,
  type DnsQuery,
  type DnsRecord,
  type SrvRecord,
} from "../src/discovery/dns";

const encoder = new TextEncoder();

function u16(value: number): number[] {
  return [(value >>> 8) & 0xff, value & 0xff];
}

function u32(value: number): number[] {
  return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
}

function concat(...parts: Array<Uint8Array | number[]>): Uint8Array {
  const arrays = parts.map((part) => part instanceof Uint8Array ? part : Uint8Array.from(part));
  const output = new Uint8Array(arrays.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of arrays) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

interface WireRecord {
  owner: Uint8Array;
  type: number;
  classCode?: number;
  ttl?: number;
  rdata: Uint8Array;
}

function wireRecord(record: WireRecord): Uint8Array {
  return concat(
    record.owner,
    u16(record.type),
    u16(record.classCode ?? 1),
    u32(record.ttl ?? 300),
    u16(record.rdata.length),
    record.rdata,
  );
}

function questionBytes(query: DnsQuery): Uint8Array {
  return query.packet.slice(12);
}

function responseFor(
  query: DnsQuery,
  records: WireRecord[] = [],
  options: {
    id?: number;
    flags?: number;
    question?: Uint8Array;
    authorities?: WireRecord[];
    additionals?: WireRecord[];
    questionCount?: number;
    trailing?: number[];
  } = {},
): Uint8Array {
  const authorities = options.authorities ?? [];
  const additionals = options.additionals ?? [];
  return concat(
    u16(options.id ?? query.id),
    u16(options.flags ?? 0x8180),
    u16(options.questionCount ?? 1),
    u16(records.length),
    u16(authorities.length),
    u16(additionals.length),
    options.question ?? questionBytes(query),
    ...records.map(wireRecord),
    ...authorities.map(wireRecord),
    ...additionals.map(wireRecord),
    options.trailing ?? [],
  );
}

function answerOwnerPointer(): Uint8Array {
  return Uint8Array.from([0xc0, 0x0c]);
}

function mxData(exchangeOffset = 12): Uint8Array {
  return concat(u16(10), [0xc0, exchangeOffset]);
}

function srvData(): Uint8Array {
  return concat(u16(10), u16(5), u16(587), [0xc0, 0x0c]);
}

function txtData(...values: string[]): Uint8Array {
  return concat(...values.map((value) => concat([encoder.encode(value).length], encoder.encode(value))));
}

function records(response: ReturnType<typeof parseDnsResponse>): DnsRecord[] {
  return [...response.answers, ...response.authorities, ...response.additionals];
}

describe("DNS wire codec for provider discovery", () => {
  it("constructs a deterministic recursive query and a binary DoH request", async () => {
    const query = createDnsQuery("_submission._tcp.example.com", "SRV", { id: 0x1234 });
    expect(query.id).toBe(0x1234);
    expect(query.name).toBe("_submission._tcp.example.com.");
    expect(query.question).toEqual({
      name: "_submission._tcp.example.com.",
      type: "SRV",
      typeCode: 33,
      classCode: 1,
    });
    expect(encodeDnsQuery("example.com", "MX", { id: 7 })).toEqual(createDnsQuery("example.com", "MX", { id: 7 }).packet);
    expect(Array.from(query.packet.slice(0, 12))).toEqual([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);

    const request = buildDohRequest(query, "https://resolver.example/dns-query");
    expect(request.method).toBe("POST");
    expect(request.url).toBe("https://resolver.example/dns-query");
    expect(request.redirect).toBe("manual");
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("accept")).toBe("application/dns-message");
    expect(request.headers.get("content-type")).toBe("application/dns-message");
    expect(request.headers.get("cache-control")).toBe("no-store");
    expect(new Uint8Array(await request.arrayBuffer())).toEqual(query.packet);
  });

  it("normalizes names, supports the root, and rejects oversized or unsafe labels", () => {
    expect(normalizeDnsName(" Example.COM. ")).toBe("example.com.");
    expect(normalizeDnsName(".")).toBe(".");
    expect(encodeDnsName(".")).toEqual(Uint8Array.from([0]));
    expect(() => encodeDnsName("a".repeat(64) + ".example")).toThrow(DnsFormatError);
    expect(() => encodeDnsName("example..com")).toThrow(DnsFormatError);
    expect(() => encodeDnsName("example\n.com")).toThrow(DnsFormatError);
    expect(() => encodeDnsName("a." + "b".repeat(253))).toThrow(DnsFormatError);
  });

  it("parses compressed MX, SRV, and TXT records with typed values", () => {
    const mxQuery = createDnsQuery("example.com", "MX", { id: 1 });
    const mxResponse = responseFor(mxQuery, [{
      owner: answerOwnerPointer(),
      type: 15,
      rdata: mxData(),
    }]);
    const mx = parseDnsResponse(mxResponse, mxQuery);
    expect(mx.flags.qr).toBe(true);
    expect(mx.flags.recursionAvailable).toBe(true);
    expect(mx.rcode).toBe(0);
    expect(mx.answers).toHaveLength(1);
    expect(isMxRecord(mx.answers[0])).toBe(true);
    expect(mx.answers[0]).toMatchObject({ name: "example.com.", preference: 10, exchange: "example.com.", section: "answer" });

    const srvQuery = createDnsQuery("_submission._tcp.example.com", "SRV", { id: 2 });
    const srvResponse = responseFor(srvQuery, [{
      owner: answerOwnerPointer(),
      type: 33,
      rdata: srvData(),
    }]);
    const srv = parseDnsResponse(srvResponse, srvQuery);
    expect(isSrvRecord(srv.answers[0])).toBe(true);
    expect(srv.answers[0]).toMatchObject({ priority: 10, weight: 5, port: 587, target: "_submission._tcp.example.com." });

    const txtQuery = createDnsQuery("example.com", "TXT", { id: 3 });
    const txtResponse = responseFor(txtQuery, [{
      owner: answerOwnerPointer(),
      type: 16,
      rdata: txtData("v=spf1 ", "~all"),
    }]);
    const txt = parseDnsResponse(txtResponse, txtQuery);
    expect(isTxtRecord(txt.answers[0])).toBe(true);
    expect(txt.answers[0]).toMatchObject({ strings: ["v=spf1 ", "~all"], text: "v=spf1 ~all" });
    const txtRecord = txt.answers.find(isTxtRecord);
    expect(txtRecord?.rawStrings.map((part) => new TextDecoder().decode(part))).toEqual(["v=spf1 ", "~all"]);
  });

  it("parses unknown records without losing their bounded RDATA", () => {
    const query = createDnsQuery("example.com", "TXT", { id: 4 });
    const response = parseDnsResponse(responseFor(query, [{
      owner: answerOwnerPointer(),
      type: 99,
      rdata: Uint8Array.from([1, 2, 3]),
    }]), query);
    expect(response.answers[0]).toMatchObject({ type: "UNKNOWN", typeCode: 99, rdataLength: 3 });
    expect((response.answers[0] as { rdata: Uint8Array }).rdata).toEqual(Uint8Array.from([1, 2, 3]));
  });

  it("validates response ID, response bit, opcode, question count, and question identity", () => {
    const query = createDnsQuery("example.com", "MX", { id: 5 });
    expect(() => parseDnsResponse(responseFor(query, [], { id: 6 }), query)).toThrow(/transaction ID/u);
    expect(() => parseDnsResponse(responseFor(query, [], { flags: 0x0100 }), query)).toThrow(/not a response/u);
    expect(() => parseDnsResponse(responseFor(query, [], { flags: 0x8900 }), query)).toThrow(/standard DNS/u);
    expect(() => parseDnsResponse(responseFor(query, [], { flags: 0x81c0 }), query)).toThrow(/reserved/u);
    expect(() => parseDnsResponse(responseFor(query, [], { questionCount: 0 }), query)).toThrow(/exactly one question/u);
    const differentQuestion = createDnsQuery("other.example", "MX", { id: query.id });
    expect(() => parseDnsResponse(responseFor(query, [], { question: questionBytes(differentQuestion) }), query)).toThrow(/does not match/u);
    const differentType = createDnsQuery("example.com", "TXT", { id: query.id });
    expect(() => parseDnsResponse(responseFor(query, [], { question: questionBytes(differentType) }), query)).toThrow(/does not match/u);
  });

  it("returns DNS errors and truncation as response metadata after validating the question", () => {
    const query = createDnsQuery("missing.example", "MX", { id: 6 });
    const response = parseDnsResponse(responseFor(query, [], { flags: 0x8383 }), query);
    expect(response.rcode).toBe(3);
    expect(response.flags.truncated).toBe(true);
    expect(response.answers).toEqual([]);
  });

  it("rejects malformed compression pointers, loops, forward references, and reserved labels", () => {
    const query = createDnsQuery("example.com", "MX", { id: 7 });
    const selfPointer = responseFor(query, [{
      owner: Uint8Array.from([0xc0, 0x2a]),
      type: 15,
      rdata: concat(u16(10), [0xc0, 0x0c]),
    }]);
    const selfPointerOffset = 12 + questionBytes(query).length;
    selfPointer[selfPointerOffset] = 0xc0;
    selfPointer[selfPointerOffset + 1] = selfPointerOffset;
    expect(() => parseDnsResponse(selfPointer, query)).toThrow(/pointer/u);

    const forwardPointer = responseFor(query, [{
      owner: Uint8Array.from([0xc0, 0xff]),
      type: 15,
      rdata: mxData(),
    }]);
    expect(() => parseDnsResponse(forwardPointer, query)).toThrow(/pointer/u);

    const reservedLabel = responseFor(query, [{
      owner: Uint8Array.from([0x40, 0x00]),
      type: 15,
      rdata: mxData(),
    }]);
    expect(() => parseDnsResponse(reservedLabel, query)).toThrow(/reserved/u);
  });

  it("rejects truncated records, invalid RDATA boundaries, trailing bytes, and preserves binary TXT", () => {
    const query = createDnsQuery("example.com", "MX", { id: 8 });
    const truncatedHeader = new Uint8Array(12);
    truncatedHeader[0] = 0;
    truncatedHeader[1] = 8;
    expect(() => parseDnsResponse(truncatedHeader, query)).toThrow(DnsFormatError);

    const invalidMx = responseFor(query, [{
      owner: answerOwnerPointer(),
      type: 15,
      rdata: Uint8Array.from([0, 10]),
    }]);
    expect(() => parseDnsResponse(invalidMx, query)).toThrow(/MX RDATA/u);
    expect(() => parseDnsResponse(responseFor(query, [], { trailing: [0] }), query)).toThrow(/trailing/u);

    const txtQuery = createDnsQuery("example.com", "TXT", { id: 9 });
    const binaryTxt = responseFor(txtQuery, [{
      owner: answerOwnerPointer(),
      type: 16,
      rdata: Uint8Array.from([2, 0xff, 0xff]),
    }]);
    const parsedBinaryTxt = parseDnsResponse(binaryTxt, txtQuery);
    const binaryRecord = parsedBinaryTxt.answers.find(isTxtRecord);
    expect(binaryRecord?.rawStrings).toEqual([Uint8Array.from([0xff, 0xff])]);
    expect(binaryRecord?.strings).toEqual(["��"]);
  });

  it("enforces packet, record, name, RDATA, and TXT bounds", () => {
    const query = createDnsQuery("example.com", "TXT", { id: 10 });
    const twoRecords = responseFor(query, [
      { owner: answerOwnerPointer(), type: 99, rdata: Uint8Array.from([1]) },
      { owner: answerOwnerPointer(), type: 99, rdata: Uint8Array.from([2]) },
    ]);
    expect(() => parseDnsResponse(twoRecords, query, { maxRecords: 1 })).toThrow(/too many records/u);
    expect(() => parseDnsResponse(twoRecords, query, { maxPacketBytes: twoRecords.length - 1 })).toThrow(/packet bound/u);
    expect(() => parseDnsResponse(twoRecords, query, { maxNameBytes: 3 })).toThrow(/name/u);

    const largeRdata = responseFor(query, [{
      owner: answerOwnerPointer(),
      type: 99,
      rdata: Uint8Array.from({ length: 10 }, (_, index) => index),
    }]);
    expect(() => parseDnsResponse(largeRdata, query, { maxRdataBytes: 5 })).toThrow(/RDATA/u);

    const largeTxt = responseFor(query, [{
      owner: answerOwnerPointer(),
      type: 16,
      rdata: txtData("123456"),
    }]);
    expect(() => parseDnsResponse(largeTxt, query, { maxTxtBytes: 5 })).toThrow(/TXT/u);
    expect(() => parseDnsResponse(largeTxt, query, { maxTxtStrings: 0 })).toThrow(/bounds/u);
    expect(() => parseDnsResponse(new Uint8Array(65_536), query)).toThrow(/packet/u);
  });

  it("rejects insecure or credential-bearing DoH endpoints", () => {
    const query = createDnsQuery("example.com", "MX", { id: 11 });
    expect(() => buildDohRequest(query, "http://resolver.example/dns-query")).toThrow(/HTTPS/u);
    expect(() => buildDohRequest(query, "https://user:pass@resolver.example/dns-query")).toThrow(/credentials/u);
    expect(() => buildDohRequest(query, "https://resolver.example/dns-query#fragment")).toThrow(/fragment/u);
  });

  it("selects SRV records by lowest priority and weighted randomness", () => {
    const makeSrv = (priority: number, weight: number, target: string): SrvRecord => ({
      name: "_submission._tcp.example.com.",
      classCode: 1,
      ttl: 300,
      type: "SRV",
      typeCode: 33,
      rdataLength: 0,
      section: "answer",
      priority,
      weight,
      port: 587,
      target,
    });
    const records = [
      makeSrv(10, 1, "one.example.com."),
      makeSrv(10, 3, "three.example.com."),
      makeSrv(20, 65_535, "never.example.com."),
    ];
    expect(selectSrvRecord(records, () => 0)?.target).toBe("one.example.com.");
    expect(selectSrvRecord(records, () => 0.3)?.target).toBe("three.example.com.");
    expect(selectSrvRecord(records, () => 0.99)?.target).toBe("three.example.com.");
    expect(selectSrvRecord([makeSrv(10, 0, "one.example.com."), makeSrv(10, 0, "two.example.com.")], () => 0.75)?.target).toBe("two.example.com.");
    expect(selectSrvRecord([], () => 0)).toBeNull();
    expect(() => selectSrvRecord(records, () => 1)).toThrow(/\[0, 1\)/u);
  });

  it("offers type guards and a typed record filter for a discovery orchestrator", () => {
    const query = createDnsQuery("example.com", "TXT", { id: 12 });
    const response = parseDnsResponse(responseFor(query, [
      { owner: answerOwnerPointer(), type: 16, rdata: txtData("one") },
      { owner: answerOwnerPointer(), type: 99, rdata: Uint8Array.from([1]) },
    ]), query);
    expect(recordsOfType(response.answers, "TXT")).toHaveLength(1);
    expect(records(response).filter(isTxtRecord)).toHaveLength(1);
    expect(records(response).filter(isMxRecord)).toHaveLength(0);
    expect(records(response).filter(isSrvRecord)).toHaveLength(0);
  });
});
