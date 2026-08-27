import { describe, expect, it } from "vitest";
import { child, parseXml, XmlParseError, xmlText } from "../src/dav/xml";

describe("bounded namespace-aware DAV XML parser", () => {
  it("decodes entities and CDATA while retaining namespaces", () => {
    const root = parseXml(`<d:multistatus xmlns:d="DAV:" xmlns:x="urn:test"><d:response><d:href><![CDATA[/a?x=1&y=2]]></d:href><x:value>one &amp; &#x1F600;</x:value></d:response></d:multistatus>`);
    expect(root.namespace).toBe("DAV:");
    const response = child(root, "response", "DAV:");
    expect(response).toBeDefined();
    expect(xmlText(child(response!, "href", "DAV:")!)).toBe("/a?x=1&y=2");
    expect(xmlText(child(response!, "value", "urn:test")!)).toBe("one & 😀");
  });

  it("rejects DTDs, external entities, malformed entities, and mismatched tags", () => {
    expect(() => parseXml("<!DOCTYPE foo [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><foo>&x;</foo>")).toThrow(XmlParseError);
    expect(() => parseXml("<foo>&not-an-entity;</foo>")).toThrow(XmlParseError);
    expect(() => parseXml("<foo>&unterminated</foo>")).toThrow(XmlParseError);
    expect(() => parseXml("<foo><bar></foo>")).toThrow(XmlParseError);
    expect(() => parseXml("<foo>&#0;</foo>")).toThrow(XmlParseError);
    expect(() => parseXml("<foo>bad\u0001</foo>")).toThrow(XmlParseError);
  });

  it("enforces depth and node bounds", () => {
    expect(() => parseXml("<a><b><c/></b></a>", { maxDepth: 2 })).toThrow(XmlParseError);
    expect(() => parseXml("<a><b/><c/></a>", { maxNodes: 2 })).toThrow(XmlParseError);
  });
});
