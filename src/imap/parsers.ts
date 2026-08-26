import {
  asList,
  asString,
  decodeModifiedUtf7,
  parseImapValues,
  type ImapValue,
} from "./codec";
import type { AddressInfo, AttachmentPart, Mailbox, MessageMetadata } from "../types";

function stringValue(value: ImapValue | undefined): string | null {
  return asString(value);
}

function parseAddressList(value: ImapValue | undefined): AddressInfo[] {
  return asList(value).flatMap((entry) => {
    const address = asList(entry);
    const name = stringValue(address[0]) ?? "";
    const mailbox = stringValue(address[2]);
    const host = stringValue(address[3]);
    if (!mailbox) return [];
    return [{
      name,
      address: host ? `${mailbox}@${host}` : mailbox,
    }];
  });
}

function parameterMap(value: ImapValue | undefined): Map<string, string> {
  const parameters = asList(value);
  const result = new Map<string, string>();
  for (let index = 0; index + 1 < parameters.length; index += 2) {
    const key = stringValue(parameters[index]);
    const parameter = stringValue(parameters[index + 1]);
    if (key && parameter !== null) result.set(key.toUpperCase(), parameter);
  }
  return result;
}

function dispositionInfo(node: ImapValue[]): { type: string | null; parameters: Map<string, string> } {
  for (const candidate of node) {
    const list = asList(candidate);
    const type = stringValue(list[0]);
    if (type && (type.toUpperCase() === "ATTACHMENT" || type.toUpperCase() === "INLINE")) {
      return { type: type.toLowerCase(), parameters: parameterMap(list[1]) };
    }
  }
  return { type: null, parameters: new Map() };
}

function collectAttachmentParts(
  node: ImapValue,
  part: string,
  output: AttachmentPart[],
): void {
  const list = asList(node);
  if (!list.length) return;

  if (Array.isArray(list[0])) {
    let child = 0;
    while (child < list.length && Array.isArray(list[child])) {
      collectAttachmentParts(list[child], part ? `${part}.${child + 1}` : `${child + 1}`, output);
      child += 1;
    }
    return;
  }

  const type = stringValue(list[0])?.toLowerCase() ?? "application";
  const subtype = stringValue(list[1])?.toLowerCase() ?? "octet-stream";
  const parameters = parameterMap(list[2]);
  const disposition = dispositionInfo(list);
  const filename =
    disposition.parameters.get("FILENAME") ??
    parameters.get("NAME") ??
    null;
  const mimeType = `${type}/${subtype}`;
  const isTextWithoutFilename = type === "text" && !filename && !disposition.type;
  const shouldExpose = !isTextWithoutFilename || Boolean(disposition.type);
  if (shouldExpose) {
    const sizeText = stringValue(list[6]);
    const size = sizeText && /^\d+$/u.test(sizeText) ? Number(sizeText) : 0;
    const contentId = stringValue(list[3])?.replace(/^<|>$/gu, "");
    output.push({
      part: part || "1",
      filename,
      mimeType,
      disposition: disposition.type,
      encoding: stringValue(list[5])?.toLowerCase() ?? "binary",
      size,
      ...(contentId ? { contentId } : {}),
    });
  }
}

export function parseAttachmentParts(value: ImapValue | undefined): AttachmentPart[] {
  const output: AttachmentPart[] = [];
  if (value) collectAttachmentParts(value, "", output);
  return output;
}

export function parseListLine(line: string): Mailbox | null {
  const marker = line.match(/^\*\s+(?:LIST|LSUB)\s+([\s\S]+)$/iu);
  if (!marker) return null;
  const values = parseImapValues(marker[1]);
  const attributes = asList(values[0]).flatMap((value) => {
    const attribute = asString(value);
    return attribute ? [attribute] : [];
  });
  const delimiter = asString(values[1]);
  const encodedName = asString(values[2]);
  if (!encodedName) return null;
  const name = decodeModifiedUtf7(encodedName);
  const specialUse = attributes.find((attribute) => /^\\(?:sent|trash|junk|drafts|archive|all)$/iu.test(attribute));
  return {
    name,
    delimiter,
    attributes,
    ...(specialUse ? { specialUse } : {}),
  };
}

function valueMap(value: ImapValue | undefined): Map<string, ImapValue> {
  const list = asList(value);
  const map = new Map<string, ImapValue>();
  for (let index = 0; index + 1 < list.length; index += 2) {
    const key = asString(list[index]);
    if (key) map.set(key.toUpperCase(), list[index + 1]);
  }
  return map;
}

export function parseFetchMetadata(lines: string[]): MessageMetadata | null {
  const fetchStart = lines.findIndex((line) => /^\*\s+\d+\s+FETCH\s+/iu.test(line));
  if (fetchStart < 0) return null;
  const fetchLine = lines[fetchStart];
  const fetchIndex = fetchLine.toUpperCase().indexOf("FETCH");
  const responseText = lines
    .slice(fetchStart)
    .filter((line) => !/^[A-Z]\d+\s+(?:OK|NO|BAD)\b/iu.test(line))
    .join(" ");
  const values = parseImapValues(responseText.slice(fetchIndex + "FETCH".length).trim());
  const fields = valueMap(values[0]);
  const uidText = stringValue(fields.get("UID"));
  if (!uidText || !/^\d+$/u.test(uidText)) return null;
  const flags = asList(fields.get("FLAGS")).flatMap((flag) => {
    const value = asString(flag);
    return value ? [value] : [];
  });
  const sizeText = stringValue(fields.get("RFC822.SIZE"));
  const size = sizeText && /^\d+$/u.test(sizeText) ? Number(sizeText) : 0;
  const envelope = asList(fields.get("ENVELOPE"));
  return {
    uid: Number(uidText),
    flags,
    size,
    internalDate: stringValue(fields.get("INTERNALDATE")),
    subject: stringValue(envelope[1]),
    from: parseAddressList(envelope[2]),
    sender: parseAddressList(envelope[3]),
    replyTo: parseAddressList(envelope[4]),
    to: parseAddressList(envelope[5]),
    cc: parseAddressList(envelope[6]),
    bcc: parseAddressList(envelope[7]),
    inReplyTo: stringValue(envelope[8]),
    messageId: stringValue(envelope[9]),
    attachments: parseAttachmentParts(fields.get("BODYSTRUCTURE")),
  };
}

export function parseSearchResponse(lines: string[]): number[] {
  return lines
    .filter((candidate) => /^\*\s+SEARCH(?:\s|$)/iu.test(candidate))
    .flatMap((line) => line.replace(/^\*\s+SEARCH\s*/iu, "").trim().split(/\s+/u))
    .flatMap((value) => (/^\d+$/u.test(value) ? [Number(value)] : []));
}
