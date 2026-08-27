const DEFAULT_MAX_DEPTH = 32;
const DEFAULT_MAX_NODES = 20_000;

export interface XmlNode {
  qName: string;
  localName: string;
  namespace: string | null;
  attributes: Record<string, string>;
  children: XmlNode[];
  text: string;
}

export class XmlParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "XmlParseError";
  }
}

export interface XmlParseOptions {
  maxDepth?: number;
  maxNodes?: number;
}

function isWhitespace(value: string): boolean {
  return /\s/u.test(value);
}

function isNameStart(value: string): boolean {
  return /[A-Za-z_:]/u.test(value);
}

function isNameCharacter(value: string): boolean {
  return /[A-Za-z0-9_.:-]/u.test(value);
}

function isValidXmlCharacter(codePoint: number): boolean {
  return codePoint === 0x9 || codePoint === 0xa || codePoint === 0xd ||
    (codePoint >= 0x20 && codePoint <= 0xd7ff) ||
    (codePoint >= 0xe000 && codePoint <= 0xfffd) ||
    (codePoint >= 0x10000 && codePoint <= 0x10ffff);
}

function splitName(value: string): { prefix: string | null; localName: string } {
  const separator = value.indexOf(":");
  return separator < 0
    ? { prefix: null, localName: value }
    : { prefix: value.slice(0, separator), localName: value.slice(separator + 1) };
}

function decodeEntity(value: string): string {
  let cursor = 0;
  let result = "";
  while (cursor < value.length) {
    const ampersand = value.indexOf("&", cursor);
    if (ampersand < 0) return result + value.slice(cursor);
    result += value.slice(cursor, ampersand);
    const semicolon = value.indexOf(";", ampersand + 1);
    if (semicolon < 0) throw new XmlParseError("Unterminated XML entity");
    const token = value.slice(ampersand + 1, semicolon);
    if (token === "amp") result += "&";
    else if (token === "apos") result += "'";
    else if (token === "gt") result += ">";
    else if (token === "lt") result += "<";
    else if (token === "quot") result += '"';
    else if (/^#(?:x[0-9A-Fa-f]+|\d+)$/u.test(token)) {
      const radix = token.startsWith("#x") ? 16 : 10;
      const digits = token.startsWith("#x") ? token.slice(2) : token.slice(1);
      const codePoint = Number.parseInt(digits, radix);
      const validXmlCharacter = codePoint === 0x9 || codePoint === 0xa || codePoint === 0xd || (codePoint >= 0x20 && codePoint <= 0xd7ff) || (codePoint >= 0xe000 && codePoint <= 0xfffd) || (codePoint >= 0x10000 && codePoint <= 0x10ffff);
      if (!Number.isSafeInteger(codePoint) || !validXmlCharacter) throw new XmlParseError("Invalid XML character reference");
      result += String.fromCodePoint(codePoint);
    } else {
      throw new XmlParseError("Unsupported XML entity");
    }
    cursor = semicolon + 1;
  }
  return result;
}

function skipWhitespace(source: string, index: number): number {
  let cursor = index;
  while (cursor < source.length && isWhitespace(source[cursor] ?? "")) cursor += 1;
  return cursor;
}

function readName(source: string, index: number): { name: string; next: number } {
  if (!isNameStart(source[index] ?? "")) throw new XmlParseError("Invalid XML name");
  let cursor = index + 1;
  while (cursor < source.length && isNameCharacter(source[cursor] ?? "")) cursor += 1;
  return { name: source.slice(index, cursor), next: cursor };
}

function findTagEnd(source: string, index: number): number {
  let quote: string | null = null;
  for (let cursor = index; cursor < source.length; cursor += 1) {
    const character = source[cursor];
    if (quote) {
      if (character === quote) quote = null;
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (character === ">") {
      return cursor;
    }
  }
  throw new XmlParseError("Unterminated XML tag");
}

function parseStartTag(source: string, start: number, end: number): {
  qName: string;
  attributes: Record<string, string>;
  selfClosing: boolean;
} {
  let cursor = skipWhitespace(source, start);
  const elementName = readName(source, cursor);
  cursor = elementName.next;
  const attributes: Record<string, string> = {};
  let selfClosing = false;
  while (cursor < end) {
    cursor = skipWhitespace(source, cursor);
    if (cursor >= end) break;
    if (source[cursor] === "/") {
      selfClosing = true;
      cursor = skipWhitespace(source, cursor + 1);
      if (cursor !== end) throw new XmlParseError("Invalid XML self-closing tag");
      break;
    }
    const attributeName = readName(source, cursor);
    cursor = skipWhitespace(source, attributeName.next);
    if (source[cursor] !== "=") throw new XmlParseError("XML attribute is missing an equals sign");
    cursor = skipWhitespace(source, cursor + 1);
    const quote = source[cursor];
    if (quote !== '"' && quote !== "'") throw new XmlParseError("XML attribute is missing quotes");
    const valueStart = cursor + 1;
    const valueEnd = source.indexOf(quote, valueStart);
    if (valueEnd < 0 || valueEnd > end) throw new XmlParseError("Unterminated XML attribute");
    if (attributeName.name in attributes) throw new XmlParseError("Duplicate XML attribute");
    attributes[attributeName.name] = decodeEntity(source.slice(valueStart, valueEnd));
    cursor = valueEnd + 1;
  }
  return { qName: elementName.name, attributes, selfClosing };
}

export function parseXml(source: string, options: XmlParseOptions = {}): XmlNode {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxNodes = options.maxNodes ?? DEFAULT_MAX_NODES;
  if (source.length === 0) throw new XmlParseError("XML response is empty");
  for (const character of source) {
    if (!isValidXmlCharacter(character.codePointAt(0) ?? 0)) throw new XmlParseError("XML contains an invalid character");
  }
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/iu.test(source)) throw new XmlParseError("XML DTDs are not supported");

  const stack: Array<{ node: XmlNode; namespaces: Map<string, string> }> = [];
  let root: XmlNode | null = null;
  let cursor = 0;
  let nodes = 0;

  while (cursor < source.length) {
    const tagStart = source.indexOf("<", cursor);
    if (tagStart < 0) {
      const text = decodeEntity(source.slice(cursor));
      if (text.trim() && !stack.length) throw new XmlParseError("Text outside XML root");
      if (stack.length) stack[stack.length - 1].node.text += text;
      break;
    }
    const text = decodeEntity(source.slice(cursor, tagStart));
    if (text.trim() && !stack.length) throw new XmlParseError("Text outside XML root");
    if (stack.length) stack[stack.length - 1].node.text += text;

    if (source.startsWith("<!--", tagStart)) {
      const commentEnd = source.indexOf("-->", tagStart + 4);
      if (commentEnd < 0) throw new XmlParseError("Unterminated XML comment");
      cursor = commentEnd + 3;
      continue;
    }
    if (source.startsWith("<?", tagStart)) {
      const instructionEnd = source.indexOf("?>", tagStart + 2);
      if (instructionEnd < 0) throw new XmlParseError("Unterminated XML processing instruction");
      cursor = instructionEnd + 2;
      continue;
    }
    if (source.startsWith("<![CDATA[", tagStart)) {
      const cdataEnd = source.indexOf("]]>", tagStart + 9);
      if (cdataEnd < 0) throw new XmlParseError("Unterminated XML CDATA section");
      if (!stack.length) throw new XmlParseError("CDATA outside XML root");
      stack[stack.length - 1].node.text += source.slice(tagStart + 9, cdataEnd);
      cursor = cdataEnd + 3;
      continue;
    }
    if (source.startsWith("<!", tagStart)) throw new XmlParseError("Unsupported XML declaration");

    const tagEnd = findTagEnd(source, tagStart + 1);
    if (source[tagStart + 1] === "/") {
      const closing = source.slice(tagStart + 2, tagEnd).trim();
      if (!/^[A-Za-z_:][A-Za-z0-9_.:-]*$/u.test(closing)) throw new XmlParseError("Invalid XML closing tag");
      const current = stack.pop();
      if (!current || current.node.qName !== closing) throw new XmlParseError("Mismatched XML closing tag");
      cursor = tagEnd + 1;
      continue;
    }

    const parsed = parseStartTag(source, tagStart + 1, tagEnd);
    nodes += 1;
    if (nodes > maxNodes) throw new XmlParseError("XML response contains too many nodes");
    if (stack.length + 1 > maxDepth) throw new XmlParseError("XML response is too deeply nested");
    const namespaces = new Map(stack.at(-1)?.namespaces ?? []);
    for (const [name, value] of Object.entries(parsed.attributes)) {
      if (name === "xmlns") namespaces.set("", value);
      else if (name.startsWith("xmlns:")) namespaces.set(name.slice(6), value);
    }
    const name = splitName(parsed.qName);
    const node: XmlNode = {
      qName: parsed.qName,
      localName: name.localName,
      namespace: namespaces.get(name.prefix ?? "") ?? null,
      attributes: Object.fromEntries(Object.entries(parsed.attributes).filter(([key]) => key !== "xmlns" && !key.startsWith("xmlns:"))),
      children: [],
      text: "",
    };
    if (stack.length) stack[stack.length - 1].node.children.push(node);
    else if (root) throw new XmlParseError("XML contains multiple roots");
    else root = node;
    if (!parsed.selfClosing) stack.push({ node, namespaces });
    cursor = tagEnd + 1;
  }

  if (stack.length) throw new XmlParseError("XML root is not closed");
  if (!root) throw new XmlParseError("XML response has no root");
  return root;
}

export function xmlText(node: XmlNode): string {
  return `${node.text}${node.children.map(xmlText).join("")}`;
}

export function child(node: XmlNode, localName: string, namespace?: string): XmlNode | undefined {
  return node.children.find((candidate) => candidate.localName === localName && (namespace === undefined || candidate.namespace === namespace));
}

export function children(node: XmlNode, localName: string, namespace?: string): XmlNode[] {
  return node.children.filter((candidate) => candidate.localName === localName && (namespace === undefined || candidate.namespace === namespace));
}
