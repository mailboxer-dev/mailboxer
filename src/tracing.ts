import { tracing } from "cloudflare:workers";

export type TraceAttribute = boolean | number | string | undefined;
export type TraceAttributes = Readonly<Record<string, TraceAttribute>>;

export function withSpan<T>(
  name: string,
  attributes: TraceAttributes,
  operation: (span: Span) => T,
): T {
  return tracing.enterSpan(name, (span) => {
    for (const [key, value] of Object.entries(attributes)) {
      if (value !== undefined) span.setAttribute(key, value);
    }
    return operation(span);
  });
}

export function protocolCommandName(command: string): string {
  const tokens = command.trim().split(/\s+/u);
  const tokenCount = tokens[0]?.toUpperCase() === "UID" ? 2 : 1;
  return tokens.slice(0, tokenCount).join(" ").toUpperCase();
}
