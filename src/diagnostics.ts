import type { TraceAttribute } from "./tracing";

export interface TraceSpanLike {
  setAttribute(name: string, value: TraceAttribute): void;
}

export interface SafeErrorDetails {
  type: string;
  message: string;
  status?: number;
}

function safeType(error: unknown): string {
  if (error instanceof Error && error.name.trim()) return error.name.trim().slice(0, 96);
  return "UnknownError";
}

function safeMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  const normalized = Array.from(raw, (character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 0x1f || code === 0x7f ? " " : character;
  }).join("").replace(/\s+/gu, " ").trim();
  const redacted = normalized
    .replace(/\bBasic\s+[A-Za-z0-9+/=_-]+/giu, "Basic [redacted]")
    .replace(/https?:\/\/[^\s"'<>]+/giu, "[redacted-url]")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu, "[redacted-email]")
    .replace(/\b[A-Za-z0-9]{4}(?:-[A-Za-z0-9]{4}){3}\b/gu, "[redacted-secret]")
    .replace(/\b(password|passcode|secret|token|authorization|credential)\b\s*[:=]\s*[^\s,;]+/giu, "$1=[redacted]");
  return (redacted || "Operation failed").slice(0, 256);
}

function safeStatus(error: unknown): number | undefined {
  if (!error || typeof error !== "object" || !("status" in error)) return undefined;
  const status = (error as { status?: unknown }).status;
  return typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599
    ? status
    : undefined;
}

export function describeError(error: unknown): SafeErrorDetails {
  const status = safeStatus(error);
  return {
    type: safeType(error),
    message: safeMessage(error),
    ...(status === undefined ? {} : { status }),
  };
}

export function annotateSpanFailure(span: TraceSpanLike, error: unknown): void {
  const details = describeError(error);
  span.setAttribute("error.type", details.type);
  span.setAttribute("error.message", details.message);
  if (details.status !== undefined) span.setAttribute("error.status_code", details.status);
}

export function logFailure(
  event: string,
  attributes: Readonly<Record<string, TraceAttribute>>,
  error: unknown,
): void {
  const details = describeError(error);
  console.error(JSON.stringify({
    event,
    ...attributes,
    error_type: details.type,
    error_message: details.message,
    ...(details.status === undefined ? {} : { error_status: details.status }),
  }));
}
