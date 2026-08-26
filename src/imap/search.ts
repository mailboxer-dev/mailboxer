import { formatImapDate, quoteImapString } from "./codec";

export interface SearchFilters {
  from?: string;
  to?: string;
  subject?: string;
  text?: string;
  since?: string;
  before?: string;
  unread?: boolean;
  flagged?: boolean;
  answered?: boolean;
  draft?: boolean;
}

function bounded(value: string, field: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 256) throw new Error(`${field} must be 1-256 characters`);
  return trimmed;
}

function needsUtf8Charset(filters: SearchFilters): boolean {
  return [filters.from, filters.to, filters.subject, filters.text]
    .filter((value): value is string => value !== undefined)
    .some((value) => [...value].some((character) => character.charCodeAt(0) > 0x7f));
}

export function compileSearch(filters: SearchFilters): string {
  const criteria: string[] = [];
  if (filters.from !== undefined) criteria.push(`FROM ${quoteImapString(bounded(filters.from, "from"))}`);
  if (filters.to !== undefined) criteria.push(`TO ${quoteImapString(bounded(filters.to, "to"))}`);
  if (filters.subject !== undefined) {
    criteria.push(`SUBJECT ${quoteImapString(bounded(filters.subject, "subject"))}`);
  }
  if (filters.text !== undefined) criteria.push(`TEXT ${quoteImapString(bounded(filters.text, "text"))}`);
  if (filters.since !== undefined) criteria.push(`SINCE ${formatImapDate(filters.since)}`);
  if (filters.before !== undefined) criteria.push(`BEFORE ${formatImapDate(filters.before)}`);
  if (filters.unread !== undefined) criteria.push(filters.unread ? "UNSEEN" : "SEEN");
  if (filters.flagged !== undefined) criteria.push(filters.flagged ? "FLAGGED" : "UNFLAGGED");
  if (filters.answered !== undefined) criteria.push(filters.answered ? "ANSWERED" : "UNANSWERED");
  if (filters.draft !== undefined) criteria.push(filters.draft ? "DRAFT" : "UNDRAFT");
  if (!criteria.length) return "ALL";
  return `${needsUtf8Charset(filters) ? "CHARSET UTF-8 " : ""}${criteria.join(" ")}`;
}
