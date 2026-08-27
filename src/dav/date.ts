function daysInMonth(year: number, month: number): number {
  if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

export function isIsoDate(value: string): boolean {
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/u);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  return month >= 1 && month <= 12 && day >= 1 && day <= daysInMonth(year, month);
}

export function isIsoDateTime(value: string): boolean {
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?(Z|[+-]\d{2}:?\d{2})?$/u);
  if (!match || !isIsoDate(`${match[1]}-${match[2]}-${match[3]}`)) return false;
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6] ?? "0");
  if (hour > 23 || minute > 59 || second > 59) return false;
  if (!match[7] || match[7] === "Z") return true;
  const offset = match[7].slice(1).replace(":", "");
  return Number(offset.slice(0, 2)) <= 23 && Number(offset.slice(2)) <= 59;
}

export function isIsoDateOrDateTime(value: string): boolean {
  return isIsoDate(value) || isIsoDateTime(value);
}

export function isUtcIsoDateOrDateTime(value: string): boolean {
  if (isIsoDate(value)) return true;
  return isIsoDateTime(value) && /(?:Z|[+-]\d{2}:?\d{2})$/u.test(value);
}
