export function containsAsciiControl(value: string, allowTab = false): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0 || code === 127 || (code < 32 && (!allowTab || code !== 9))) return true;
  }
  return false;
}
