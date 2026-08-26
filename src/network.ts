export interface SocketLike {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): void;
  startTls(): SocketLike;
  opened?: Promise<unknown>;
  closed?: Promise<unknown>;
}

function appendBytes(left: Uint8Array<ArrayBufferLike>, right: Uint8Array<ArrayBufferLike>): Uint8Array<ArrayBufferLike> {
  const merged = new Uint8Array(left.length + right.length);
  merged.set(left);
  merged.set(right, left.length);
  return merged;
}

export class SocketConnection {
  private socket: SocketLike;
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private buffer: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  private closed = false;

  constructor(socket: SocketLike) {
    this.socket = socket;
    this.reader = socket.readable.getReader();
    this.writer = socket.writable.getWriter();
  }

  async writeBytes(bytes: Uint8Array): Promise<void> {
    await this.writer.write(bytes);
  }

  async writeText(value: string): Promise<void> {
    await this.writeBytes(new TextEncoder().encode(value));
  }

  private async pull(): Promise<void> {
    const result = await this.reader.read();
    if (result.done || !result.value) throw new Error("Remote socket closed");
    this.buffer = appendBytes(this.buffer, result.value);
  }

  async readLine(maxBytes = 256 * 1024): Promise<string> {
    while (true) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline >= 0) {
        const line = this.buffer.slice(0, newline);
        this.buffer = this.buffer.slice(newline + 1);
        const withoutCr = line[line.length - 1] === 0x0d ? line.slice(0, -1) : line;
        return new TextDecoder().decode(withoutCr);
      }
      if (this.buffer.length > maxBytes) throw new Error("Protocol line exceeds the safety limit");
      await this.pull();
    }
  }

  async readExactly(length: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(length) || length < 0) throw new Error("Invalid socket read length");
    while (this.buffer.length < length) await this.pull();
    const bytes = this.buffer.slice(0, length);
    this.buffer = this.buffer.slice(length);
    return bytes;
  }

  async discardExactly(length: number): Promise<void> {
    if (!Number.isSafeInteger(length) || length < 0) throw new Error("Invalid socket discard length");
    let remaining = length;
    while (remaining > 0) {
      if (!this.buffer.length) await this.pull();
      const amount = Math.min(remaining, this.buffer.length);
      this.buffer = this.buffer.slice(amount);
      remaining -= amount;
    }
  }

  async startTls(): Promise<void> {
    this.reader.releaseLock();
    this.writer.releaseLock();
    const upgraded = this.socket.startTls();
    if (upgraded.opened) await upgraded.opened;
    this.socket = upgraded;
    this.buffer = new Uint8Array(0);
    this.reader = upgraded.readable.getReader();
    this.writer = upgraded.writable.getWriter();
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.reader.cancel().catch(() => undefined);
    this.reader.releaseLock();
    this.writer.releaseLock();
    try {
      this.socket.close();
    } catch {
      // The socket may already be closed by the remote peer.
    }
  }
}

export async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timeoutId !== undefined) clearTimeout(timeoutId);
  }
}
