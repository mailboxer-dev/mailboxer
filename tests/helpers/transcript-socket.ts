import type { SocketLike } from "../../src/network";

interface TranscriptState {
  chunks: Uint8Array[];
  writes: Uint8Array[];
  closed: boolean;
}

function copyChunk(chunk: Uint8Array): Uint8Array {
  return new Uint8Array(chunk);
}

export class TranscriptSocket implements SocketLike {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  readonly opened = Promise.resolve();
  readonly closed: Promise<void>;
  private readonly state: TranscriptState;
  private resolveClosed!: () => void;

  constructor(chunks: Uint8Array[], state?: TranscriptState) {
    this.state = state ?? { chunks: chunks.map(copyChunk), writes: [], closed: false };
    this.closed = new Promise<void>((resolve) => {
      this.resolveClosed = resolve;
    });
    this.readable = new ReadableStream<Uint8Array>({
      pull: (controller) => {
        const chunk = this.state.chunks.shift();
        if (chunk) controller.enqueue(copyChunk(chunk));
        else controller.close();
      },
    });
    this.writable = new WritableStream<Uint8Array>({
      write: (chunk) => {
        this.state.writes.push(copyChunk(chunk));
      },
    });
  }

  startTls(): SocketLike {
    return new TranscriptSocket([], this.state);
  }

  close(): void {
    if (this.state.closed) return;
    this.state.closed = true;
    this.resolveClosed();
  }

  outputText(): string {
    return this.state.writes.map((chunk) => new TextDecoder().decode(chunk)).join("");
  }

  remainingChunks(): number {
    return this.state.chunks.length;
  }
}

export function textChunks(value: string, chunkSize = 11): Uint8Array[] {
  const bytes = new TextEncoder().encode(value);
  const chunks: Uint8Array[] = [];
  for (let index = 0; index < bytes.length; index += chunkSize) chunks.push(bytes.slice(index, index + chunkSize));
  return chunks;
}

export function mixedChunks(...values: Array<string | Uint8Array>): Uint8Array[] {
  return values.flatMap((value) => (typeof value === "string" ? textChunks(value) : [value]));
}
