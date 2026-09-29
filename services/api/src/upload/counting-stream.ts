import { Transform, type TransformCallback } from 'node:stream';
import { createHash, type Hash } from 'node:crypto';

export class StreamLimitExceededError extends Error {
  readonly limit: number;
  readonly bytesReceived: number;

  constructor(limit: number, bytesReceived: number) {
    super(`Payload limit of ${limit} bytes exceeded (received ${bytesReceived} bytes)`);
    this.name = 'StreamLimitExceededError';
    this.limit = limit;
    this.bytesReceived = bytesReceived;
  }
}

export class StreamTimeoutError extends Error {
  readonly timeoutMs: number;

  constructor(timeoutMs: number) {
    super(`Stream idle timeout of ${timeoutMs}ms exceeded`);
    this.name = 'StreamTimeoutError';
    this.timeoutMs = timeoutMs;
  }
}

export interface CountingHashStreamOptions {
  limit: number;
  idleTimeoutMs?: number;
  abortController?: AbortController;
}

/**
 * In-memory pass-through stream (Tee) that:
 * 1. Counts incoming bytes incrementally without buffering the payload.
 * 2. Computes the SHA-256 digest in real-time.
 * 3. Enforces an idle timeout (default 30 seconds) on incoming chunks.
 * 4. Strictly enforces effectiveLimit, aborting the stream immediately when exceeded.
 */
export class CountingHashStream extends Transform {
  private bytesReceived = 0;
  private readonly limit: number;
  private readonly hasher: Hash;
  private idleTimer: NodeJS.Timeout | null = null;
  private readonly idleTimeoutMs: number;
  private readonly abortController?: AbortController | undefined;
  private isTerminated = false;

  constructor(options: CountingHashStreamOptions) {
    super();
    this.limit = options.limit;
    this.idleTimeoutMs = options.idleTimeoutMs ?? 30_000;
    this.abortController = options.abortController;
    this.hasher = createHash('sha256');
    this.resetIdleTimer();
  }

  private resetIdleTimer(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
    }
    this.idleTimer = setTimeout(() => {
      this.handleTimeout();
    }, this.idleTimeoutMs);

    if (this.idleTimer.unref) {
      this.idleTimer.unref();
    }
  }

  private handleTimeout(): void {
    if (this.isTerminated) return;
    this.isTerminated = true;
    this.clearIdleTimer();
    const err = new StreamTimeoutError(this.idleTimeoutMs);
    if (this.abortController) {
      this.abortController.abort(err);
    }
    this.destroy(err);
  }

  private clearIdleTimer(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
  }

  override _transform(
    chunk: Buffer | Uint8Array,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    if (this.isTerminated) {
      return;
    }

    this.resetIdleTimer();
    const len = chunk.length;
    this.bytesReceived += len;

    if (this.bytesReceived > this.limit) {
      this.clearIdleTimer();
      this.isTerminated = true;
      const err = new StreamLimitExceededError(this.limit, this.bytesReceived);
      if (this.abortController) {
        this.abortController.abort(err);
      }
      callback(err);
      return;
    }

    this.hasher.update(chunk);
    callback(null, chunk);
  }

  override _flush(callback: TransformCallback): void {
    this.clearIdleTimer();
    callback();
  }

  override _destroy(err: Error | null, callback: (error: Error | null) => void): void {
    this.clearIdleTimer();
    this.isTerminated = true;
    callback(err);
  }

  getBytesReceived(): number {
    return this.bytesReceived;
  }

  getSha256Hex(): string {
    return this.hasher.copy().digest('hex');
  }

  getFinalSha256Hex(): string {
    return this.hasher.digest('hex');
  }
}
