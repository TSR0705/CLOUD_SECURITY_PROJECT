import { describe, it, expect } from 'vitest';
import { Readable } from 'node:stream';
import { createHash } from 'node:crypto';
import {
  CountingHashStream,
  StreamLimitExceededError,
  StreamTimeoutError,
} from '../../../services/api/src/upload/counting-stream.js';

describe('CountingHashStream (Unit Tests)', () => {
  it('correctly counts bytes and computes SHA-256 incrementally', async () => {
    const data = Buffer.from('The quick brown fox jumps over the lazy dog');
    const expectedSha256 = createHash('sha256').update(data).digest('hex');

    const source = Readable.from([data.subarray(0, 10), data.subarray(10, 25), data.subarray(25)]);

    const countingStream = new CountingHashStream({ limit: 1000 });
    source.pipe(countingStream);

    const chunks: Buffer[] = [];
    for await (const chunk of countingStream) {
      chunks.push(Buffer.from(chunk));
    }

    const output = Buffer.concat(chunks);
    expect(output.toString()).toBe(data.toString());
    expect(countingStream.getBytesReceived()).toBe(data.length);
    expect(countingStream.getFinalSha256Hex()).toBe(expectedSha256);
  });

  it('immediately aborts and emits StreamLimitExceededError when limit is breached', async () => {
    const limit = 50;
    const oversizedChunk = Buffer.alloc(100, 'a');

    const source = Readable.from([oversizedChunk]);
    const countingStream = new CountingHashStream({ limit });

    source.pipe(countingStream);

    await expect(async () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const _ of countingStream) {
        // consume
      }
    }).rejects.toThrow(StreamLimitExceededError);

    expect(countingStream.getBytesReceived()).toBeGreaterThan(limit);
  });

  it('triggers StreamTimeoutError when stream is idle longer than idleTimeoutMs', async () => {
    let pushed = false;
    const source = new Readable({
      read() {
        if (!pushed) {
          pushed = true;
          this.push(Buffer.from('x'));
        }
      },
    });

    const countingStream = new CountingHashStream({
      limit: 1000,
      idleTimeoutMs: 100, // 100ms test timeout
    });

    source.pipe(countingStream);

    await expect(async () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const _ of countingStream) {
        // consume
      }
    }).rejects.toThrow(StreamTimeoutError);

    source.destroy();
  });
});
