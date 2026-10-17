import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_LOCAL_KEY_REFERENCE,
  encryptBuffer,
  generateNonce,
  LocalKeyProvider,
  NONCE_BYTES,
} from '@sug/crypto';

describe('P19 Nonce Uniqueness & Collision Resistance (10,000 Iterations)', () => {
  it('generates 10,000 strictly unique 96-bit CSPRNG nonces (0 collisions)', () => {
    const ITERATIONS = 10_000;
    const seen = new Set<string>();

    const start = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
      const nonce = generateNonce();
      expect(nonce.length).toBe(NONCE_BYTES);
      const hex = nonce.toString('hex');
      seen.add(hex);
    }
    const durationMs = performance.now() - start;

    expect(seen.size).toBe(ITERATIONS);
    // Print throughput note for verification audit
    console.log(
      `[Nonce Uniqueness] Generated ${ITERATIONS} 96-bit nonces in ${durationMs.toFixed(2)}ms (0 collisions, ${(ITERATIONS / (durationMs / 1000)).toFixed(0)} nonces/sec)`,
    );
  });

  it('guarantees unique nonces across repeated encryptBuffer operations', async () => {
    const testKek = crypto.randomBytes(32);
    const provider = new LocalKeyProvider({
      keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
    });

    const plaintext = Buffer.from('payload', 'utf8');
    const aad = {
      appId: 'app_nonce_check',
      fileId: 'file_nonce_check',
      storageVersionId: 'ver_nonce_check',
      sha256Plaintext: crypto.createHash('sha256').update(plaintext).digest('hex'),
    };

    const seenNonces = new Set<string>();
    const RUNS = 100;

    for (let i = 0; i < RUNS; i++) {
      const enc = await encryptBuffer(plaintext, {
        keyProvider: provider,
        aad,
      });
      seenNonces.add(enc.header.nonce.toString('hex'));
    }

    expect(seenNonces.size).toBe(RUNS);
  });
});
