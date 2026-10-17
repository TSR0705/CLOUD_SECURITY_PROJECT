import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  decryptBuffer,
  DEFAULT_LOCAL_KEY_REFERENCE,
  encryptBuffer,
  InvalidAadError,
  InvalidEnvelopeError,
  InvalidMagicError,
  LocalKeyProvider,
  MIN_HEADER_BYTES,
  parseSug1Header,
  STANDARD_HEADER_BYTES,
  UnsupportedVersionError,
} from '@sug/crypto';

describe('crypto-02: Verify-Before-Release & Tamper Rejection', () => {
  const testKek = crypto.randomBytes(32);
  const provider = new LocalKeyProvider({
    keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
  });

  const basePlaintext = Buffer.from(
    'Confidential payload requiring integrity verification',
    'utf8',
  );
  const baseSha = crypto.createHash('sha256').update(basePlaintext).digest('hex');
  const baseAad = {
    appId: 'app_tenant_sec',
    fileId: 'file_confidential_01',
    storageVersionId: 'ver_immutable_01',
    sha256Plaintext: baseSha,
  };

  it('rejects tampered ciphertext with AuthenticationError', async () => {
    const encrypted = await encryptBuffer(basePlaintext, {
      keyProvider: provider,
      aad: baseAad,
    });

    const tampered = Buffer.from(encrypted.serialized);
    // Flip 1 bit in the ciphertext payload (after 75-byte header)
    const ciphertextOffset = STANDARD_HEADER_BYTES + 5;
    tampered[ciphertextOffset] = (tampered[ciphertextOffset] ?? 0) ^ 0x01;

    await expect(
      decryptBuffer(tampered, {
        keyProvider: provider,
        aad: baseAad,
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('rejects tampered authentication tag with AuthenticationError', async () => {
    const encrypted = await encryptBuffer(basePlaintext, {
      keyProvider: provider,
      aad: baseAad,
    });

    const tampered = Buffer.from(encrypted.serialized);
    // Auth tag is located at offset 59..74
    const tagOffset = 65;
    tampered[tagOffset] = (tampered[tagOffset] ?? 0) ^ 0x80;

    await expect(
      decryptBuffer(tampered, {
        keyProvider: provider,
        aad: baseAad,
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('rejects truncated ciphertext with AuthenticationError', async () => {
    const encrypted = await encryptBuffer(basePlaintext, {
      keyProvider: provider,
      aad: baseAad,
    });

    // Truncate last 10 bytes of ciphertext
    const truncated = encrypted.serialized.subarray(0, encrypted.serialized.length - 10);

    await expect(
      decryptBuffer(truncated, {
        keyProvider: provider,
        aad: baseAad,
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('rejects invalid magic bytes with InvalidMagicError', async () => {
    const encrypted = await encryptBuffer(basePlaintext, {
      keyProvider: provider,
      aad: baseAad,
    });

    const corrupted = Buffer.from(encrypted.serialized);
    corrupted.write('BAD1', 0, 4, 'ascii');

    await expect(
      decryptBuffer(corrupted, {
        keyProvider: provider,
        aad: baseAad,
      }),
    ).rejects.toThrow(InvalidMagicError);
  });

  it('rejects unsupported envelope version with UnsupportedVersionError', async () => {
    const encrypted = await encryptBuffer(basePlaintext, {
      keyProvider: provider,
      aad: baseAad,
    });

    const corrupted = Buffer.from(encrypted.serialized);
    corrupted.writeUInt8(2, 4); // Version 2

    await expect(
      decryptBuffer(corrupted, {
        keyProvider: provider,
        aad: baseAad,
      }),
    ).rejects.toThrow(UnsupportedVersionError);
  });

  it('rejects undersized buffer smaller than minimum header with InvalidEnvelopeError', async () => {
    const tinyBuffer = Buffer.from('SUG1\x01truncated', 'ascii');

    await expect(
      decryptBuffer(tinyBuffer, {
        keyProvider: provider,
        aad: baseAad,
      }),
    ).rejects.toThrow(InvalidEnvelopeError);
  });

  it('rejects truncated header with declared wrappedDekLength larger than remaining buffer', async () => {
    const headerPrefix = Buffer.alloc(19);
    Buffer.from('SUG1', 'ascii').copy(headerPrefix, 0);
    headerPrefix.writeUInt8(1, 4);
    // Nonce 12 bytes
    crypto.randomBytes(12).copy(headerPrefix, 5);
    // Declare 1000 bytes wrapped DEK length
    headerPrefix.writeUInt16BE(1000, 17);

    // Provide only 50 bytes total
    const corrupted = Buffer.concat([headerPrefix, Buffer.alloc(31)]);

    expect(() => parseSug1Header(corrupted)).toThrow(InvalidEnvelopeError);
  });

  it('encryptBuffer rejects mismatched sha256Plaintext in AAD with InvalidAadError', async () => {
    const mismatchedAad = {
      ...baseAad,
      sha256Plaintext: 'f'.repeat(64), // Does not match basePlaintext
    };

    await expect(
      encryptBuffer(basePlaintext, {
        keyProvider: provider,
        aad: mismatchedAad,
      }),
    ).rejects.toThrow(InvalidAadError);
  });

  it('rejects envelope when decrypted plaintext digest does not match AAD sha256Plaintext', async () => {
    // Encrypt legitimate plaintext with its correct sha256
    const encrypted = await encryptBuffer(basePlaintext, {
      keyProvider: provider,
      aad: baseAad,
    });

    // Provide AAD with an altered sha256Plaintext during decrypt
    // Even if GCM tag verification were bypassed or mismatched, digest verification fails closed
    const alteredDigestAad = {
      ...baseAad,
      sha256Plaintext: crypto.createHash('sha256').update('different content').digest('hex'),
    };

    let emittedPlaintext: Buffer | null = null;
    try {
      emittedPlaintext = await decryptBuffer(encrypted.serialized, {
        keyProvider: provider,
        aad: alteredDigestAad,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(AuthenticationError);
    }

    expect(emittedPlaintext).toBeNull();
  });

  it('rejects envelopes at all truncated boundary lengths (0, 1, 4, 18, 19, 35, 58, 74 bytes)', () => {
    expect(MIN_HEADER_BYTES).toBe(75);
    const testBoundaries = [0, 1, 4, 18, 19, 35, 58, 74];
    for (const len of testBoundaries) {
      const truncatedBuf = Buffer.alloc(len);
      if (len >= 4) Buffer.from('SUG1', 'ascii').copy(truncatedBuf, 0);
      if (len >= 5) truncatedBuf.writeUInt8(1, 4);
      if (len >= 19) truncatedBuf.writeUInt16BE(40, 17);

      expect(
        () => parseSug1Header(truncatedBuf),
        `Should reject truncated length ${len} with InvalidEnvelopeError`,
      ).toThrow(InvalidEnvelopeError);
    }
  });

  it('rejects wrappedDekLength < 40 bytes with InvalidEnvelopeError', () => {
    const invalidLengths = [0, 8, 16, 32, 39];
    for (const badDekLen of invalidLengths) {
      const headerBuf = Buffer.alloc(STANDARD_HEADER_BYTES);
      Buffer.from('SUG1', 'ascii').copy(headerBuf, 0);
      headerBuf.writeUInt8(1, 4);
      crypto.randomBytes(12).copy(headerBuf, 5);
      headerBuf.writeUInt16BE(badDekLen, 17);

      expect(
        () => parseSug1Header(headerBuf),
        `Should reject wrappedDekLength ${badDekLen} with InvalidEnvelopeError`,
      ).toThrow(InvalidEnvelopeError);
    }
  });

  it('verify-before-release guarantees zero plaintext leakage on authentication failure', async () => {
    const secretPlaintext = Buffer.from('CRITICAL_TOP_SECRET_PLAINTEXT_12345', 'utf8');
    const aad = {
      ...baseAad,
      sha256Plaintext: crypto.createHash('sha256').update(secretPlaintext).digest('hex'),
    };

    const encrypted = await encryptBuffer(secretPlaintext, {
      keyProvider: provider,
      aad,
    });

    // Flip last byte of ciphertext
    const corrupted = Buffer.from(encrypted.serialized);
    corrupted[corrupted.length - 1] = (corrupted[corrupted.length - 1] ?? 0) ^ 0xff;

    let emittedPlaintext: Buffer | null = null;
    try {
      emittedPlaintext = await decryptBuffer(corrupted, {
        keyProvider: provider,
        aad,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(AuthenticationError);
    }

    // Invariant: emittedPlaintext MUST remain null
    expect(emittedPlaintext).toBeNull();
  });
});
