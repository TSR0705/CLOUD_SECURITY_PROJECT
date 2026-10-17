import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  decryptBuffer,
  DEFAULT_LOCAL_KEY_REFERENCE,
  encryptBuffer,
  InvalidEnvelopeError,
  InvalidMagicError,
  LocalKeyProvider,
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
