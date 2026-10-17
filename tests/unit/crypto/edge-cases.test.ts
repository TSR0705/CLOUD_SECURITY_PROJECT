import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  CryptoError,
  decryptBuffer,
  DEFAULT_LOCAL_KEY_REFERENCE,
  encryptBuffer,
  extractCiphertext,
  InvalidEnvelopeError,
  KeyProviderError,
  LocalKeyProvider,
  parseSug1Header,
  serializeSug1Envelope,
  STANDARD_HEADER_BYTES,
  SUG1_MAGIC,
  SUG1_VERSION,
} from '@sug/crypto';

describe('P19 Edge Cases & Defensive Branch Verification', () => {
  const testKek = crypto.randomBytes(32);
  const provider = new LocalKeyProvider({
    keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
  });

  const basePlaintext = Buffer.from('Edge case test payload', 'utf8');
  const baseAad = {
    appId: 'app_edge',
    fileId: 'file_edge',
    storageVersionId: 'ver_edge',
    sha256Plaintext: crypto.createHash('sha256').update(basePlaintext).digest('hex'),
  };

  it('rejects non-Buffer plaintext in encryptBuffer', async () => {
    // @ts-expect-error testing invalid argument
    await expect(
      encryptBuffer('string_not_buffer', { keyProvider: provider, aad: baseAad }),
    ).rejects.toThrow(CryptoError);
  });

  it('rejects missing keyProvider in encryptBuffer and decryptBuffer', async () => {
    // @ts-expect-error testing invalid argument
    await expect(encryptBuffer(basePlaintext, { aad: baseAad })).rejects.toThrow(CryptoError);

    // @ts-expect-error testing invalid argument
    await expect(decryptBuffer(Buffer.alloc(80), { aad: baseAad })).rejects.toThrow(CryptoError);
  });

  it('rejects customDek or customNonce with incorrect lengths', async () => {
    await expect(
      encryptBuffer(basePlaintext, {
        keyProvider: provider,
        aad: baseAad,
        customDek: crypto.randomBytes(16), // expected 32
      }),
    ).rejects.toThrow(CryptoError);

    await expect(
      encryptBuffer(basePlaintext, {
        keyProvider: provider,
        aad: baseAad,
        customNonce: crypto.randomBytes(8), // expected 12
      }),
    ).rejects.toThrow(CryptoError);
  });

  it('decrypts when passed an object with { header, ciphertext }', async () => {
    const encrypted = await encryptBuffer(basePlaintext, {
      keyProvider: provider,
      aad: baseAad,
    });

    const decrypted = await decryptBuffer(
      { header: encrypted.header, ciphertext: encrypted.ciphertext },
      { keyProvider: provider, aad: baseAad },
    );

    expect(decrypted.equals(basePlaintext)).toBe(true);
  });

  it('rejects invalid envelope object shape with InvalidEnvelopeError', async () => {
    // @ts-expect-error testing invalid envelope object
    await expect(
      decryptBuffer({ somethingElse: 123 }, { keyProvider: provider, aad: baseAad }),
    ).rejects.toThrow(InvalidEnvelopeError);
  });

  it('parseSug1Header rejects non-Buffer input', () => {
    // @ts-expect-error testing invalid input
    expect(() => parseSug1Header('not_a_buffer')).toThrow(InvalidEnvelopeError);
  });

  it('serializeSug1Envelope validates all buffer parameters strictly', () => {
    const validNonce = crypto.randomBytes(12);
    const validWrappedDek = crypto.randomBytes(40);
    const validTag = crypto.randomBytes(16);
    const validCiphertext = Buffer.from('data');

    // Invalid nonce length
    expect(() =>
      serializeSug1Envelope(
        { nonce: crypto.randomBytes(10), wrappedDek: validWrappedDek, authTag: validTag },
        validCiphertext,
      ),
    ).toThrow(InvalidEnvelopeError);

    // Invalid tag length
    expect(() =>
      serializeSug1Envelope(
        { nonce: validNonce, wrappedDek: validWrappedDek, authTag: crypto.randomBytes(12) },
        validCiphertext,
      ),
    ).toThrow(InvalidEnvelopeError);

    // Non-Buffer wrappedDek
    expect(() =>
      serializeSug1Envelope(
        // @ts-expect-error invalid wrappedDek
        { nonce: validNonce, wrappedDek: 'not_buffer', authTag: validTag },
        validCiphertext,
      ),
    ).toThrow(InvalidEnvelopeError);

    // Oversized wrappedDek
    expect(() =>
      serializeSug1Envelope(
        { nonce: validNonce, wrappedDek: Buffer.alloc(70000), authTag: validTag },
        validCiphertext,
      ),
    ).toThrow(InvalidEnvelopeError);

    // Non-Buffer ciphertext
    expect(() =>
      serializeSug1Envelope(
        { nonce: validNonce, wrappedDek: validWrappedDek, authTag: validTag },
        // @ts-expect-error invalid ciphertext
        'not_buffer',
      ),
    ).toThrow(InvalidEnvelopeError);
  });

  it('extractCiphertext rejects buffer shorter than headerLength', () => {
    const dummyHeader = {
      magic: SUG1_MAGIC,
      version: SUG1_VERSION,
      nonce: crypto.randomBytes(12),
      wrappedDekLength: 40,
      wrappedDek: crypto.randomBytes(40),
      authTag: crypto.randomBytes(16),
      headerLength: STANDARD_HEADER_BYTES,
    };

    expect(() => extractCiphertext(Buffer.alloc(50), dummyHeader)).toThrow(InvalidEnvelopeError);
  });

  it('LocalKeyProvider handles secretsDir lookup', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sug-secrets-dir-'));
    const keyRef = 'custom_service_key';
    const secretFile = path.join(tmpDir, keyRef);
    const fileKek = crypto.randomBytes(32);
    fs.writeFileSync(secretFile, fileKek);

    try {
      const providerWithSecretsDir = new LocalKeyProvider({
        secretsDir: tmpDir,
      });

      const dek = crypto.randomBytes(32);
      const { wrappedKey, keyReference } = await providerWithSecretsDir.wrapKey(dek, keyRef);
      expect(keyReference).toBe(keyRef);

      const unwrapped = await providerWithSecretsDir.unwrapKey(wrappedKey, keyRef);
      expect(unwrapped.equals(dek)).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('LocalKeyProvider rejects empty keyReference on addKey', () => {
    const p = new LocalKeyProvider();
    // @ts-expect-error testing empty string
    expect(() => p.addKey('', crypto.randomBytes(32))).toThrow(KeyProviderError);
    // @ts-expect-error testing non-string
    expect(() => p.addKey(null, crypto.randomBytes(32))).toThrow(KeyProviderError);
  });

  it('exports all expected public members from index.ts', async () => {
    const cryptoModule = await import('../../../packages/crypto/src/index.js');
    expect(cryptoModule.SUG1_MAGIC).toBe('SUG1');
    expect(cryptoModule.SUG1_VERSION).toBe(1);
    expect(typeof cryptoModule.encryptBuffer).toBe('function');
    expect(typeof cryptoModule.decryptBuffer).toBe('function');
    expect(typeof cryptoModule.buildCanonicalAad).toBe('function');
    expect(typeof cryptoModule.parseSug1Header).toBe('function');
    expect(cryptoModule.LocalKeyProvider).toBeDefined();
    expect(cryptoModule.KmsKeyProvider).toBeDefined();
  });
});
