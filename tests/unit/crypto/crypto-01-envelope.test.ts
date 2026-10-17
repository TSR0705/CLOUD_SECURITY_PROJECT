import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  AUTH_TAG_BYTES,
  decryptBuffer,
  DEFAULT_LOCAL_KEY_REFERENCE,
  encryptBuffer,
  LocalKeyProvider,
  NONCE_BYTES,
  RFC3394_WRAPPED_DEK_BYTES,
  STANDARD_HEADER_BYTES,
  SUG1_MAGIC,
  SUG1_VERSION,
} from '@sug/crypto';

describe('crypto-01: SUG1 Envelope Encryption & Round-Trip Decryption', () => {
  const testKek = crypto.randomBytes(32);
  const provider = new LocalKeyProvider({
    keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
  });

  const baseAad = {
    appId: 'app_tenant_alpha',
    fileId: 'file_report_2026',
    storageVersionId: 'v1_storage_obj',
    sha256Plaintext: crypto.createHash('sha256').update('hello world').digest('hex'),
  };

  it('encrypts plaintext into valid SUG1 envelope structure', async () => {
    const plaintext = Buffer.from('hello world', 'utf8');
    const encrypted = await encryptBuffer(plaintext, {
      keyProvider: provider,
      aad: baseAad,
    });

    expect(encrypted.header.magic).toBe(SUG1_MAGIC);
    expect(encrypted.header.version).toBe(SUG1_VERSION);
    expect(encrypted.header.nonce.length).toBe(NONCE_BYTES);
    expect(encrypted.header.wrappedDekLength).toBe(RFC3394_WRAPPED_DEK_BYTES);
    expect(encrypted.header.wrappedDek.length).toBe(RFC3394_WRAPPED_DEK_BYTES);
    expect(encrypted.header.authTag.length).toBe(AUTH_TAG_BYTES);
    expect(encrypted.header.headerLength).toBe(STANDARD_HEADER_BYTES);
    expect(encrypted.ciphertext.length).toBe(plaintext.length);
    expect(encrypted.serialized.length).toBe(STANDARD_HEADER_BYTES + plaintext.length);
    expect(encrypted.keyReference).toBe(DEFAULT_LOCAL_KEY_REFERENCE);

    // Verify wire bytes layout directly
    expect(encrypted.serialized.subarray(0, 4).toString('ascii')).toBe('SUG1');
    expect(encrypted.serialized.readUInt8(4)).toBe(1);
    expect(encrypted.serialized.readUInt16BE(17)).toBe(40);
  });

  it('round-trips plaintext correctly using decryptBuffer()', async () => {
    const plaintext = Buffer.from('Cryptographic security at the gateway layer.', 'utf8');
    const aad = {
      ...baseAad,
      sha256Plaintext: crypto.createHash('sha256').update(plaintext).digest('hex'),
    };

    const encrypted = await encryptBuffer(plaintext, {
      keyProvider: provider,
      aad,
    });

    const decrypted = await decryptBuffer(encrypted.serialized, {
      keyProvider: provider,
      aad,
    });

    expect(decrypted.equals(plaintext)).toBe(true);
    expect(decrypted.toString('utf8')).toBe('Cryptographic security at the gateway layer.');
  });

  it('generates fresh DEK, nonce, and ciphertext for every encryption run', async () => {
    const plaintext = Buffer.from('Identical plaintext message for freshness check', 'utf8');
    const aad = {
      ...baseAad,
      sha256Plaintext: crypto.createHash('sha256').update(plaintext).digest('hex'),
    };

    const enc1 = await encryptBuffer(plaintext, { keyProvider: provider, aad });
    const enc2 = await encryptBuffer(plaintext, { keyProvider: provider, aad });

    // Nonces must be unique
    expect(enc1.header.nonce.equals(enc2.header.nonce)).toBe(false);

    // Wrapped DEKs must differ because DEKs are fresh
    expect(enc1.header.wrappedDek.equals(enc2.header.wrappedDek)).toBe(false);

    // Ciphertext must differ because key and nonce differ
    expect(enc1.ciphertext.equals(enc2.ciphertext)).toBe(false);

    // Auth tags must differ
    expect(enc1.header.authTag.equals(enc2.header.authTag)).toBe(false);

    // Both decrypt back to the identical original plaintext
    const dec1 = await decryptBuffer(enc1.serialized, { keyProvider: provider, aad });
    const dec2 = await decryptBuffer(enc2.serialized, { keyProvider: provider, aad });
    expect(dec1.equals(plaintext)).toBe(true);
    expect(dec2.equals(plaintext)).toBe(true);
  });

  it('supports zero-byte empty plaintext buffer', async () => {
    const emptyPlaintext = Buffer.alloc(0);
    const aad = {
      ...baseAad,
      sha256Plaintext: crypto.createHash('sha256').update(emptyPlaintext).digest('hex'),
    };

    const encrypted = await encryptBuffer(emptyPlaintext, {
      keyProvider: provider,
      aad,
    });

    expect(encrypted.ciphertext.length).toBe(0);
    expect(encrypted.serialized.length).toBe(STANDARD_HEADER_BYTES);

    const decrypted = await decryptBuffer(encrypted.serialized, {
      keyProvider: provider,
      aad,
    });

    expect(decrypted.length).toBe(0);
    expect(decrypted.equals(emptyPlaintext)).toBe(true);
  });

  it('supports large payloads (1 MB binary)', async () => {
    const largeBuffer = crypto.randomBytes(1024 * 1024);
    const aad = {
      ...baseAad,
      sha256Plaintext: crypto.createHash('sha256').update(largeBuffer).digest('hex'),
    };

    const encrypted = await encryptBuffer(largeBuffer, {
      keyProvider: provider,
      aad,
    });

    expect(encrypted.serialized.length).toBe(STANDARD_HEADER_BYTES + largeBuffer.length);

    const decrypted = await decryptBuffer(encrypted.serialized, {
      keyProvider: provider,
      aad,
    });

    expect(decrypted.equals(largeBuffer)).toBe(true);
  });

  it('supports snake_case database model input for AAD', async () => {
    const plaintext = Buffer.from('Database model snake_case interop test', 'utf8');
    const sha = crypto.createHash('sha256').update(plaintext).digest('hex');

    const snakeAad = {
      app_id: 'app_snake_01',
      file_id: 'file_snake_02',
      storage_version_id: 'ver_snake_03',
      sha256_plaintext: sha,
    };

    const encrypted = await encryptBuffer(plaintext, {
      keyProvider: provider,
      aad: snakeAad,
    });

    const decrypted = await decryptBuffer(encrypted.serialized, {
      keyProvider: provider,
      aad: snakeAad,
    });

    expect(decrypted.equals(plaintext)).toBe(true);
  });

  it('decryptBuffer accepts EncryptedObject directly', async () => {
    const plaintext = Buffer.from('EncryptedObject input test', 'utf8');
    const aad = {
      ...baseAad,
      sha256Plaintext: crypto.createHash('sha256').update(plaintext).digest('hex'),
    };

    const encrypted = await encryptBuffer(plaintext, {
      keyProvider: provider,
      aad,
    });

    // Pass encrypted object directly instead of serialized Buffer
    const decrypted = await decryptBuffer(encrypted, {
      keyProvider: provider,
      aad,
    });

    expect(decrypted.equals(plaintext)).toBe(true);
  });
});
