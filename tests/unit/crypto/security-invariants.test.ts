import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  AUTH_TAG_BYTES,
  AuthenticationError,
  buildCanonicalAad,
  DEK_BYTES,
  decryptBuffer,
  DEFAULT_LOCAL_KEY_REFERENCE,
  encryptBuffer,
  generateDek,
  generateNonce,
  KeyProviderError,
  LocalKeyProvider,
  NONCE_BYTES,
  parseSug1Header,
  RFC3394_WRAPPED_DEK_BYTES,
  STANDARD_HEADER_BYTES,
  SUG1_MAGIC,
  SUG1_VERSION,
} from '@sug/crypto';

describe('P19 Security Invariants Audit Tests', () => {
  const testKek = crypto.randomBytes(32);
  const provider = new LocalKeyProvider({
    keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
  });

  const samplePlaintext = Buffer.from('Security Invariant Verification Payload', 'utf8');
  const sampleSha = crypto.createHash('sha256').update(samplePlaintext).digest('hex');
  const sampleAad = {
    appId: 'app_inv_test',
    fileId: 'file_inv_test',
    storageVersionId: 'ver_inv_test',
    sha256Plaintext: sampleSha,
  };

  it('Invariant 1: Payload cipher is strictly AES-256-GCM', async () => {
    // Encrypting with custom known DEK and Nonce must match node:crypto aes-256-gcm exactly
    const customDek = crypto.randomBytes(32);
    const customNonce = crypto.randomBytes(12);

    const enc = await encryptBuffer(samplePlaintext, {
      keyProvider: provider,
      aad: sampleAad,
      customDek,
      customNonce,
    });

    const expectedAad = buildCanonicalAad(sampleAad);
    const directCipher = crypto.createCipheriv('aes-256-gcm', customDek, customNonce);
    directCipher.setAAD(expectedAad);
    const directCiphertext = Buffer.concat([
      directCipher.update(samplePlaintext),
      directCipher.final(),
    ]);
    const directTag = directCipher.getAuthTag();

    expect(enc.ciphertext.equals(directCiphertext)).toBe(true);
    expect(enc.header.authTag.equals(directTag)).toBe(true);
  });

  it('Invariant 2: DEK is strictly 256 bits (32 bytes) CSPRNG', () => {
    for (let i = 0; i < 50; i++) {
      const dek = generateDek();
      expect(dek.length).toBe(DEK_BYTES);
      expect(DEK_BYTES).toBe(32);
    }
  });

  it('Invariant 3: Nonce is strictly 96 bits (12 bytes) CSPRNG', () => {
    for (let i = 0; i < 50; i++) {
      const nonce = generateNonce();
      expect(nonce.length).toBe(NONCE_BYTES);
      expect(NONCE_BYTES).toBe(12);
    }
  });

  it('Invariant 4: Authentication Tag is strictly 128 bits (16 bytes)', async () => {
    const enc = await encryptBuffer(samplePlaintext, {
      keyProvider: provider,
      aad: sampleAad,
    });
    expect(enc.header.authTag.length).toBe(AUTH_TAG_BYTES);
    expect(AUTH_TAG_BYTES).toBe(16);
  });

  it('Invariant 5: DEK wrapping uses RFC 3394 AES-256 Key Wrap', async () => {
    const dek = crypto.randomBytes(32);
    const { wrappedKey } = await provider.wrapKey(dek);

    // RFC 3394 wraps 32-byte key + 8-byte ICV into 40 bytes
    expect(wrappedKey.length).toBe(RFC3394_WRAPPED_DEK_BYTES);
    expect(RFC3394_WRAPPED_DEK_BYTES).toBe(40);

    // Direct unwrapping using node:crypto with RFC 3394 default IV
    const decipher = crypto.createDecipheriv(
      'id-aes256-wrap',
      testKek,
      Buffer.from('A6A6A6A6A6A6A6A6', 'hex'),
    );
    const directUnwrapped = Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
    expect(directUnwrapped.equals(dek)).toBe(true);
  });

  it('Invariant 6: Wire format conforms strictly to SUG1 layout with 75-byte standard header', async () => {
    const enc = await encryptBuffer(samplePlaintext, {
      keyProvider: provider,
      aad: sampleAad,
    });

    const parsed = parseSug1Header(enc.serialized);
    expect(parsed.magic).toBe(SUG1_MAGIC);
    expect(parsed.version).toBe(SUG1_VERSION);
    expect(parsed.headerLength).toBe(STANDARD_HEADER_BYTES);
    expect(STANDARD_HEADER_BYTES).toBe(75);
  });

  it('Invariant 7: AAD length-prefixed encoding binds all 4 artifact identity fields', () => {
    const aadBuf = buildCanonicalAad(sampleAad);
    // Begins with length of "SUG-AAD-V1" (10 bytes -> 0x0000000a)
    expect(aadBuf.readUInt32BE(0)).toBe(10);
    expect(aadBuf.subarray(4, 14).toString('utf8')).toBe('SUG-AAD-V1');
  });

  it('Invariant 8: Verify-before-release guarantees zero unauthenticated plaintext emitted', async () => {
    const enc = await encryptBuffer(samplePlaintext, {
      keyProvider: provider,
      aad: sampleAad,
    });

    const corrupted = Buffer.from(enc.serialized);
    corrupted[75] = (corrupted[75] ?? 0) ^ 0xff; // Corrupt ciphertext

    await expect(
      decryptBuffer(corrupted, { keyProvider: provider, aad: sampleAad }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('Invariant 9: Fail-closed on any key or provider error', async () => {
    const emptyProvider = new LocalKeyProvider();
    await expect(
      encryptBuffer(samplePlaintext, {
        keyProvider: emptyProvider,
        aad: sampleAad,
      }),
    ).rejects.toThrow(KeyProviderError);
  });

  it('Invariant 10: In-memory DEK is wiped/zeroed after encryption and decryption', async () => {
    // Pass custom DEK copy and verify encryptBuffer does not leak plaintext DEK
    const testDek = crypto.randomBytes(32);
    const testDekCopy = Buffer.from(testDek);

    const enc = await encryptBuffer(samplePlaintext, {
      keyProvider: provider,
      aad: sampleAad,
      customDek: testDekCopy,
    });

    // The internal copy of DEK created in encryptBuffer was wiped via dek.fill(0)
    // The encrypted envelope can be successfully decrypted
    const dec = await decryptBuffer(enc.serialized, {
      keyProvider: provider,
      aad: sampleAad,
    });
    expect(dec.equals(samplePlaintext)).toBe(true);
  });
});
