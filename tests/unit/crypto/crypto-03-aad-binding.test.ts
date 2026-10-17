import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  buildCanonicalAad,
  decryptBuffer,
  DEFAULT_LOCAL_KEY_REFERENCE,
  encryptBuffer,
  InvalidAadError,
  LocalKeyProvider,
  normalizeAadInput,
} from '@sug/crypto';

describe('crypto-03: AAD Identity Binding', () => {
  const testKek = crypto.randomBytes(32);
  const provider = new LocalKeyProvider({
    keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
  });

  const plaintext = Buffer.from(
    'Cryptographically bound document to tenant and storage identity',
    'utf8',
  );
  const validSha = crypto.createHash('sha256').update(plaintext).digest('hex');

  const canonicalAad = {
    appId: 'app_finance_prod',
    fileId: 'file_ledger_2026_q1',
    storageVersionId: 'ver_immutable_0099',
    sha256Plaintext: validSha,
  };

  it('rejects decryption when appId is altered', async () => {
    const encrypted = await encryptBuffer(plaintext, {
      keyProvider: provider,
      aad: canonicalAad,
    });

    const alteredAad = {
      ...canonicalAad,
      appId: 'app_finance_malicious',
    };

    await expect(
      decryptBuffer(encrypted.serialized, {
        keyProvider: provider,
        aad: alteredAad,
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('rejects decryption when fileId is altered', async () => {
    const encrypted = await encryptBuffer(plaintext, {
      keyProvider: provider,
      aad: canonicalAad,
    });

    const alteredAad = {
      ...canonicalAad,
      fileId: 'file_ledger_2026_q2',
    };

    await expect(
      decryptBuffer(encrypted.serialized, {
        keyProvider: provider,
        aad: alteredAad,
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('rejects decryption when storageVersionId is altered', async () => {
    const encrypted = await encryptBuffer(plaintext, {
      keyProvider: provider,
      aad: canonicalAad,
    });

    const alteredAad = {
      ...canonicalAad,
      storageVersionId: 'ver_immutable_0100',
    };

    await expect(
      decryptBuffer(encrypted.serialized, {
        keyProvider: provider,
        aad: alteredAad,
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('rejects decryption when sha256Plaintext is altered', async () => {
    const encrypted = await encryptBuffer(plaintext, {
      keyProvider: provider,
      aad: canonicalAad,
    });

    const alteredAad = {
      ...canonicalAad,
      sha256Plaintext: '0'.repeat(64),
    };

    await expect(
      decryptBuffer(encrypted.serialized, {
        keyProvider: provider,
        aad: alteredAad,
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  describe('normalizeAadInput & buildCanonicalAad validation', () => {
    it('throws InvalidAadError for non-object input', () => {
      // @ts-expect-error testing invalid input
      expect(() => normalizeAadInput(null)).toThrow(InvalidAadError);
      // @ts-expect-error testing invalid input
      expect(() => normalizeAadInput('string')).toThrow(InvalidAadError);
    });

    it('throws InvalidAadError for missing or empty appId', () => {
      expect(() =>
        normalizeAadInput({
          appId: '',
          fileId: 'f1',
          storageVersionId: 'v1',
          sha256Plaintext: validSha,
        }),
      ).toThrow(InvalidAadError);
    });

    it('throws InvalidAadError for missing or empty fileId', () => {
      expect(() =>
        normalizeAadInput({
          appId: 'a1',
          fileId: '   ',
          storageVersionId: 'v1',
          sha256Plaintext: validSha,
        }),
      ).toThrow(InvalidAadError);
    });

    it('throws InvalidAadError for missing or empty storageVersionId', () => {
      expect(() =>
        normalizeAadInput({
          appId: 'a1',
          fileId: 'f1',
          storageVersionId: '',
          sha256Plaintext: validSha,
        }),
      ).toThrow(InvalidAadError);
    });

    it('throws InvalidAadError for invalid sha256Plaintext', () => {
      expect(() =>
        normalizeAadInput({
          appId: 'a1',
          fileId: 'f1',
          storageVersionId: 'v1',
          sha256Plaintext: 'not_a_valid_hex_string',
        }),
      ).toThrow(InvalidAadError);

      expect(() =>
        normalizeAadInput({
          appId: 'a1',
          fileId: 'f1',
          storageVersionId: 'v1',
          sha256Plaintext: 'a'.repeat(63), // too short
        }),
      ).toThrow(InvalidAadError);
    });

    it('normalizes uppercase sha256 and hex prefixes', () => {
      const norm1 = normalizeAadInput({
        appId: 'a1',
        fileId: 'f1',
        storageVersionId: 'v1',
        sha256Plaintext: validSha.toUpperCase(),
      });
      expect(norm1.sha256Plaintext).toBe(validSha.toLowerCase());

      const norm2 = normalizeAadInput({
        appId: 'a1',
        fileId: 'f1',
        storageVersionId: 'v1',
        sha256Plaintext: `0x${validSha}`,
      });
      expect(norm2.sha256Plaintext).toBe(validSha.toLowerCase());

      const norm3 = normalizeAadInput({
        appId: 'a1',
        fileId: 'f1',
        storageVersionId: 'v1',
        sha256Plaintext: `\\x${validSha}`,
      });
      expect(norm3.sha256Plaintext).toBe(validSha.toLowerCase());
    });

    it('length-prefixed encoding prevents ambiguity between adjacent fields', () => {
      // (appId: "ab", fileId: "cd") vs (appId: "a", fileId: "bcd")
      const buf1 = buildCanonicalAad({
        appId: 'ab',
        fileId: 'cd',
        storageVersionId: 'v1',
        sha256Plaintext: validSha,
      });

      const buf2 = buildCanonicalAad({
        appId: 'a',
        fileId: 'bcd',
        storageVersionId: 'v1',
        sha256Plaintext: validSha,
      });

      // Simple string concatenation would collide ("abcd" == "abcd"), but length prefixing avoids collision
      expect(buf1.equals(buf2)).toBe(false);
    });
  });
});
