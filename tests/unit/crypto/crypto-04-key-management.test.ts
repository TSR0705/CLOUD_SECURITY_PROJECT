import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  decryptBuffer,
  DEFAULT_LOCAL_KEY_REFERENCE,
  DEFAULT_MOCK_KMS_KEY_REF,
  encryptBuffer,
  KeyProviderError,
  KmsKeyProvider,
  LocalKeyProvider,
  RFC3394_WRAPPED_DEK_BYTES,
} from '@sug/crypto';

describe('crypto-04: Key Management & Provider Fail-Closed Behavior', () => {
  const validKek = crypto.randomBytes(32);
  const validDek = crypto.randomBytes(32);

  const baseAad = {
    appId: 'app_kms_test',
    fileId: 'file_kms_test',
    storageVersionId: 'ver_kms_test',
    sha256Plaintext: crypto.createHash('sha256').update('data').digest('hex'),
  };

  describe('LocalKeyProvider', () => {
    it('wraps 32-byte DEK to 40-byte wrapped key using RFC 3394', async () => {
      const provider = new LocalKeyProvider({
        keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: validKek },
      });

      const { wrappedKey, keyReference } = await provider.wrapKey(validDek);
      expect(wrappedKey.length).toBe(RFC3394_WRAPPED_DEK_BYTES);
      expect(keyReference).toBe(DEFAULT_LOCAL_KEY_REFERENCE);

      const unwrapped = await provider.unwrapKey(wrappedKey);
      expect(unwrapped.equals(validDek)).toBe(true);
    });

    it('rejects invalid KEK length on construction or addition', () => {
      expect(() => {
        new LocalKeyProvider({
          // 16 bytes instead of 32
          keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: crypto.randomBytes(16) },
        });
      }).toThrow(KeyProviderError);

      const provider = new LocalKeyProvider();
      expect(() => {
        // 48 bytes instead of 32
        provider.addKey('key2', crypto.randomBytes(48));
      }).toThrow(KeyProviderError);
    });

    it('rejects wrapping DEKs that are not 32 bytes', async () => {
      const provider = new LocalKeyProvider({
        keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: validKek },
      });

      await expect(provider.wrapKey(crypto.randomBytes(16))).rejects.toThrow(KeyProviderError);
      await expect(provider.wrapKey(crypto.randomBytes(64))).rejects.toThrow(KeyProviderError);
    });

    it('rejects unwrapping wrapped DEKs that are not 40 bytes', async () => {
      const provider = new LocalKeyProvider({
        keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: validKek },
      });

      await expect(provider.unwrapKey(crypto.randomBytes(32))).rejects.toThrow(KeyProviderError);
    });

    it('fails closed when unwrapping with the wrong KEK', async () => {
      const kekA = crypto.randomBytes(32);
      const kekB = crypto.randomBytes(32);

      const providerA = new LocalKeyProvider({
        keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: kekA },
      });
      const providerB = new LocalKeyProvider({
        keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: kekB },
      });

      const { wrappedKey } = await providerA.wrapKey(validDek);

      // Attempt unwrap with wrong KEK providerB
      await expect(providerB.unwrapKey(wrappedKey)).rejects.toThrow(KeyProviderError);
    });

    it('resolves KEK from secretFilePath', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sug-kek-test-'));
      const secretFile = path.join(tmpDir, 'sug_kek');
      const fileKek = crypto.randomBytes(32);
      fs.writeFileSync(secretFile, fileKek.toString('hex'), 'utf8');

      try {
        const provider = new LocalKeyProvider({
          secretFilePath: secretFile,
        });

        const { wrappedKey } = await provider.wrapKey(validDek);
        const unwrapped = await provider.unwrapKey(wrappedKey);
        expect(unwrapped.equals(validDek)).toBe(true);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('resolves KEK from environment variable SUG_KEK', async () => {
      const envKek = crypto.randomBytes(32);
      const prevEnv = process.env.SUG_KEK;
      process.env.SUG_KEK = envKek.toString('hex');

      try {
        const provider = new LocalKeyProvider();
        const { wrappedKey } = await provider.wrapKey(validDek);
        const unwrapped = await provider.unwrapKey(wrappedKey);
        expect(unwrapped.equals(validDek)).toBe(true);
      } finally {
        if (prevEnv !== undefined) {
          process.env.SUG_KEK = prevEnv;
        } else {
          delete process.env.SUG_KEK;
        }
      }
    });

    it('fails closed when key reference is not found', async () => {
      const provider = new LocalKeyProvider();
      await expect(provider.wrapKey(validDek, 'nonexistent_key_ref')).rejects.toThrow(
        KeyProviderError,
      );
    });
  });

  describe('KmsKeyProvider', () => {
    it('fails closed in live production mode (mock: false)', async () => {
      const liveKms = new KmsKeyProvider({ mock: false });
      expect(liveKms.providerId).toBe('kms');

      await expect(liveKms.wrapKey(validDek)).rejects.toThrow(KeyProviderError);
      await expect(liveKms.unwrapKey(crypto.randomBytes(40))).rejects.toThrow(KeyProviderError);
    });

    it('rejects invalid DEK lengths on KMS wrapKey and unwrapKey', async () => {
      const mockKms = new KmsKeyProvider({ mock: true });

      await expect(mockKms.wrapKey(crypto.randomBytes(16))).rejects.toThrow(KeyProviderError);
      await expect(mockKms.unwrapKey(crypto.randomBytes(32))).rejects.toThrow(KeyProviderError);
    });

    it('successfully wraps and unwraps in test mock mode (mock: true)', async () => {
      const mockKms = new KmsKeyProvider({
        mock: true,
        defaultKeyReference: DEFAULT_MOCK_KMS_KEY_REF,
      });

      const { wrappedKey, keyReference } = await mockKms.wrapKey(validDek);
      expect(wrappedKey.length).toBe(RFC3394_WRAPPED_DEK_BYTES);
      expect(keyReference).toBe(DEFAULT_MOCK_KMS_KEY_REF);

      const unwrapped = await mockKms.unwrapKey(wrappedKey);
      expect(unwrapped.equals(validDek)).toBe(true);
    });

    it('end-to-end envelope encryption and decryption with mock KMS provider', async () => {
      const mockKms = new KmsKeyProvider({ mock: true });
      const plaintext = Buffer.from('Plaintext protected by KMS key envelope', 'utf8');
      const aad = {
        ...baseAad,
        sha256Plaintext: crypto.createHash('sha256').update(plaintext).digest('hex'),
      };

      const encrypted = await encryptBuffer(plaintext, {
        keyProvider: mockKms,
        aad,
      });

      const decrypted = await decryptBuffer(encrypted.serialized, {
        keyProvider: mockKms,
        aad,
      });

      expect(decrypted.equals(plaintext)).toBe(true);
    });

    it('fails unwrapping when KMS key reference differs in mock mode', async () => {
      const mockKms = new KmsKeyProvider({ mock: true });
      const { wrappedKey } = await mockKms.wrapKey(validDek, 'arn:aws:kms:key-1');

      // Attempt unwrapping with key-2
      await expect(mockKms.unwrapKey(wrappedKey, 'arn:aws:kms:key-2')).rejects.toThrow(
        KeyProviderError,
      );
    });

    it('strictly forbids mock KMS mode when NODE_ENV is set to production', () => {
      const prevEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      try {
        expect(() => new KmsKeyProvider({ mock: true })).toThrow(KeyProviderError);
      } finally {
        if (prevEnv !== undefined) {
          process.env.NODE_ENV = prevEnv;
        } else {
          delete process.env.NODE_ENV;
        }
      }
    });

    it('rejects path traversal attempts in keyReference under secretsDir', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sug-traversal-'));
      try {
        const provider = new LocalKeyProvider({ secretsDir: tmpDir });
        await expect(provider.wrapKey(validDek, '../../../secret_outside')).rejects.toThrow(
          KeyProviderError,
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });
});
