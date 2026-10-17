import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  decryptBuffer,
  DEFAULT_LOCAL_KEY_REFERENCE,
  encryptBuffer,
  InvalidEnvelopeError,
  InvalidMagicError,
  KeyProviderError,
  LocalKeyProvider,
  STANDARD_HEADER_BYTES,
  UnsupportedVersionError,
} from '@sug/crypto';

interface PositiveVector {
  readonly id: string;
  readonly description: string;
  readonly kekHex: string;
  readonly dekHex: string;
  readonly nonceHex: string;
  readonly plaintextUtf8?: string;
  readonly plaintextHex: string;
  readonly aad: {
    readonly appId: string;
    readonly fileId: string;
    readonly storageVersionId: string;
    readonly sha256Plaintext: string;
  };
  readonly wrappedDekHex: string;
  readonly authTagHex: string;
  readonly ciphertextHex: string;
  readonly serializedEnvelopeHex: string;
}

interface NegativeVector {
  readonly id: string;
  readonly description: string;
  readonly baseVectorId: string;
  readonly corruptType: string;
  readonly wrongKekHex?: string;
  readonly expectedError: string;
}

interface VectorFile {
  readonly version: number;
  readonly positive: readonly PositiveVector[];
  readonly negative: readonly NegativeVector[];
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const vectorFilePath = path.resolve(
  __dirname,
  '../../../packages/crypto/test-vectors/sug1-vectors.json',
);

describe('P19 Cryptographic Test Vectors Runner (sug1-vectors.json)', () => {
  const vectorFileContent = fs.readFileSync(vectorFilePath, 'utf8');
  const vectorData: VectorFile = JSON.parse(vectorFileContent);

  describe('Official Published Standards Test Vectors', () => {
    it('matches RFC 3394 Section 4.6 (Wrap 256 Bits of Key Data with 256-Bit KEK)', async () => {
      // IETF RFC 3394 Section 4.6
      const kek = Buffer.from(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'hex',
      );
      const keyData = Buffer.from(
        '00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f',
        'hex',
      );
      const expectedWrapped =
        '28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21';

      const provider = new LocalKeyProvider({
        keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: kek },
      });

      const { wrappedKey } = await provider.wrapKey(keyData);
      expect(wrappedKey.toString('hex').toLowerCase()).toBe(expectedWrapped);

      const unwrapped = await provider.unwrapKey(Buffer.from(expectedWrapped, 'hex'));
      expect(unwrapped.equals(keyData)).toBe(true);
    });

    it('matches NIST SP 800-38D Test Case 13 (AES-256-GCM zero plaintext, zero AAD)', () => {
      // NIST SP 800-38D Case 13
      const key = Buffer.alloc(32);
      const iv = Buffer.alloc(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([cipher.update(Buffer.alloc(0)), cipher.final()]);
      const tag = cipher.getAuthTag();

      expect(ct.length).toBe(0);
      expect(tag.toString('hex').toLowerCase()).toBe('530f8afbc74536b9a963b4f1c4cb738b');
    });

    it('matches NIST SP 800-38D Test Case 14 (AES-256-GCM 16-byte plaintext)', () => {
      // NIST SP 800-38D Case 14
      const key = Buffer.alloc(32);
      const iv = Buffer.alloc(12);
      const plaintext = Buffer.alloc(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();

      expect(ct.toString('hex').toLowerCase()).toBe('cea7403d4d606b6e074ec5d3baf39d18');
      expect(tag.toString('hex').toLowerCase()).toBe('d0d1c8a799996bf0265b98b5d48ab919');
    });
  });

  describe('Positive Test Vectors', () => {
    for (const vec of vectorData.positive) {
      it(`passes positive vector [${vec.id}]: ${vec.description}`, async () => {
        const kek = Buffer.from(vec.kekHex, 'hex');
        const dek = Buffer.from(vec.dekHex, 'hex');
        const nonce = Buffer.from(vec.nonceHex, 'hex');
        const plaintext = Buffer.from(vec.plaintextHex, 'hex');

        const provider = new LocalKeyProvider({
          keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: kek },
        });

        // 1. Verify encryption with custom test keys matches vector
        const encrypted = await encryptBuffer(plaintext, {
          keyProvider: provider,
          aad: vec.aad,
          customDek: dek,
          customNonce: nonce,
        });

        expect(encrypted.header.wrappedDek.toString('hex')).toBe(vec.wrappedDekHex);
        expect(encrypted.header.authTag.toString('hex')).toBe(vec.authTagHex);
        expect(encrypted.ciphertext.toString('hex')).toBe(vec.ciphertextHex);
        expect(encrypted.serialized.toString('hex')).toBe(vec.serializedEnvelopeHex);

        // 2. Verify decryption from the pre-computed serialized envelope in the vector file
        const precomputedEnvelope = Buffer.from(vec.serializedEnvelopeHex, 'hex');
        const decrypted = await decryptBuffer(precomputedEnvelope, {
          keyProvider: provider,
          aad: vec.aad,
        });

        expect(decrypted.equals(plaintext)).toBe(true);
        if (vec.plaintextUtf8 !== undefined) {
          expect(decrypted.toString('utf8')).toBe(vec.plaintextUtf8);
        }
      });
    }
  });

  describe('Negative Test Vectors', () => {
    const posMap = new Map<string, PositiveVector>();
    for (const p of vectorData.positive) {
      posMap.set(p.id, p);
    }

    for (const neg of vectorData.negative) {
      it(`fails closed for negative vector [${neg.id}]: ${neg.description}`, async () => {
        const baseVec = posMap.get(neg.baseVectorId);
        if (!baseVec) {
          throw new Error(`Base vector ${neg.baseVectorId} not found`);
        }

        const kek = Buffer.from(baseVec.kekHex, 'hex');
        const baseProvider = new LocalKeyProvider({
          keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: kek },
        });

        let targetBuffer = Buffer.from(baseVec.serializedEnvelopeHex, 'hex');
        let targetAad = { ...baseVec.aad };
        let targetProvider = baseProvider;

        switch (neg.corruptType) {
          case 'magic':
            targetBuffer = Buffer.from(targetBuffer);
            targetBuffer.write('BAD1', 0, 4, 'ascii');
            break;
          case 'version':
            targetBuffer = Buffer.from(targetBuffer);
            targetBuffer.writeUInt8(2, 4);
            break;
          case 'truncate_header':
            targetBuffer = targetBuffer.subarray(0, 30);
            break;
          case 'flip_tag_bit': {
            targetBuffer = Buffer.from(targetBuffer);
            const tagOffset = 19 + 40; // 59
            targetBuffer[tagOffset] = (targetBuffer[tagOffset] ?? 0) ^ 0x01;
            break;
          }
          case 'flip_ciphertext_bit': {
            targetBuffer = Buffer.from(targetBuffer);
            const ctOffset = STANDARD_HEADER_BYTES;
            targetBuffer[ctOffset] = (targetBuffer[ctOffset] ?? 0) ^ 0x01;
            break;
          }
          case 'alter_aad_app_id':
            targetAad = { ...targetAad, appId: 'app_malicious' };
            break;
          case 'alter_aad_sha256':
            targetAad = { ...targetAad, sha256Plaintext: '0'.repeat(64) };
            break;
          case 'wrong_kek':
            if (!neg.wrongKekHex) throw new Error('Missing wrongKekHex in vector');
            targetProvider = new LocalKeyProvider({
              keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: Buffer.from(neg.wrongKekHex, 'hex') },
            });
            break;
          default:
            throw new Error(`Unknown corruptType: ${neg.corruptType}`);
        }

        const errorClassMap: Record<string, new (...args: readonly (string | number)[]) => Error> =
          {
            InvalidMagicError,
            UnsupportedVersionError,
            InvalidEnvelopeError,
            AuthenticationError,
            KeyProviderError,
          };

        const ExpectedErrorClass = errorClassMap[neg.expectedError];
        if (!ExpectedErrorClass) {
          throw new Error(`Unknown expectedError: ${neg.expectedError}`);
        }

        await expect(
          decryptBuffer(targetBuffer, {
            keyProvider: targetProvider,
            aad: targetAad,
          }),
        ).rejects.toThrow(ExpectedErrorClass);
      });
    }
  });
});
