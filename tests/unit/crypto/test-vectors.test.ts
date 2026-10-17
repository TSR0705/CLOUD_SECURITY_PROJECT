import { Buffer } from 'node:buffer';
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
