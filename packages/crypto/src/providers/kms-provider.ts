/**
 * @sug/crypto/providers/kms-provider
 * KMS Key Provider interface and hermetic test stub according to ADR-0010.
 * In live mode, fails closed until cloud deployment phases.
 * In mock mode, enables hermetic multi-provider unit testing.
 */

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { DEK_BYTES, RFC3394_DEFAULT_IV, RFC3394_WRAPPED_DEK_BYTES } from '../constants.js';
import { KeyProviderError } from '../errors.js';
import type { KeyProvider } from '../types.js';

export const DEFAULT_MOCK_KMS_KEY_REF = 'arn:aws:kms:us-east-1:123456789012:key/mock-sug-key-01';

export interface KmsKeyProviderOptions {
  /**
   * If true, enables hermetic simulated KMS wrapping via derived keys for tests.
   * If false, fails closed with KeyProviderError.
   */
  readonly mock?: boolean | undefined;
  /**
   * Default KMS key ARN or resource ID.
   */
  readonly defaultKeyReference?: string | undefined;
}

export class KmsKeyProvider implements KeyProvider {
  public readonly providerId = 'kms';
  public readonly defaultKeyReference: string;
  private readonly mock: boolean;

  constructor(options: KmsKeyProviderOptions = {}) {
    this.mock = options.mock ?? false;
    this.defaultKeyReference = options.defaultKeyReference ?? DEFAULT_MOCK_KMS_KEY_REF;

    if (this.mock && process.env.NODE_ENV === 'production') {
      throw new KeyProviderError(
        'Mock KMS provider is strictly forbidden when NODE_ENV is set to "production"',
      );
    }
  }

  private deriveMockKey(keyReference: string): Buffer {
    // Derive deterministic 32-byte key from keyReference for test mock
    return crypto.createHash('sha256').update(`kms-mock-kek:${keyReference}`).digest();
  }

  public async wrapKey(
    plaintextKey: Buffer,
    keyReference?: string,
  ): Promise<{ wrappedKey: Buffer; keyReference: string }> {
    const ref = keyReference ?? this.defaultKeyReference;

    if (!Buffer.isBuffer(plaintextKey) || plaintextKey.length !== DEK_BYTES) {
      throw new KeyProviderError(
        `DEK must be a 32-byte Buffer, got ${plaintextKey?.length ?? 0} bytes`,
      );
    }

    if (!this.mock) {
      throw new KeyProviderError(
        `Live KMS provider is not enabled for key reference '${ref}'. Cloud KMS integration is scheduled for production phase deployment. Enable mock: true for hermetic tests.`,
      );
    }

    const mockKek = this.deriveMockKey(ref);
    try {
      const cipher = crypto.createCipheriv('id-aes256-wrap', mockKek, RFC3394_DEFAULT_IV);
      const wrappedKey = Buffer.concat([cipher.update(plaintextKey), cipher.final()]);
      return { wrappedKey, keyReference: ref };
    } catch (err) {
      throw new KeyProviderError(`Mock KMS wrap failed for '${ref}': ${(err as Error).message}`, {
        cause: err as Error,
      });
    }
  }

  public async unwrapKey(wrappedKey: Buffer, keyReference?: string): Promise<Buffer> {
    const ref = keyReference ?? this.defaultKeyReference;

    if (!Buffer.isBuffer(wrappedKey) || wrappedKey.length !== RFC3394_WRAPPED_DEK_BYTES) {
      throw new KeyProviderError(
        `Wrapped DEK must be a ${RFC3394_WRAPPED_DEK_BYTES}-byte Buffer, got ${wrappedKey?.length ?? 0} bytes`,
      );
    }

    if (!this.mock) {
      throw new KeyProviderError(
        `Live KMS provider is not enabled for key reference '${ref}'. Cloud KMS integration is scheduled for production phase deployment. Enable mock: true for hermetic tests.`,
      );
    }

    const mockKek = this.deriveMockKey(ref);
    try {
      const decipher = crypto.createDecipheriv('id-aes256-wrap', mockKek, RFC3394_DEFAULT_IV);
      const unwrapped = Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
      if (unwrapped.length !== DEK_BYTES) {
        throw new KeyProviderError(
          `Unwrapped DEK length mismatch: expected ${DEK_BYTES} bytes, got ${unwrapped.length}`,
        );
      }
      return unwrapped;
    } catch (err) {
      throw new KeyProviderError(
        `Mock KMS unwrap failed for '${ref}': integrity check failed or wrong key reference`,
        { cause: err as Error },
      );
    }
  }
}
