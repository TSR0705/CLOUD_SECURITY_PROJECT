/**
 * @sug/crypto/providers/local-provider
 * Local file/secret/env-based Key Encryption Key (KEK) provider implementing RFC 3394 Key Wrap.
 */

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DEK_BYTES, RFC3394_DEFAULT_IV, RFC3394_WRAPPED_DEK_BYTES } from '../constants.js';
import { KeyProviderError } from '../errors.js';
import type { KeyProvider } from '../types.js';

export const DEFAULT_LOCAL_KEY_REFERENCE = 'local:default';
const HEX_64_REGEX = /^[0-9a-f]{64}$/i;

export interface LocalKeyProviderOptions {
  /**
   * Pre-configured map of key references to 32-byte KEKs (Buffer or hex string).
   */
  readonly keys?: Record<string, Buffer | string> | undefined;
  /**
   * Default key reference to use if none specified (default: 'local:default').
   */
  readonly defaultKeyReference?: string | undefined;
  /**
   * Explicit file path to load the default KEK from (e.g. Docker secret '/run/secrets/kek').
   */
  readonly secretFilePath?: string | undefined;
  /**
   * Directory to look up secret files by key reference (e.g. process.env.SECRETS_DIR).
   */
  readonly secretsDir?: string | undefined;
}

/**
 * Normalizes a raw KEK value (Buffer or string) to a 32-byte Buffer.
 */
function normalizeKek(raw: Buffer | string, sourceName: string): Buffer {
  if (Buffer.isBuffer(raw)) {
    if (raw.length === DEK_BYTES) {
      return Buffer.from(raw);
    }
    // Check if buffer contains text-encoded hex or base64 (common in secret files)
    const asText = raw.toString('utf8').trim();
    if (HEX_64_REGEX.test(asText)) {
      return Buffer.from(asText, 'hex');
    }
    const b64Buf = Buffer.from(asText, 'base64');
    if (b64Buf.length === DEK_BYTES) {
      return b64Buf;
    }
    throw new KeyProviderError(
      `Invalid KEK length from ${sourceName}: expected ${DEK_BYTES} bytes, got ${raw.length}`,
    );
  }

  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (HEX_64_REGEX.test(trimmed)) {
      return Buffer.from(trimmed, 'hex');
    }
    // Try base64 if 44 characters
    const b64Buf = Buffer.from(trimmed, 'base64');
    if (b64Buf.length === DEK_BYTES) {
      return b64Buf;
    }
    // Try raw utf8 if 32 bytes
    const utf8Buf = Buffer.from(trimmed, 'utf8');
    if (utf8Buf.length === DEK_BYTES) {
      return utf8Buf;
    }
    throw new KeyProviderError(
      `Invalid KEK format from ${sourceName}: must be 32 bytes (64-char hex, base64, or 32 raw bytes)`,
    );
  }

  throw new KeyProviderError(`Unsupported KEK type from ${sourceName}: expected Buffer or string`);
}

export class LocalKeyProvider implements KeyProvider {
  public readonly providerId = 'local';
  public readonly defaultKeyReference: string;

  private readonly keyStore = new Map<string, Buffer>();
  private readonly secretFilePath?: string | undefined;
  private readonly secretsDir?: string | undefined;

  constructor(options: LocalKeyProviderOptions = {}) {
    this.defaultKeyReference = options.defaultKeyReference ?? DEFAULT_LOCAL_KEY_REFERENCE;
    this.secretFilePath = options.secretFilePath;
    this.secretsDir = options.secretsDir ?? process.env.SECRETS_DIR;

    if (options.keys) {
      for (const [ref, keyVal] of Object.entries(options.keys)) {
        this.keyStore.set(ref, normalizeKek(keyVal, `key option '${ref}'`));
      }
    }
  }

  /**
   * Registers or updates a KEK in the local store.
   */
  public addKey(keyReference: string, key: Buffer | string): void {
    if (!keyReference || typeof keyReference !== 'string') {
      throw new KeyProviderError('Key reference must be a non-empty string');
    }
    this.keyStore.set(keyReference, normalizeKek(key, `key reference '${keyReference}'`));
  }

  /**
   * Resolves the 32-byte KEK for the given reference.
   * Checks in order:
   * 1. In-memory store
   * 2. Explicit secretFilePath (for default reference)
   * 3. secretsDir / <reference> or secretsDir / kek
   * 4. Standard Docker secrets (/run/secrets/<ref> or /run/secrets/kek)
   * 5. Environment variables (SUG_LOCAL_KEK or SUG_KEK)
   */
  private resolveKek(keyReference: string): Buffer {
    // 1. In-memory store
    const existing = this.keyStore.get(keyReference);
    if (existing) {
      return existing;
    }

    // 2. Explicit secret file path (if requesting default key)
    if (keyReference === this.defaultKeyReference && this.secretFilePath) {
      if (fs.existsSync(this.secretFilePath)) {
        try {
          const content = fs.readFileSync(this.secretFilePath);
          const kek = normalizeKek(content, `secret file '${this.secretFilePath}'`);
          this.keyStore.set(keyReference, kek);
          return kek;
        } catch (err) {
          throw new KeyProviderError(
            `Failed to load KEK from secret file '${this.secretFilePath}': ${(err as Error).message}`,
            { cause: err as Error },
          );
        }
      }
    }

    // 3. secretsDir lookup
    if (this.secretsDir && fs.existsSync(this.secretsDir)) {
      const normalizedSecretsDir = path.resolve(this.secretsDir);
      const sanitizedRef = keyReference.replace(/[^a-zA-Z0-9_-]/g, '_');
      const candidatePaths = [
        path.join(normalizedSecretsDir, sanitizedRef),
        path.join(normalizedSecretsDir, 'kek'),
        path.join(normalizedSecretsDir, 'sug_kek'),
      ];
      for (const cand of candidatePaths) {
        const resolvedCand = path.resolve(cand);
        if (!resolvedCand.startsWith(normalizedSecretsDir)) {
          continue;
        }
        if (fs.existsSync(resolvedCand)) {
          try {
            const content = fs.readFileSync(resolvedCand);
            const kek = normalizeKek(content, `secretsDir '${resolvedCand}'`);
            this.keyStore.set(keyReference, kek);
            return kek;
          } catch {
            // continue checking next candidates
          }
        }
      }
    }

    // 4. Standard Docker secret locations
    const dockerSecretPaths = [
      `/run/secrets/${keyReference.replace(/[^a-zA-Z0-9_-]/g, '_')}`,
      '/run/secrets/sug_kek',
      '/run/secrets/kek',
    ];
    for (const cand of dockerSecretPaths) {
      if (fs.existsSync(cand)) {
        try {
          const content = fs.readFileSync(cand);
          const kek = normalizeKek(content, `docker secret '${cand}'`);
          this.keyStore.set(keyReference, kek);
          return kek;
        } catch {
          // continue
        }
      }
    }

    // 5. Environment variables (SUG_LOCAL_KEK or SUG_KEK)
    const envKek = process.env.SUG_LOCAL_KEK ?? process.env.SUG_KEK;
    if (envKek && (keyReference === this.defaultKeyReference || keyReference === 'local:default')) {
      const kek = normalizeKek(envKek, 'environment variable SUG_KEK');
      this.keyStore.set(keyReference, kek);
      return kek;
    }

    throw new KeyProviderError(
      `Key reference '${keyReference}' not found: no KEK configured in memory, file, or environment`,
    );
  }

  /**
   * Wraps a 32-byte DEK using RFC 3394 AES-256 Key Wrap.
   */
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

    const kek = this.resolveKek(ref);

    try {
      const cipher = crypto.createCipheriv('id-aes256-wrap', kek, RFC3394_DEFAULT_IV);
      const wrappedKey = Buffer.concat([cipher.update(plaintextKey), cipher.final()]);
      return { wrappedKey, keyReference: ref };
    } catch (err) {
      throw new KeyProviderError(
        `Failed to wrap DEK with key reference '${ref}': ${(err as Error).message}`,
        { cause: err as Error },
      );
    }
  }

  /**
   * Unwraps a 40-byte wrapped DEK using RFC 3394 AES-256 Key Wrap.
   */
  public async unwrapKey(wrappedKey: Buffer, keyReference?: string): Promise<Buffer> {
    const ref = keyReference ?? this.defaultKeyReference;
    if (!Buffer.isBuffer(wrappedKey) || wrappedKey.length !== RFC3394_WRAPPED_DEK_BYTES) {
      throw new KeyProviderError(
        `Wrapped DEK must be a ${RFC3394_WRAPPED_DEK_BYTES}-byte Buffer, got ${wrappedKey?.length ?? 0} bytes`,
      );
    }

    const kek = this.resolveKek(ref);

    try {
      const decipher = crypto.createDecipheriv('id-aes256-wrap', kek, RFC3394_DEFAULT_IV);
      const unwrapped = Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
      if (unwrapped.length !== DEK_BYTES) {
        throw new KeyProviderError(
          `Unwrapped DEK length mismatch: expected ${DEK_BYTES} bytes, got ${unwrapped.length}`,
        );
      }
      return unwrapped;
    } catch (err) {
      throw new KeyProviderError(
        `Failed to unwrap DEK with key reference '${ref}': integrity check failed or wrong KEK`,
        { cause: err as Error },
      );
    }
  }
}
