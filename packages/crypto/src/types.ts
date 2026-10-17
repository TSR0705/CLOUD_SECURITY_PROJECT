/**
 * @sug/crypto/types
 * TypeScript interfaces and types for SUG1 envelope encryption.
 */

import type { Buffer } from 'node:buffer';

/**
 * Immutable artifact identity inputs required for AAD binding.
 * Binds ciphertext directly to tenant application, file, storage version, and plaintext digest.
 */
export interface CanonicalAadInput {
  readonly appId: string;
  readonly fileId: string;
  readonly storageVersionId: string;
  readonly sha256Plaintext: string;
}

/**
 * Alternative snake_case naming allowed for interop with database models.
 */
export interface RawAadInput {
  readonly appId?: string | undefined;
  readonly app_id?: string | undefined;
  readonly fileId?: string | undefined;
  readonly file_id?: string | undefined;
  readonly storageVersionId?: string | undefined;
  readonly storage_version_id?: string | undefined;
  readonly sha256Plaintext?: string | undefined;
  readonly sha256_plaintext?: string | undefined;
}

/**
 * Parsed header of a SUG1 binary envelope.
 */
export interface Sug1Header {
  readonly magic: string; // 'SUG1'
  readonly version: number; // 1
  readonly nonce: Buffer; // 12 bytes
  readonly wrappedDekLength: number; // e.g. 40
  readonly wrappedDek: Buffer; // e.g. 40 bytes
  readonly authTag: Buffer; // 16 bytes
  readonly headerLength: number; // Total header size in bytes (e.g. 75)
}

/**
 * Key Provider interface abstracting KEK storage (Local / Docker secret / SSM / KMS).
 */
export interface KeyProvider {
  readonly providerId: string;
  readonly defaultKeyReference: string;
  wrapKey(
    plaintextKey: Buffer,
    keyReference?: string,
  ): Promise<{ wrappedKey: Buffer; keyReference: string }>;
  unwrapKey(wrappedKey: Buffer, keyReference?: string): Promise<Buffer>;
}

/**
 * Configuration options for buffer encryption.
 */
export interface EncryptOptions {
  readonly keyProvider: KeyProvider;
  readonly aad: CanonicalAadInput | RawAadInput;
  readonly keyReference?: string | undefined;
  readonly customDek?: Buffer | undefined; // For reproducible test vectors only
  readonly customNonce?: Buffer | undefined; // For reproducible test vectors only
}

/**
 * Configuration options for buffer decryption.
 */
export interface DecryptOptions {
  readonly keyProvider: KeyProvider;
  readonly aad: CanonicalAadInput | RawAadInput;
  readonly keyReference?: string | undefined;
}

/**
 * Encrypted object output with structured metadata and raw serialized bytes.
 */
export interface EncryptedObject {
  readonly header: Sug1Header;
  readonly ciphertext: Buffer;
  readonly serialized: Buffer;
  readonly keyReference: string;
}
