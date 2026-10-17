/**
 * @sug/crypto/cipher
 * AES-256-GCM envelope encryption and verify-before-release decryption primitives.
 */

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { buildCanonicalAad, normalizeAadInput } from './aad.js';
import { AUTH_TAG_BYTES, DEK_BYTES, NONCE_BYTES, SUG1_MAGIC, SUG1_VERSION } from './constants.js';
import { extractCiphertext, parseSug1Header, serializeSug1Envelope } from './envelope.js';
import {
  AuthenticationError,
  CryptoError,
  InvalidAadError,
  InvalidEnvelopeError,
} from './errors.js';
import type { DecryptOptions, EncryptedObject, EncryptOptions, Sug1Header } from './types.js';

/**
 * Generates a fresh cryptographically secure 256-bit (32-byte) Data Encryption Key (DEK).
 */
export function generateDek(): Buffer {
  return crypto.randomBytes(DEK_BYTES);
}

/**
 * Generates a fresh cryptographically secure 96-bit (12-byte) CSPRNG nonce.
 * Conforms to NIST SP 800-38D recommendation for AES-GCM.
 */
export function generateNonce(): Buffer {
  return crypto.randomBytes(NONCE_BYTES);
}

/**
 * Encrypts a plaintext buffer using AES-256-GCM envelope encryption.
 *
 * Algorithm:
 * 1. Generates fresh 256-bit DEK and fresh 96-bit CSPRNG nonce.
 * 2. Validates that declared sha256Plaintext matches the actual plaintext digest.
 * 3. Encodes canonical AAD binding (appId, fileId, storageVersionId, sha256Plaintext).
 * 4. Encrypts plaintext with AES-256-GCM and computes 128-bit authentication tag.
 * 5. Wraps DEK with the specified KeyProvider (RFC 3394 AES Key Wrap).
 * 6. Serializes header + wrapped DEK + auth tag + ciphertext into canonical SUG1 binary envelope.
 * 7. Securely zeroes in-memory DEK before returning.
 */
export async function encryptBuffer(
  plaintext: Buffer,
  options: EncryptOptions,
): Promise<EncryptedObject> {
  if (!Buffer.isBuffer(plaintext)) {
    throw new CryptoError('Plaintext must be a Buffer');
  }

  if (!options || !options.keyProvider) {
    throw new CryptoError('EncryptOptions.keyProvider is required');
  }

  // 1. Verify and normalize AAD input
  const actualPlaintextSha = crypto.createHash('sha256').update(plaintext).digest('hex');
  const normalizedAadInput = normalizeAadInput(options.aad);

  // Validate that caller-provided sha256Plaintext matches actual plaintext digest
  if (
    normalizedAadInput.sha256Plaintext.length !== actualPlaintextSha.length ||
    !crypto.timingSafeEqual(
      Buffer.from(normalizedAadInput.sha256Plaintext, 'ascii'),
      Buffer.from(actualPlaintextSha, 'ascii'),
    )
  ) {
    throw new InvalidAadError(
      `AAD sha256Plaintext mismatch: declared '${normalizedAadInput.sha256Plaintext}', but plaintext hashes to '${actualPlaintextSha}'`,
    );
  }

  const canonicalAad = buildCanonicalAad(normalizedAadInput);

  // 2. Obtain DEK and Nonce (supports test vectors with custom keys)
  const dek = options.customDek ? Buffer.from(options.customDek) : generateDek();
  if (dek.length !== DEK_BYTES) {
    throw new CryptoError(`DEK must be exactly ${DEK_BYTES} bytes, got ${dek.length}`);
  }

  const nonce = options.customNonce ? Buffer.from(options.customNonce) : generateNonce();
  if (nonce.length !== NONCE_BYTES) {
    throw new CryptoError(`Nonce must be exactly ${NONCE_BYTES} bytes, got ${nonce.length}`);
  }

  let ciphertext: Buffer;
  let authTag: Buffer;

  try {
    // 3. Encrypt with AES-256-GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', dek, nonce);
    cipher.setAAD(canonicalAad);
    ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    authTag = cipher.getAuthTag();

    if (authTag.length !== AUTH_TAG_BYTES) {
      throw new CryptoError(
        `Invalid auth tag length: expected ${AUTH_TAG_BYTES} bytes, got ${authTag.length}`,
      );
    }
  } catch (err) {
    // Securely wipe DEK on failure
    dek.fill(0);
    throw err instanceof CryptoError
      ? err
      : new CryptoError(`Encryption failed: ${(err as Error).message}`, { cause: err as Error });
  }

  let wrappedKey: Buffer;
  let keyReference: string;

  try {
    // 4. Wrap DEK via KeyProvider
    const wrapResult = await options.keyProvider.wrapKey(dek, options.keyReference);
    wrappedKey = wrapResult.wrappedKey;
    keyReference = wrapResult.keyReference;
  } finally {
    // 5. Zero out plaintext DEK from memory immediately
    dek.fill(0);
  }

  // 6. Build Sug1Header and serialized binary envelope
  const header: Sug1Header = {
    magic: SUG1_MAGIC,
    version: SUG1_VERSION,
    nonce,
    wrappedDekLength: wrappedKey.length,
    wrappedDek: wrappedKey,
    authTag,
    headerLength: 19 + wrappedKey.length + authTag.length,
  };

  const serialized = serializeSug1Envelope(header, ciphertext);

  return {
    header,
    ciphertext,
    serialized,
    keyReference,
  };
}

/**
 * Decrypts a SUG1 envelope buffer with strict verify-before-release semantics.
 *
 * Security Invariant:
 * Plaintext is NEVER emitted or returned if the AES-GCM authentication tag
 * fails verification, if AAD is altered, if the envelope is corrupted, or if
 * the recomputed plaintext SHA-256 digest does not match the bound AAD identity.
 */
export async function decryptBuffer(
  envelope: Buffer | { serialized: Buffer } | { header: Sug1Header; ciphertext: Buffer },
  options: DecryptOptions,
): Promise<Buffer> {
  if (!options || !options.keyProvider) {
    throw new CryptoError('DecryptOptions.keyProvider is required');
  }

  let header: Sug1Header;
  let ciphertext: Buffer;

  if (Buffer.isBuffer(envelope)) {
    header = parseSug1Header(envelope);
    ciphertext = extractCiphertext(envelope, header);
  } else if ('serialized' in envelope && Buffer.isBuffer(envelope.serialized)) {
    header = parseSug1Header(envelope.serialized);
    ciphertext = extractCiphertext(envelope.serialized, header);
  } else if ('header' in envelope && 'ciphertext' in envelope) {
    header = envelope.header;
    ciphertext = envelope.ciphertext;
  } else {
    throw new InvalidEnvelopeError('Invalid envelope input: expected Buffer or EncryptedObject');
  }

  // 1. Build canonical AAD buffer (validates expected identity)
  const normalizedAadInput = normalizeAadInput(options.aad);
  const canonicalAad = buildCanonicalAad(normalizedAadInput);

  // 2. Unwrap DEK using KeyProvider
  const dek = await options.keyProvider.unwrapKey(header.wrappedDek, options.keyReference);

  // 3. Verify-Before-Release Decryption
  let plaintextBuffer: Buffer | null = null;
  let chunk1: Buffer | null = null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', dek, header.nonce);
    decipher.setAAD(canonicalAad);
    decipher.setAuthTag(header.authTag);

    chunk1 = decipher.update(ciphertext);
    const chunk2 = decipher.final(); // Authenticates tag and AAD against ciphertext

    plaintextBuffer = Buffer.concat([chunk1, chunk2]);
  } catch (err) {
    if (chunk1) {
      chunk1.fill(0);
    }
    throw new AuthenticationError(
      `Ciphertext authentication failed: tag mismatch, altered AAD, or corrupted payload. ${(err as Error).message}`,
    );
  } finally {
    // Securely wipe unwrapped DEK from memory
    dek.fill(0);
  }

  if (plaintextBuffer === null) {
    throw new AuthenticationError('Authentication failed: no plaintext produced');
  }

  // 4. Independently verify that the recomputed plaintext digest strictly matches the expected AAD sha256Plaintext
  const computedPlaintextSha = crypto.createHash('sha256').update(plaintextBuffer).digest('hex');
  const digestMatches =
    computedPlaintextSha.length === normalizedAadInput.sha256Plaintext.length &&
    crypto.timingSafeEqual(
      Buffer.from(computedPlaintextSha, 'ascii'),
      Buffer.from(normalizedAadInput.sha256Plaintext, 'ascii'),
    );

  if (!digestMatches) {
    plaintextBuffer.fill(0);
    throw new AuthenticationError(
      `Plaintext digest verification failed: expected '${normalizedAadInput.sha256Plaintext}', computed '${computedPlaintextSha}'`,
    );
  }

  return plaintextBuffer;
}
