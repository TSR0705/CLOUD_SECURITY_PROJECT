/**
 * @sug/crypto/aad
 * Canonical Authenticated Additional Data (AAD) generation and validation.
 * Binds ciphertext directly to immutable artifact identity.
 */

import { Buffer } from 'node:buffer';
import { InvalidAadError } from './errors.js';
import type { CanonicalAadInput, RawAadInput } from './types.js';

const AAD_DOMAIN_LABEL = 'SUG-AAD-V1';
const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;

/**
 * Normalizes and validates AAD input from either camelCase or snake_case formats.
 * Enforces non-empty strings and valid 64-character lowercase hexadecimal SHA-256 digests.
 */
export function normalizeAadInput(raw: CanonicalAadInput | RawAadInput): CanonicalAadInput {
  if (!raw || typeof raw !== 'object') {
    throw new InvalidAadError('AAD input must be a non-null object');
  }

  const rec = raw as RawAadInput;
  const appId = (rec.appId ?? rec.app_id)?.trim();
  if (!appId || typeof appId !== 'string') {
    throw new InvalidAadError('Missing or empty appId in AAD input');
  }

  const fileId = (rec.fileId ?? rec.file_id)?.trim();
  if (!fileId || typeof fileId !== 'string') {
    throw new InvalidAadError('Missing or empty fileId in AAD input');
  }

  const storageVersionId = (rec.storageVersionId ?? rec.storage_version_id)?.trim();
  if (!storageVersionId || typeof storageVersionId !== 'string') {
    throw new InvalidAadError('Missing or empty storageVersionId in AAD input');
  }

  let sha256 = (rec.sha256Plaintext ?? rec.sha256_plaintext)?.trim().toLowerCase();
  if (!sha256 || typeof sha256 !== 'string') {
    throw new InvalidAadError('Missing or empty sha256Plaintext in AAD input');
  }

  if (sha256.startsWith('\\x') || sha256.startsWith('0x')) {
    sha256 = sha256.slice(2);
  }

  if (!SHA256_HEX_REGEX.test(sha256)) {
    throw new InvalidAadError(
      `Invalid sha256Plaintext: must be 64 hexadecimal characters, got '${sha256}'`,
    );
  }

  return {
    appId,
    fileId,
    storageVersionId,
    sha256Plaintext: sha256,
  };
}

/**
 * Encodes canonical AAD into an unambiguous length-prefixed binary buffer.
 *
 * Encoding format:
 * [uint32BE(len)][ "SUG-AAD-V1"       ]
 * [uint32BE(len)][ appId              ]
 * [uint32BE(len)][ fileId             ]
 * [uint32BE(len)][ storageVersionId   ]
 * [uint32BE(len)][ sha256Plaintext    ]
 */
export function buildCanonicalAad(raw: CanonicalAadInput | RawAadInput): Buffer {
  const norm = normalizeAadInput(raw);

  const parts = [
    Buffer.from(AAD_DOMAIN_LABEL, 'utf8'),
    Buffer.from(norm.appId, 'utf8'),
    Buffer.from(norm.fileId, 'utf8'),
    Buffer.from(norm.storageVersionId, 'utf8'),
    Buffer.from(norm.sha256Plaintext, 'utf8'),
  ];

  const buffers: Buffer[] = [];
  for (const part of parts) {
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(part.length, 0);
    buffers.push(lenBuf, part);
  }

  return Buffer.concat(buffers);
}
