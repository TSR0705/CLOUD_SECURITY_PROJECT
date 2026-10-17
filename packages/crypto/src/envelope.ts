/**
 * @sug/crypto/envelope
 * SUG1 binary envelope parser and serializer according to ADR-0010 Section 1.
 */

import { Buffer } from 'node:buffer';
import {
  AUTH_TAG_BYTES,
  HEADER_PREFIX_BYTES,
  MIN_HEADER_BYTES,
  NONCE_BYTES,
  SUG1_MAGIC,
  SUG1_MAGIC_BYTES,
  SUG1_VERSION,
} from './constants.js';
import { InvalidEnvelopeError, InvalidMagicError, UnsupportedVersionError } from './errors.js';
import type { Sug1Header } from './types.js';

/**
 * Parses and strictly validates a SUG1 envelope header from a binary buffer.
 *
 * Header structure:
 * - Offset 0..3:   Magic (4 bytes, 'SUG1')
 * - Offset 4:      Version (1 byte, 0x01)
 * - Offset 5..16:  IV / Nonce (12 bytes)
 * - Offset 17..18: Wrapped DEK Length (2 bytes, uint16BE)
 * - Offset 19..N:  Wrapped DEK (variable bytes)
 * - Followed by:   Auth Tag (16 bytes)
 *
 * Total header length = 19 + wrappedDekLength + 16
 */
export function parseSug1Header(buffer: Buffer): Sug1Header {
  if (!Buffer.isBuffer(buffer)) {
    throw new InvalidEnvelopeError('Envelope data must be a Buffer');
  }

  if (buffer.length < MIN_HEADER_BYTES) {
    throw new InvalidEnvelopeError(
      `Envelope buffer too small: expected at least ${MIN_HEADER_BYTES} bytes, got ${buffer.length}`,
    );
  }

  // 1. Verify Magic
  const magic = buffer.subarray(0, 4).toString('ascii');
  if (magic !== SUG1_MAGIC) {
    throw new InvalidMagicError(magic);
  }

  // 2. Verify Version
  const version = buffer.readUInt8(4);
  if (version !== SUG1_VERSION) {
    throw new UnsupportedVersionError(version);
  }

  // 3. Extract Nonce (12 bytes)
  const nonce = Buffer.from(buffer.subarray(5, 5 + NONCE_BYTES));

  // 4. Extract Wrapped DEK Length (uint16BE)
  const wrappedDekLength = buffer.readUInt16BE(17);
  const minRequiredLength = HEADER_PREFIX_BYTES + wrappedDekLength + AUTH_TAG_BYTES;

  if (buffer.length < minRequiredLength) {
    throw new InvalidEnvelopeError(
      `Truncated envelope header: expected at least ${minRequiredLength} bytes for wrapped DEK (${wrappedDekLength} bytes) + auth tag, got ${buffer.length}`,
    );
  }

  // 5. Extract Wrapped DEK
  const wrappedDekOffset = HEADER_PREFIX_BYTES;
  const wrappedDekEnd = wrappedDekOffset + wrappedDekLength;
  const wrappedDek = Buffer.from(buffer.subarray(wrappedDekOffset, wrappedDekEnd));

  // 6. Extract Auth Tag (16 bytes)
  const authTagOffset = wrappedDekEnd;
  const authTagEnd = authTagOffset + AUTH_TAG_BYTES;
  const authTag = Buffer.from(buffer.subarray(authTagOffset, authTagEnd));

  return {
    magic,
    version,
    nonce,
    wrappedDekLength,
    wrappedDek,
    authTag,
    headerLength: authTagEnd,
  };
}

/**
 * Serializes a SUG1 header and ciphertext into a single binary envelope Buffer.
 */
export function serializeSug1Envelope(
  header: {
    readonly nonce: Buffer;
    readonly wrappedDek: Buffer;
    readonly authTag: Buffer;
    readonly version?: number;
  },
  ciphertext: Buffer,
): Buffer {
  if (!Buffer.isBuffer(header.nonce) || header.nonce.length !== NONCE_BYTES) {
    throw new InvalidEnvelopeError(
      `Nonce must be a Buffer of exactly ${NONCE_BYTES} bytes, got ${header.nonce?.length ?? 0}`,
    );
  }

  if (!Buffer.isBuffer(header.authTag) || header.authTag.length !== AUTH_TAG_BYTES) {
    throw new InvalidEnvelopeError(
      `Auth tag must be a Buffer of exactly ${AUTH_TAG_BYTES} bytes, got ${header.authTag?.length ?? 0}`,
    );
  }

  if (!Buffer.isBuffer(header.wrappedDek)) {
    throw new InvalidEnvelopeError('Wrapped DEK must be a Buffer');
  }

  if (header.wrappedDek.length > 65535) {
    throw new InvalidEnvelopeError(
      `Wrapped DEK length exceeds maximum 65535 bytes: ${header.wrappedDek.length}`,
    );
  }

  if (!Buffer.isBuffer(ciphertext)) {
    throw new InvalidEnvelopeError('Ciphertext must be a Buffer');
  }

  const version = header.version ?? SUG1_VERSION;
  const prefix = Buffer.alloc(HEADER_PREFIX_BYTES);

  // Magic 'SUG1' (4 bytes)
  SUG1_MAGIC_BYTES.copy(prefix, 0);
  // Version (1 byte)
  prefix.writeUInt8(version, 4);
  // Nonce (12 bytes)
  header.nonce.copy(prefix, 5);
  // Wrapped DEK length (2 bytes uint16BE)
  prefix.writeUInt16BE(header.wrappedDek.length, 17);

  return Buffer.concat([prefix, header.wrappedDek, header.authTag, ciphertext]);
}

/**
 * Extracts the ciphertext payload slice following the validated header.
 */
export function extractCiphertext(envelopeBuffer: Buffer, header: Sug1Header): Buffer {
  if (envelopeBuffer.length < header.headerLength) {
    throw new InvalidEnvelopeError(
      `Envelope buffer is shorter than header length: ${envelopeBuffer.length} < ${header.headerLength}`,
    );
  }
  return envelopeBuffer.subarray(header.headerLength);
}
