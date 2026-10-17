import { Buffer } from 'node:buffer';

/**
 * 4-byte ASCII magic identifier for Secure Upload Gateway encrypted envelopes.
 */
export const SUG1_MAGIC = 'SUG1';
export const SUG1_MAGIC_BYTES: Buffer = Buffer.from(SUG1_MAGIC, 'ascii'); // 0x53 0x55 0x47 0x31

/**
 * Current supported SUG1 binary format version.
 */
export const SUG1_VERSION = 1; // 0x01

/**
 * AES-256-GCM cipher constants.
 */
export const DEK_BYTES = 32; // 256 bits
export const NONCE_BYTES = 12; // 96 bits (NIST SP 800-38D)
export const AUTH_TAG_BYTES = 16; // 128 bits

/**
 * RFC 3394 AES Key Wrap constants.
 */
export const RFC3394_DEFAULT_IV: Buffer = Buffer.from('A6A6A6A6A6A6A6A6', 'hex'); // 8 bytes
export const RFC3394_WRAPPED_DEK_BYTES = 40; // 32 bytes DEK + 8 bytes ICV

/**
 * SUG1 binary wire format header offsets and bounds.
 *
 * Offset  0..3:  Magic (4 bytes)
 * Offset  4:     Version (1 byte)
 * Offset  5..16: IV / Nonce (12 bytes)
 * Offset 17..18: Wrapped DEK Length (2 bytes, uint16BE)
 * Offset 19..N:  Wrapped DEK (variable bytes)
 * Followed by:   Auth Tag (16 bytes)
 * Followed by:   Ciphertext (stream to EOF)
 */
export const HEADER_PREFIX_BYTES = 19; // Offset to start of wrapped DEK
export const MIN_HEADER_BYTES = HEADER_PREFIX_BYTES + AUTH_TAG_BYTES; // 35 bytes (0-byte wrapped DEK)
export const STANDARD_HEADER_BYTES =
  HEADER_PREFIX_BYTES + RFC3394_WRAPPED_DEK_BYTES + AUTH_TAG_BYTES; // 75 bytes
