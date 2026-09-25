import crypto from 'node:crypto';

export const KEY_PREFIX_LENGTH = 8;
export const SECRET_BYTES_LENGTH = 32;
export const SECRET_HEX_LENGTH = 64;
export const API_KEY_REGEX = /^sug_([a-f0-9]{8})_([a-f0-9]{64})$/i;

export interface GeneratedRawKey {
  rawKey: string;
  keyPrefix: string;
  secret: string;
}

export interface ParsedRawKey {
  keyPrefix: string;
  secret: string;
}

/**
 * Generates a high-entropy API key using Node's cryptographic random source.
 * Format: sug_<8-char-hex-prefix>_<64-char-hex-secret>
 *
 * - keyPrefix provides 32 bits of collision resistance for indexed DB lookups.
 * - secret provides 256 bits of CSPRNG entropy.
 */
export function generateRawKey(): GeneratedRawKey {
  const keyPrefix = crypto
    .randomBytes(KEY_PREFIX_LENGTH / 2)
    .toString('hex')
    .toLowerCase();
  const secret = crypto.randomBytes(SECRET_BYTES_LENGTH).toString('hex').toLowerCase();
  const rawKey = `sug_${keyPrefix}_${secret}`;
  return { rawKey, keyPrefix, secret };
}

/**
 * Parses and validates an API key string against strict format rules.
 * Returns null if the key format, lengths, or character sets are invalid.
 */
export function parseRawKey(rawKey: unknown): ParsedRawKey | null {
  if (typeof rawKey !== 'string') {
    return null;
  }
  const trimmed = rawKey.trim();
  const match = API_KEY_REGEX.exec(trimmed);
  if (!match || match.length !== 3) {
    return null;
  }
  const keyPrefix = match[1]?.toLowerCase();
  const secret = match[2]?.toLowerCase();
  if (!keyPrefix || !secret) {
    return null;
  }
  return { keyPrefix, secret };
}

/**
 * Computes HMAC-SHA-256 over the API key secret using the application pepper.
 * Returns a 32-byte Buffer suitable for storing in api_keys.key_hmac.
 */
export function computeKeyHmac(secret: string, pepper: string): Buffer {
  if (!secret || typeof secret !== 'string') {
    throw new Error('API key secret is required to compute HMAC');
  }
  if (!pepper || typeof pepper !== 'string') {
    throw new Error('Application pepper is required to compute HMAC');
  }

  // If pepper is 64 hex characters (32 bytes), use binary buffer; otherwise UTF-8 buffer
  const pepperBuffer =
    pepper.length === 64 && /^[0-9a-fA-F]{64}$/.test(pepper)
      ? Buffer.from(pepper, 'hex')
      : Buffer.from(pepper, 'utf8');

  return crypto.createHmac('sha256', pepperBuffer).update(Buffer.from(secret, 'utf8')).digest();
}

/**
 * Compares two HMAC buffers in constant time using crypto.timingSafeEqual.
 * Prevents timing side-channel attacks during authentication.
 *
 * Safely returns false if buffer lengths differ without throwing an uncaught exception.
 */
export function constantTimeCompare(a: unknown, b: unknown): boolean {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    return false;
  }
  if (a.length !== b.length || a.length !== 32) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}
