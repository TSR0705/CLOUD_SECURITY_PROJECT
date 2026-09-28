import crypto from 'node:crypto';

/**
 * Recursively sorts object keys in alphabetical order, ensuring deterministic JSON serialization.
 * Strips undefined values, preserves array order, and guarantees standard primitive representation.
 */
export function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== 'object') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }

  const sortedObj: Record<string, unknown> = {};
  const keys = Object.keys(value as Record<string, unknown>).sort();

  for (const key of keys) {
    const val = (value as Record<string, unknown>)[key];
    if (val !== undefined) {
      sortedObj[key] = sortKeys(val);
    }
  }

  return sortedObj;
}

/**
 * Serializes any data structure into canonical JSON representation:
 * - Deterministic alphabetical key ordering
 * - Zero unnecessary whitespace
 * - Consistent UTF-8 encoding
 */
export function toCanonicalJson(doc: unknown): string {
  const sorted = sortKeys(doc);
  return JSON.stringify(sorted);
}

/**
 * Computes the SHA-256 hash of a canonical JSON string, returning a 32-byte Buffer.
 */
export function computePolicyHash(canonicalJson: string): Buffer {
  return crypto.createHash('sha256').update(canonicalJson, 'utf8').digest();
}

/**
 * Computes the SHA-256 hash of a canonical JSON string, returning a 64-character lowercase hex string.
 */
export function computePolicyHashHex(canonicalJson: string): string {
  return crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('hex');
}
