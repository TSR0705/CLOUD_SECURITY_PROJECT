import type { MimeValidationResult } from './types.js';

const MIME_STRUCTURE_REGEX = /^[a-zA-Z0-9!#$%&'*+^_`|~-]+\/[a-zA-Z0-9!#$%&'*+^_`|~.-]+$/;

export interface ParsedMime {
  isValid: boolean;
  baseMime: string;
  parameters: Record<string, string>;
}

/**
 * Deterministically parses and normalizes a MIME type string according to RFC 2045/6838.
 *
 * Normalization Rules:
 * 1. Trims leading and trailing whitespace.
 * 2. Extracts base 'type/subtype' and converts to lowercase.
 * 3. Strips and parses optional parameters (e.g. '; charset=utf-8').
 * 4. Rejects control characters, null bytes, multiple slashes, or missing type/subtype.
 */
export function parseAndNormalizeMime(rawMime?: string | null): ParsedMime {
  const raw = String(rawMime ?? '').trim();
  if (!raw) {
    return { isValid: false, baseMime: '', parameters: {} };
  }

  // Reject control characters or null bytes
  if (/[\x00-\x1F\x7F-\x9F]/.test(raw)) {
    return { isValid: false, baseMime: '', parameters: {} };
  }

  const parts = raw.split(';');
  const baseMime = (parts[0] ?? '').trim().toLowerCase();

  if (!MIME_STRUCTURE_REGEX.test(baseMime)) {
    return { isValid: false, baseMime: '', parameters: {} };
  }

  const parameters: Record<string, string> = {};
  for (let i = 1; i < parts.length; i++) {
    const param = (parts[i] ?? '').trim();
    if (param) {
      const eqIdx = param.indexOf('=');
      if (eqIdx > 0) {
        const key = param.substring(0, eqIdx).trim().toLowerCase();
        let val = param.substring(eqIdx + 1).trim();
        // Remove surrounding quotes if present
        if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) {
          val = val.substring(1, val.length - 1);
        }
        parameters[key] = val;
      }
    }
  }

  return {
    isValid: true,
    baseMime,
    parameters,
  };
}

/**
 * Validates untrusted client-declared MIME type against policy allowlist and blocklist.
 */
export function validateDeclaredMime(
  rawMime?: string | null,
  allowedMimeTypes: readonly string[] = [],
  blockedMimeTypes: readonly string[] = [],
): MimeValidationResult {
  const raw = String(rawMime ?? '').trim();

  if (!raw) {
    return {
      allowed: false,
      reasonCode: 'MIME_MISSING',
      normalizedMime: '',
      rawMime: raw,
      reason: 'Declared MIME type is missing or empty',
    };
  }

  const parsed = parseAndNormalizeMime(raw);
  if (!parsed.isValid || !parsed.baseMime) {
    return {
      allowed: false,
      reasonCode: 'MIME_MALFORMED',
      normalizedMime: '',
      rawMime: raw,
      reason: `Declared MIME type '${raw}' is malformed or invalid`,
    };
  }

  const norm = parsed.baseMime;

  const normalizedBlocked = new Set(
    blockedMimeTypes.map((m) => parseAndNormalizeMime(m).baseMime || m.toLowerCase().trim()),
  );

  if (normalizedBlocked.has(norm)) {
    return {
      allowed: false,
      reasonCode: 'MIME_BLOCKED',
      normalizedMime: norm,
      rawMime: raw,
      parameters: parsed.parameters,
      reason: `MIME type '${norm}' is explicitly blocked by policy`,
    };
  }

  const normalizedAllowed = new Set(
    allowedMimeTypes.map((m) => parseAndNormalizeMime(m).baseMime || m.toLowerCase().trim()),
  );

  if (normalizedAllowed.size > 0 && !normalizedAllowed.has(norm)) {
    return {
      allowed: false,
      reasonCode: 'MIME_NOT_ALLOWED',
      normalizedMime: norm,
      rawMime: raw,
      parameters: parsed.parameters,
      reason: `MIME type '${norm}' is not permitted by policy`,
    };
  }

  return {
    allowed: true,
    reasonCode: 'MIME_ALLOWED',
    normalizedMime: norm,
    rawMime: raw,
    parameters: parsed.parameters,
    reason: `MIME type '${norm}' is permitted by policy`,
  };
}
