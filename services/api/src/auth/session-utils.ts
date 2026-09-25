/**
 * Utility functions for upload authorization, object key generation, and filename sanitization.
 */

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Validates that a string is a well-formed UUID.
 */
export function isValidUuid(val: unknown): val is string {
  return typeof val === 'string' && UUID_REGEX.test(val.trim());
}

/**
 * Safely extracts and normalizes a UUID string, or returns undefined.
 */
export function toSafeUuid(val: unknown): string | undefined {
  if (typeof val === 'string' && UUID_REGEX.test(val.trim())) {
    return val.trim().toLowerCase();
  }
  return undefined;
}

/**
 * Generates an immutable, server-controlled quarantine object key adhering strictly
 * to the canonical format: incoming/<app_id>/<upload_id> (ADR 0001, ADR 0008).
 *
 * User-supplied filenames are NEVER incorporated into storage keys.
 * Defends against path traversal (../, ..\), control characters, and cross-application namespace escape.
 */
export function generateQuarantineKey(applicationId: string, uploadId: string): string {
  const safeAppId = toSafeUuid(applicationId);
  if (!safeAppId) {
    throw new Error('Invalid applicationId for quarantine object key');
  }

  const safeUploadId = toSafeUuid(uploadId);
  if (!safeUploadId) {
    throw new Error('Invalid uploadId for quarantine object key');
  }

  return `incoming/${safeAppId}/${safeUploadId}`;
}

/**
 * Sanitizes an incoming original filename for storage as user metadata.
 * Strips directory separators, null bytes, control characters, and traversal patterns.
 */
export function sanitizeOriginalFilename(filename: string): string {
  if (!filename || typeof filename !== 'string') {
    throw new Error('Filename must be a non-empty string');
  }

  // Remove any null bytes or control characters
  let sanitized = filename.replace(/[\x00-\x1F\x7F]/g, '');

  // Strip Windows and POSIX directory separators to isolate base filename
  sanitized = sanitized.split(/[/\\]/).pop() ?? '';

  // Prevent path traversal remnants
  sanitized = sanitized.replace(/\.\.+/g, '.');

  sanitized = sanitized.trim();

  if (!sanitized || sanitized === '.' || sanitized === '..') {
    throw new Error('Filename is invalid or contains only forbidden characters');
  }

  // Enforce PostgreSQL schema length constraint (1..255)
  if (sanitized.length > 255) {
    const dotIndex = sanitized.lastIndexOf('.');
    if (dotIndex > 0 && sanitized.length - dotIndex <= 32) {
      const ext = sanitized.slice(dotIndex);
      const base = sanitized.slice(0, dotIndex);
      sanitized = base.slice(0, 255 - ext.length) + ext;
    } else {
      sanitized = sanitized.slice(0, 255);
    }
  }

  return sanitized;
}
