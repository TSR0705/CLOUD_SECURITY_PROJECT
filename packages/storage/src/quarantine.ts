/**
 * Server-controlled Quarantine Key Scheme
 * Enforces strict pattern: incoming/<applicationId>/<uploadId>
 * Rejects path traversals, special characters, client-controlled filenames or extensions
 */

import { InvalidRequest } from './errors.js';

// Safe alphanumeric identifier: letters, digits, hyphens, underscores (1 to 128 characters)
const SAFE_ID_REGEX = /^[a-zA-Z0-9_-]{1,128}$/;

/**
 * Validates whether an identifier is safe for use in quarantine object keys.
 * Rejects directory traversal (..), path separators (/ or \), whitespace, null bytes,
 * URL-encoded characters, or any character outside [a-zA-Z0-9_-].
 */
export function isValidQuarantineIdentifier(id: unknown): id is string {
  if (typeof id !== 'string') {
    return false;
  }
  if (!SAFE_ID_REGEX.test(id)) {
    return false;
  }
  // Extra safety checks
  if (id.includes('..') || id.includes('/') || id.includes('\\') || id.includes('\0')) {
    return false;
  }
  return true;
}

/**
 * Constructs a canonical, server-controlled quarantine object key.
 *
 * @param applicationId Safe application identifier (e.g. UUID or alphanumeric tag)
 * @param uploadId Safe upload session identifier (e.g. UUID)
 * @returns Key formatted as `incoming/${applicationId}/${uploadId}`
 * @throws InvalidRequest if either identifier fails strict validation
 */
export function buildQuarantineKey(applicationId: string, uploadId: string): string {
  if (!isValidQuarantineIdentifier(applicationId)) {
    throw new InvalidRequest(
      `Invalid applicationId for quarantine key: must be 1-128 alphanumeric, hyphen, or underscore characters`,
    );
  }

  if (!isValidQuarantineIdentifier(uploadId)) {
    throw new InvalidRequest(
      `Invalid uploadId for quarantine key: must be 1-128 alphanumeric, hyphen, or underscore characters`,
    );
  }

  return `incoming/${applicationId}/${uploadId}`;
}

/**
 * Parses and validates an existing quarantine key into its components.
 * Returns null if the key does not match `incoming/<applicationId>/<uploadId>`.
 */
export function parseQuarantineKey(
  key: string,
): { applicationId: string; uploadId: string } | null {
  if (typeof key !== 'string') {
    return null;
  }

  const parts = key.split('/');
  if (parts.length !== 3) {
    return null;
  }

  const [prefix, applicationId, uploadId] = parts;
  if (prefix !== 'incoming') {
    return null;
  }

  if (!isValidQuarantineIdentifier(applicationId) || !isValidQuarantineIdentifier(uploadId)) {
    return null;
  }

  return { applicationId, uploadId };
}
