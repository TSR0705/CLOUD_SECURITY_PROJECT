import type { FilenameValidationResult } from './types.js';

const DIRECTIONAL_OVERRIDE_REGEX = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;
const CONTROL_CHARACTERS_REGEX = /[\x00-\x1F\x7F-\x9F]/g;
const URL_ENCODED_TRAVERSAL_REGEX = /%(?:2e|2f|5c|00)/i;
const DOUBLE_ENCODED_TRAVERSAL_REGEX = /%25(?:2e|2f|5c|00)/i;

const RESERVED_DEVICE_NAMES: ReadonlySet<string> = new Set([
  'con',
  'prn',
  'aux',
  'nul',
  'com1',
  'com2',
  'com3',
  'com4',
  'com5',
  'com6',
  'com7',
  'com8',
  'com9',
  'lpt1',
  'lpt2',
  'lpt3',
  'lpt4',
  'lpt5',
  'lpt6',
  'lpt7',
  'lpt8',
  'lpt9',
]);

const MAX_NORMALIZED_LENGTH = 255;
const MAX_RAW_LENGTH = 1024;

/**
 * Pure, deterministic filename safety validator.
 * Validates untrusted client-supplied filenames to ensure they cannot be used as storage/filesystem paths
 * or weaponized for directory traversal, spoofing, or control character injection.
 */
export function validateFilename(rawFilename?: string | null): FilenameValidationResult {
  const issues: string[] = [];
  let hasTraversalAttempt = false;
  let hasDangerousCharacters = false;
  let hasRtlOverride = false;
  let hasReservedName = false;

  // 1. Check for missing or empty filename
  if (rawFilename === undefined || rawFilename === null || rawFilename.trim() === '') {
    return {
      valid: false,
      reasonCode: 'FILENAME_EMPTY',
      sanitized: 'unnamed_file',
      hasTraversalAttempt: false,
      hasDangerousCharacters: true,
      hasRtlOverride: false,
      hasReservedName: false,
      issues: ['Filename is empty or contains only whitespace'],
      reason: 'Filename must not be empty or whitespace',
    };
  }

  const raw = String(rawFilename);

  // 2. Check maximum raw length
  if (raw.length > MAX_RAW_LENGTH) {
    issues.push(`Filename length (${raw.length}) exceeds maximum raw limit of ${MAX_RAW_LENGTH}`);
    return {
      valid: false,
      reasonCode: 'NAME_TOO_LONG',
      sanitized: raw.slice(0, MAX_NORMALIZED_LENGTH),
      hasTraversalAttempt: false,
      hasDangerousCharacters: true,
      hasRtlOverride: false,
      hasReservedName: false,
      issues,
      reason: `Filename exceeds maximum raw limit of ${MAX_RAW_LENGTH} characters`,
    };
  }

  // 3. Detect NUL bytes (raw or encoded)
  if (raw.includes('\0') || /%00/i.test(raw)) {
    hasDangerousCharacters = true;
    issues.push('Filename contains null byte (0x00 or %00)');
    return {
      valid: false,
      reasonCode: 'NULL_BYTE_DETECTED',
      sanitized: sanitizeFilename(raw),
      hasTraversalAttempt: false,
      hasDangerousCharacters: true,
      hasRtlOverride: false,
      hasReservedName: false,
      issues,
      reason: 'Null bytes are strictly forbidden in filenames',
    };
  }

  // 4. Detect Unicode directional override characters (U+202E RTL override)
  if (DIRECTIONAL_OVERRIDE_REGEX.test(raw)) {
    hasRtlOverride = true;
    hasDangerousCharacters = true;
    issues.push('Filename contains Unicode directional override characters');
    return {
      valid: false,
      reasonCode: 'RTL_OVERRIDE_DETECTED',
      sanitized: sanitizeFilename(raw),
      hasTraversalAttempt: false,
      hasDangerousCharacters: true,
      hasRtlOverride: true,
      hasReservedName: false,
      issues,
      reason: 'Unicode directional override characters (e.g. RTL) are forbidden',
    };
  }

  // 5. Detect URL-encoded or double-encoded path separators and traversals
  if (URL_ENCODED_TRAVERSAL_REGEX.test(raw) || DOUBLE_ENCODED_TRAVERSAL_REGEX.test(raw)) {
    hasTraversalAttempt = true;
    hasDangerousCharacters = true;
    issues.push('Filename contains URL-encoded path traversal or separator sequences');
    return {
      valid: false,
      reasonCode: 'ENCODED_TRAVERSAL_DETECTED',
      sanitized: sanitizeFilename(raw),
      hasTraversalAttempt: true,
      hasDangerousCharacters: true,
      hasRtlOverride: false,
      hasReservedName: false,
      issues,
      reason: 'URL-encoded path separators and traversals are forbidden',
    };
  }

  // 6. Detect directory traversal sequences
  if (
    raw.includes('..') ||
    raw.startsWith('../') ||
    raw.startsWith('..\\') ||
    /\/\.\.(?:\/|$)/.test(raw) ||
    /\\\.\.(?:\\|$)/.test(raw)
  ) {
    hasTraversalAttempt = true;
    issues.push('Filename contains directory traversal sequence (..)');
    return {
      valid: false,
      reasonCode: 'PATH_TRAVERSAL_DETECTED',
      sanitized: sanitizeFilename(raw),
      hasTraversalAttempt: true,
      hasDangerousCharacters: true,
      hasRtlOverride: false,
      hasReservedName: false,
      issues,
      reason: 'Directory traversal sequences are forbidden in filenames',
    };
  }

  // 7. Detect raw path separators (slashes / and \)
  if (raw.includes('/') || raw.includes('\\')) {
    hasTraversalAttempt = true;
    issues.push('Filename contains path separators (/ or \\)');
    return {
      valid: false,
      reasonCode: 'PATH_SEPARATOR_FORBIDDEN',
      sanitized: sanitizeFilename(raw),
      hasTraversalAttempt: true,
      hasDangerousCharacters: true,
      hasRtlOverride: false,
      hasReservedName: false,
      issues,
      reason: 'Path separators are forbidden in filenames',
    };
  }

  // 8. Detect ASCII and Unicode control characters
  if (CONTROL_CHARACTERS_REGEX.test(raw)) {
    hasDangerousCharacters = true;
    issues.push('Filename contains control characters');
    return {
      valid: false,
      reasonCode: 'CONTROL_CHARACTERS_DETECTED',
      sanitized: sanitizeFilename(raw),
      hasTraversalAttempt: false,
      hasDangerousCharacters: true,
      hasRtlOverride: false,
      hasReservedName: false,
      issues,
      reason: 'Control characters are forbidden in filenames',
    };
  }

  // 9. Detect Windows reserved device names
  const baseName = extractBaseName(raw).toLowerCase();
  if (RESERVED_DEVICE_NAMES.has(baseName)) {
    hasReservedName = true;
    issues.push(`Filename base matches reserved device name: ${baseName}`);
    return {
      valid: false,
      reasonCode: 'RESERVED_DEVICE_NAME',
      sanitized: sanitizeFilename(raw),
      hasTraversalAttempt: false,
      hasDangerousCharacters: true,
      hasRtlOverride: false,
      hasReservedName: true,
      issues,
      reason: `Filename matches reserved device name '${baseName}'`,
    };
  }

  const sanitized = sanitizeFilename(raw);

  return {
    valid: true,
    reasonCode: 'VALID',
    sanitized,
    hasTraversalAttempt,
    hasDangerousCharacters,
    hasRtlOverride,
    hasReservedName,
    issues,
    reason: 'Filename is safe and valid',
  };
}

/**
 * Deterministically sanitizes a raw filename to a safe display name:
 * 1. Decodes one level of URL-encoding if present.
 * 2. Strips directional override characters.
 * 3. Strips control characters.
 * 4. Extracts basename (strips / and \).
 * 5. Strips leading and trailing dots/spaces.
 * 6. Collapses consecutive dots.
 * 7. Clamps to 255 characters while preserving extension.
 */
export function sanitizeFilename(rawFilename: string): string {
  let cleaned = String(rawFilename ?? '');

  // Strip directional overrides
  cleaned = cleaned.replace(DIRECTIONAL_OVERRIDE_REGEX, '');

  // Strip control characters & null bytes
  cleaned = cleaned.replace(CONTROL_CHARACTERS_REGEX, '');

  // Extract basename by stripping directory separators
  const lastSlash = Math.max(cleaned.lastIndexOf('/'), cleaned.lastIndexOf('\\'));
  if (lastSlash >= 0) {
    cleaned = cleaned.substring(lastSlash + 1);
  }

  // Trim whitespace
  cleaned = cleaned.trim();

  // Strip leading and trailing dots
  cleaned = cleaned.replace(/^\.+/, '').replace(/\.+$/, '');

  // Collapse consecutive dots
  cleaned = cleaned.replace(/\.{2,}/g, '.');

  if (!cleaned) {
    return 'unnamed_file';
  }

  const lastDot = cleaned.lastIndexOf('.');
  let extension = '';
  let basename = cleaned;

  if (lastDot > 0 && lastDot < cleaned.length - 1) {
    extension = cleaned.substring(lastDot).toLowerCase();
    basename = cleaned.substring(0, lastDot);
  }

  // Check if sanitized basename is a reserved device name; if so prefix safe prefix
  if (RESERVED_DEVICE_NAMES.has(basename.toLowerCase())) {
    basename = `safe_${basename}`;
  }

  // Clamp total length to 255 characters
  if (cleaned.length > MAX_NORMALIZED_LENGTH) {
    if (extension) {
      const allowedBaseLen = MAX_NORMALIZED_LENGTH - extension.length;
      return `${basename.substring(0, allowedBaseLen)}${extension}`;
    }
    return cleaned.substring(0, MAX_NORMALIZED_LENGTH);
  }

  return `${basename}${extension}`;
}

function extractBaseName(filename: string): string {
  const lastSlash = Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\'));
  const name = lastSlash >= 0 ? filename.substring(lastSlash + 1) : filename;
  const dotIndex = name.indexOf('.');
  return dotIndex > 0 ? name.substring(0, dotIndex) : name;
}
