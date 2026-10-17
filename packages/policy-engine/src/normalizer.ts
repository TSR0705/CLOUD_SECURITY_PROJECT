/**
 * Unicode Directional and Control characters commonly abused for extension spoofing
 * and visual misdirection (e.g. U+202E Right-to-Left Override).
 */
const DIRECTIONAL_OVERRIDE_REGEX = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;

/**
 * Control characters including ASCII 0x00-0x1F and 0x7F-0x9F.
 */
const CONTROL_CHARACTERS_REGEX = /[\x00-\x1F\x7F-\x9F]/g;

/**
 * High-risk executable or script extensions commonly hidden via double-extension attacks.
 */
const DANGEROUS_EXTENSIONS: ReadonlySet<string> = new Set([
  '.exe',
  '.bat',
  '.cmd',
  '.sh',
  '.vbs',
  '.js',
  '.py',
  '.php',
  '.phtml',
  '.scr',
  '.pif',
  '.dll',
  '.com',
  '.ps1',
  '.msi',
  '.jar',
  '.app',
]);

const MAX_NORMALIZED_LENGTH = 255;

export interface FilenameNormalizationResult {
  raw: string;
  normalized: string;
  extension: string;
  hasDangerousCharacters: boolean;
  hasTraversalAttempt: boolean;
  hasHiddenExtension: boolean;
  hasRtlOverride: boolean;
}

/**
 * Pure, deterministic filename normalizer for the Secure Upload Gateway.
 *
 * Security Protections:
 * 1. Directory traversal elimination: strips path prefixes (/ and \), strips '..' sequences.
 * 2. Spoofing detection: flags and strips Unicode RTL/directional override characters (U+202E).
 * 3. Null-byte / control characters: flags and strips ASCII/Unicode control characters.
 * 4. Hidden extension detection: flags files containing executable extensions prior to the final extension.
 * 5. Length clamping: limits filename to 255 characters while preserving the final extension.
 */
export function normalizeFilename(rawFilename: string): FilenameNormalizationResult {
  const raw = String(rawFilename ?? '');

  let hasDangerousCharacters = false;
  let hasTraversalAttempt = false;
  let hasHiddenExtension = false;
  let hasRtlOverride = false;

  // 1. Detect directional override characters
  if (DIRECTIONAL_OVERRIDE_REGEX.test(raw)) {
    hasRtlOverride = true;
    hasDangerousCharacters = true;
  }

  // 2. Detect path traversal attempts
  if (raw.includes('..') || raw.includes('/') || raw.includes('\\')) {
    hasTraversalAttempt = true;
  }

  // 3. Detect control characters or null bytes
  if (CONTROL_CHARACTERS_REGEX.test(raw)) {
    hasDangerousCharacters = true;
  }

  // Strip directional overrides
  let cleaned = raw.replace(DIRECTIONAL_OVERRIDE_REGEX, '');

  // Strip control characters & null bytes
  cleaned = cleaned.replace(CONTROL_CHARACTERS_REGEX, '');

  // Extract basename by stripping Unix and Windows directory separators
  const lastSlash = Math.max(cleaned.lastIndexOf('/'), cleaned.lastIndexOf('\\'));
  if (lastSlash >= 0) {
    cleaned = cleaned.substring(lastSlash + 1);
  }

  // Trim whitespace
  cleaned = cleaned.trim();

  // Strip leading/trailing dots or spaces to eliminate traversal artifacts
  cleaned = cleaned.replace(/^\.+/, '').replace(/\.+$/, '');

  // Collapse multiple consecutive dots in the body
  cleaned = cleaned.replace(/\.{2,}/g, '.');

  // Handle empty or whitespace-only filename
  if (!cleaned) {
    cleaned = 'unnamed_file';
    hasDangerousCharacters = true;
  }

  // Extract extension(s)
  const lastDot = cleaned.lastIndexOf('.');
  let extension = '';
  let basename = cleaned;

  if (lastDot > 0 && lastDot < cleaned.length - 1) {
    extension = cleaned.substring(lastDot).toLowerCase();
    basename = cleaned.substring(0, lastDot);

    // Check for double extension / hidden executable extension
    // e.g., 'invoice.exe.pdf' or 'payload.php.png'
    const parts = basename.split('.');
    for (const part of parts) {
      if (part) {
        const subExt = `.${part.toLowerCase()}`;
        if (DANGEROUS_EXTENSIONS.has(subExt)) {
          hasHiddenExtension = true;
          break;
        }
      }
    }
  }

  // Clamp total length to 255 characters, preserving extension
  let normalized = cleaned;
  if (normalized.length > MAX_NORMALIZED_LENGTH) {
    if (extension) {
      const allowedBasenameLength = MAX_NORMALIZED_LENGTH - extension.length;
      normalized = `${basename.substring(0, allowedBasenameLength)}${extension}`;
    } else {
      normalized = normalized.substring(0, MAX_NORMALIZED_LENGTH);
    }
  }

  return {
    raw,
    normalized,
    extension,
    hasDangerousCharacters,
    hasTraversalAttempt,
    hasHiddenExtension,
    hasRtlOverride,
  };
}
