import type { ExtensionExtractionResult, ExtensionValidationResult } from './types.js';

const RECOGNIZED_COMPOUND_EXTENSIONS: ReadonlySet<string> = new Set([
  '.tar.gz',
  '.tar.bz2',
  '.tar.xz',
  '.tar.zst',
]);

/**
 * Deterministically extracts extension metadata from a filename.
 *
 * Rules:
 * - 'report.pdf' -> primary: '.pdf', compound: '.pdf'
 * - 'report.tar.gz' -> primary: '.gz', compound: '.tar.gz'
 * - 'report.exe' -> primary: '.exe', compound: '.exe'
 * - 'report' -> hasExtension: false, extension: ''
 * - '.hidden' / '.gitignore' -> isDotfile: true, hasExtension: false, extension: ''
 * - 'foo.' -> trailing dot stripped -> hasExtension: false, extension: ''
 * - 'foo..pdf' -> consecutive dots collapsed -> primary: '.pdf'
 * - 'archive.TAR.GZ' -> case-insensitive lowercased: '.tar.gz' / '.gz'
 */
export function extractExtension(rawFilename?: string | null): ExtensionExtractionResult {
  const raw = String(rawFilename ?? '').trim();
  if (!raw) {
    return {
      raw,
      extension: '',
      compoundExtension: '',
      hasExtension: false,
      isDotfile: false,
      allExtensions: [],
    };
  }

  // Strip path directory prefixes if any
  const lastSlash = Math.max(raw.lastIndexOf('/'), raw.lastIndexOf('\\'));
  const basename = lastSlash >= 0 ? raw.substring(lastSlash + 1) : raw;

  // Check for hidden dotfiles (e.g. '.gitignore', '.hidden', '.env')
  if (basename.startsWith('.') && !basename.slice(1).includes('.')) {
    return {
      raw,
      extension: '',
      compoundExtension: '',
      hasExtension: false,
      isDotfile: true,
      allExtensions: [],
    };
  }

  // Remove trailing dots (e.g. 'foo.')
  const strippedTrailingDots = basename.replace(/\.+$/, '');
  if (!strippedTrailingDots.includes('.')) {
    return {
      raw,
      extension: '',
      compoundExtension: '',
      hasExtension: false,
      isDotfile: basename.startsWith('.'),
      allExtensions: [],
    };
  }

  // Normalize consecutive dots in filename
  const collapsed = strippedTrailingDots.replace(/\.{2,}/g, '.');

  // Split into components by '.'
  const parts = collapsed.split('.');
  // The first part is the root name, subsequent parts are extension parts
  const extParts = parts.slice(1);
  const allExtensions = extParts.map((p) => `.${p.toLowerCase()}`);

  const primaryExtension = allExtensions[allExtensions.length - 1] ?? '';

  // Check for recognized compound extensions (e.g. '.tar.gz')
  let compoundExtension = primaryExtension;
  if (allExtensions.length >= 2) {
    const candidateCompound = `${allExtensions[allExtensions.length - 2]}${primaryExtension}`;
    if (RECOGNIZED_COMPOUND_EXTENSIONS.has(candidateCompound)) {
      compoundExtension = candidateCompound;
    }
  }

  return {
    raw,
    extension: primaryExtension,
    compoundExtension,
    hasExtension: primaryExtension.length > 0,
    isDotfile: basename.startsWith('.'),
    allExtensions,
  };
}

/**
 * Validates a file extension against policy allowlist and blocklist.
 *
 * Evaluation Order:
 * 1. Missing extension check -> EXTENSION_MISSING
 * 2. Explicit policy blockedExtensions check -> EXTENSION_BLOCKED
 * 3. Policy allowedExtensions check -> EXTENSION_ALLOWED / EXTENSION_NOT_ALLOWED
 */
export function validateExtension(
  extensionInput: string | ExtensionExtractionResult,
  allowedExtensions: readonly string[],
  blockedExtensions: readonly string[] = [],
): ExtensionValidationResult {
  const extraction =
    typeof extensionInput === 'string' ? extractExtension(extensionInput) : extensionInput;

  if (!extraction.hasExtension || !extraction.extension) {
    return {
      allowed: false,
      reasonCode: 'EXTENSION_MISSING',
      extension: '',
      reason: 'File extension is missing or unidentifiable',
    };
  }

  const primary = extraction.extension.toLowerCase();
  const compound = extraction.compoundExtension.toLowerCase();

  const normalizedBlocked = new Set(
    blockedExtensions.map((e) => (e.startsWith('.') ? e.toLowerCase() : `.${e.toLowerCase()}`)),
  );

  // Check blocklist against primary and compound extension
  if (normalizedBlocked.has(primary) || (compound !== primary && normalizedBlocked.has(compound))) {
    const blockedMatched = normalizedBlocked.has(compound) ? compound : primary;
    return {
      allowed: false,
      reasonCode: 'EXTENSION_BLOCKED',
      extension: primary,
      reason: `Extension '${blockedMatched}' is explicitly blocked by policy`,
    };
  }

  const normalizedAllowed = new Set(
    allowedExtensions.map((e) => (e.startsWith('.') ? e.toLowerCase() : `.${e.toLowerCase()}`)),
  );

  if (normalizedAllowed.size === 0) {
    return {
      allowed: false,
      reasonCode: 'EXTENSION_UNDETERMINED',
      extension: primary,
      reason: 'No allowed extensions defined in policy',
    };
  }

  // Check allowlist against compound first, then primary
  if (normalizedAllowed.has(compound) || normalizedAllowed.has(primary)) {
    return {
      allowed: true,
      reasonCode: 'EXTENSION_ALLOWED',
      extension: primary,
      reason: `Extension '${primary}' is permitted by policy`,
    };
  }

  return {
    allowed: false,
    reasonCode: 'EXTENSION_NOT_ALLOWED',
    extension: primary,
    reason: `Extension '${primary}' is not permitted by policy`,
  };
}
