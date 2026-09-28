import { type PolicyDocument, MAX_POLICY_FILE_SIZE_BYTES } from './schema.js';
import { normalizeFilename, type FilenameNormalizationResult } from './normalizer.js';

export type PrecheckErrorCode =
  | 'INVALID_SIZE'
  | 'SIZE_EXCEEDS_POLICY'
  | 'SIZE_EXCEEDS_GLOBAL_LIMIT'
  | 'MISSING_EXTENSION'
  | 'EXTENSION_BLOCKED'
  | 'EXTENSION_NOT_ALLOWED'
  | 'MIME_BLOCKED'
  | 'MIME_NOT_ALLOWED'
  | 'MIME_EXTENSION_MISMATCH'
  | 'SUSPICIOUS_FILENAME'
  | 'ARCHIVE_FORBIDDEN';

export interface PrecheckFileInput {
  filename: string;
  declaredSize: number;
  declaredMime: string;
  declaredSha256?: string | undefined;
}

export interface PrecheckResult {
  allowed: boolean;
  code?: PrecheckErrorCode;
  reason?: string;
  details?: {
    rawFilename: string;
    normalizedFilename: string;
    extension: string;
    declaredSize: number;
    declaredMime: string;
    maxAllowedSize: number;
    flags: {
      hasTraversalAttempt: boolean;
      hasDangerousCharacters: boolean;
      hasHiddenExtension: boolean;
      hasRtlOverride: boolean;
    };
  };
}

/**
 * Standard mapping between file extensions and expected canonical MIME types
 * for initial pre-upload sanity checks.
 */
const CANONICAL_MIME_MAP: Record<string, ReadonlySet<string>> = {
  '.jpg': new Set(['image/jpeg']),
  '.jpeg': new Set(['image/jpeg']),
  '.png': new Set(['image/png']),
  '.gif': new Set(['image/gif']),
  '.webp': new Set(['image/webp']),
  '.pdf': new Set(['application/pdf']),
  '.txt': new Set(['text/plain']),
  '.csv': new Set(['text/csv', 'text/plain', 'application/csv']),
  '.docx': new Set(['application/vnd.openxmlformats-officedocument.wordprocessingml.document']),
  '.xlsx': new Set(['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']),
  '.zip': new Set(['application/zip', 'application/x-zip-compressed']),
  '.tar': new Set(['application/x-tar']),
  '.gz': new Set(['application/gzip', 'application/x-gzip']),
};

const ARCHIVE_EXTENSIONS = new Set(['.zip', '.tar', '.gz', '.tgz', '.7z', '.rar']);

/**
 * Pure, deterministic precheck function for the Secure Upload Gateway policy engine.
 * Evaluates declared file metadata against the application's pinned security policy
 * prior to upload session creation and token issuance.
 */
export function precheck(policy: PolicyDocument, file: PrecheckFileInput): PrecheckResult {
  const norm: FilenameNormalizationResult = normalizeFilename(file.filename);
  const declaredSize = Number(file.declaredSize);
  const declaredMime = String(file.declaredMime || '')
    .trim()
    .toLowerCase();

  const details = {
    rawFilename: norm.raw,
    normalizedFilename: norm.normalized,
    extension: norm.extension,
    declaredSize,
    declaredMime,
    maxAllowedSize: policy.maxFileSize,
    flags: {
      hasTraversalAttempt: norm.hasTraversalAttempt,
      hasDangerousCharacters: norm.hasDangerousCharacters,
      hasHiddenExtension: norm.hasHiddenExtension,
      hasRtlOverride: norm.hasRtlOverride,
    },
  };

  // 1. Check for high-risk Unicode directional spoofing (e.g. U+202E)
  if (norm.hasRtlOverride) {
    return {
      allowed: false,
      code: 'SUSPICIOUS_FILENAME',
      reason: 'Filename contains dangerous Unicode directional override characters',
      details,
    };
  }

  // 2. Check for hidden or disguised executable extensions (e.g. invoice.exe.pdf)
  if (norm.hasHiddenExtension) {
    return {
      allowed: false,
      code: 'SUSPICIOUS_FILENAME',
      reason: 'Filename contains disguised executable extension',
      details,
    };
  }

  // 3. File size bounds validation
  if (!Number.isInteger(declaredSize) || declaredSize <= 0) {
    return {
      allowed: false,
      code: 'INVALID_SIZE',
      reason: 'Declared file size must be a positive integer greater than 0',
      details,
    };
  }

  if (declaredSize > MAX_POLICY_FILE_SIZE_BYTES) {
    return {
      allowed: false,
      code: 'SIZE_EXCEEDS_GLOBAL_LIMIT',
      reason: `Declared file size ${declaredSize} bytes exceeds gateway ceiling of ${MAX_POLICY_FILE_SIZE_BYTES} bytes (50 MB)`,
      details,
    };
  }

  if (declaredSize > policy.maxFileSize) {
    return {
      allowed: false,
      code: 'SIZE_EXCEEDS_POLICY',
      reason: `Declared file size ${declaredSize} bytes exceeds policy limit of ${policy.maxFileSize} bytes`,
      details,
    };
  }

  // 4. File extension validation
  if (!norm.extension) {
    return {
      allowed: false,
      code: 'MISSING_EXTENSION',
      reason: 'File extension is missing or unidentifiable',
      details,
    };
  }

  const blockedExts = new Set(policy.blockedExtensions.map((e) => e.toLowerCase()));
  if (blockedExts.has(norm.extension)) {
    return {
      allowed: false,
      code: 'EXTENSION_BLOCKED',
      reason: `Extension '${norm.extension}' is explicitly blocked by policy`,
      details,
    };
  }

  const allowedExts = new Set(policy.allowedExtensions.map((e) => e.toLowerCase()));
  if (!allowedExts.has(norm.extension)) {
    return {
      allowed: false,
      code: 'EXTENSION_NOT_ALLOWED',
      reason: `Extension '${norm.extension}' is not permitted by policy`,
      details,
    };
  }

  // 5. MIME type validation
  const blockedMimes = new Set(policy.blockedMimeTypes.map((m) => m.toLowerCase()));
  if (blockedMimes.has(declaredMime)) {
    return {
      allowed: false,
      code: 'MIME_BLOCKED',
      reason: `MIME type '${declaredMime}' is explicitly blocked by policy`,
      details,
    };
  }

  const allowedMimes = new Set(policy.allowedMimeTypes.map((m) => m.toLowerCase()));
  if (!allowedMimes.has(declaredMime)) {
    return {
      allowed: false,
      code: 'MIME_NOT_ALLOWED',
      reason: `MIME type '${declaredMime}' is not permitted by policy`,
      details,
    };
  }

  // 6. MIME and extension consistency check
  if (policy.requireMimeMatch) {
    const expectedMimes = CANONICAL_MIME_MAP[norm.extension];
    if (expectedMimes && !expectedMimes.has(declaredMime)) {
      return {
        allowed: false,
        code: 'MIME_EXTENSION_MISMATCH',
        reason: `Declared MIME type '${declaredMime}' does not match file extension '${norm.extension}'`,
        details,
      };
    }
  }

  // 7. Archive permission check
  if (!policy.allowArchives && ARCHIVE_EXTENSIONS.has(norm.extension)) {
    return {
      allowed: false,
      code: 'ARCHIVE_FORBIDDEN',
      reason: 'Archive files are prohibited by policy',
      details,
    };
  }

  return {
    allowed: true,
    details,
  };
}
