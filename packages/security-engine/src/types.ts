/**
 * @sug/security-engine
 * Core deterministic validation types, reason codes, and result interfaces.
 */

export type CanonicalFileType =
  | 'PDF'
  | 'JPEG'
  | 'PNG'
  | 'GIF'
  | 'WEBP'
  | 'TIFF'
  | 'DOCX'
  | 'XLSX'
  | 'PPTX'
  | 'ZIP'
  | 'TAR'
  | 'GZIP'
  | 'TEXT'
  | 'CSV'
  | 'JSON'
  | 'XML'
  | 'SVG'
  | 'EXECUTABLE'
  | 'OCTET_STREAM';

// ============================================================
// Filename Safety Types
// ============================================================

export type FilenameReasonCode =
  | 'VALID'
  | 'FILENAME_EMPTY'
  | 'PATH_TRAVERSAL_DETECTED'
  | 'PATH_SEPARATOR_FORBIDDEN'
  | 'ENCODED_TRAVERSAL_DETECTED'
  | 'NULL_BYTE_DETECTED'
  | 'CONTROL_CHARACTERS_DETECTED'
  | 'RTL_OVERRIDE_DETECTED'
  | 'RESERVED_DEVICE_NAME'
  | 'NAME_TOO_LONG';

export interface FilenameValidationResult {
  valid: boolean;
  reasonCode: FilenameReasonCode;
  sanitized: string;
  hasTraversalAttempt: boolean;
  hasDangerousCharacters: boolean;
  hasRtlOverride: boolean;
  hasReservedName: boolean;
  issues: string[];
  reason: string;
}

// ============================================================
// Extension Extraction & Validation Types
// ============================================================

export interface ExtensionExtractionResult {
  raw: string;
  extension: string; // Canonical primary extension, e.g. '.pdf', '.gz', or ''
  compoundExtension: string; // Compound if recognized (e.g. '.tar.gz'), otherwise same as extension
  hasExtension: boolean;
  isDotfile: boolean;
  allExtensions: string[]; // All dotted segments from basename, e.g. ['.pdf', '.exe']
}

export type ExtensionReasonCode =
  | 'EXTENSION_ALLOWED'
  | 'EXTENSION_BLOCKED'
  | 'EXTENSION_NOT_ALLOWED'
  | 'EXTENSION_MISSING'
  | 'EXTENSION_UNDETERMINED';

export interface ExtensionValidationResult {
  allowed: boolean;
  reasonCode: ExtensionReasonCode;
  extension: string;
  reason: string;
}

// ============================================================
// Double-Extension Protection Types
// ============================================================

export type DoubleExtensionReasonCode =
  | 'SINGLE_EXTENSION'
  | 'SAFE_COMPOUND_EXTENSION'
  | 'NO_EXTENSION'
  | 'DOUBLE_EXTENSION_DETECTED'
  | 'HIDDEN_EXECUTABLE_EXTENSION';

export interface DoubleExtensionValidationResult {
  valid: boolean;
  reasonCode: DoubleExtensionReasonCode;
  isDoubleExtension: boolean;
  isDangerous: boolean;
  detectedSuffix?: string | undefined;
  innerExtension?: string | undefined;
  reason: string;
}

// ============================================================
// Declared MIME Validation Types
// ============================================================

export type MimeReasonCode =
  'MIME_ALLOWED' | 'MIME_BLOCKED' | 'MIME_NOT_ALLOWED' | 'MIME_MALFORMED' | 'MIME_MISSING';

export interface MimeValidationResult {
  allowed: boolean;
  reasonCode: MimeReasonCode;
  normalizedMime: string;
  rawMime: string;
  parameters?: Record<string, string> | undefined;
  reason: string;
}

// ============================================================
// Magic-Byte & Signature Detection Types
// ============================================================

export interface MagicDetectionResult {
  detected: boolean;
  mime?: string | undefined;
  extension?: string | undefined;
  source: 'file-type' | 'custom-signature' | 'fallback';
  bytesExamined: number;
}

// ============================================================
// libmagic CLI Types
// ============================================================

export interface LibmagicResult {
  available: boolean;
  detectedMime?: string | undefined;
  rawOutput?: string | undefined;
  error?: string | undefined;
}

export interface LibmagicOptions {
  timeoutMs?: number | undefined;
  customRunner?:
    | ((
        command: string,
        args: string[],
      ) => Promise<{ stdout: string; stderr: string; exitCode: number }>)
    | undefined;
}

// ============================================================
// Detector Consistency Rule Types
// ============================================================

export type TypeConsistencyReasonCode =
  | 'CONSISTENT'
  | 'MAGIC_EXTENSION_MISMATCH'
  | 'MAGIC_MIME_MISMATCH'
  | 'MIME_EXTENSION_MISMATCH'
  | 'POLYGLOT_OR_CORRUPT'
  | 'UNDETERMINED';

export interface TypeConsistencyResult {
  consistent: boolean;
  reasonCode: TypeConsistencyReasonCode;
  canonicalType?: CanonicalFileType | undefined;
  extensionCanonicalType?: CanonicalFileType | undefined;
  mimeCanonicalType?: CanonicalFileType | undefined;
  magicCanonicalType?: CanonicalFileType | undefined;
  discrepancies: string[];
  reason: string;
}

// ============================================================
// Size Validation Rule Types
// ============================================================

export type SizeReasonCode =
  | 'SIZE_VALID'
  | 'INVALID_SIZE'
  | 'SIZE_EXCEEDS_POLICY'
  | 'SIZE_EXCEEDS_GLOBAL_LIMIT'
  | 'SIZE_MISMATCH';

export interface SizeValidationResult {
  valid: boolean;
  reasonCode: SizeReasonCode;
  actualSize: number;
  declaredSize?: number | undefined;
  maxAllowedSize: number;
  reason: string;
}
