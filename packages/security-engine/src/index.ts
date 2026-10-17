/**
 * @sug/security-engine
 * Pure, deterministic file validation, type mapping, and signature inspection.
 */

export const Security_EnginePackageName = '@sug/security-engine' as const;

export interface Security_EngineInfo {
  name: typeof Security_EnginePackageName;
  version: string;
}

export const Security_EngineInfo: Security_EngineInfo = {
  name: Security_EnginePackageName,
  version: '0.1.0',
};

// Types & Reason Codes
export type {
  CanonicalFileType,
  FilenameReasonCode,
  FilenameValidationResult,
  ExtensionExtractionResult,
  ExtensionReasonCode,
  ExtensionValidationResult,
  DoubleExtensionReasonCode,
  DoubleExtensionValidationResult,
  MimeReasonCode,
  MimeValidationResult,
  MagicDetectionResult,
  LibmagicResult,
  LibmagicOptions,
  TypeConsistencyReasonCode,
  TypeConsistencyResult,
  SizeReasonCode,
  SizeValidationResult,
} from './types.js';

// Canonical Type Map
export {
  CANONICAL_TYPE_DEFINITIONS,
  type CanonicalTypeDefinition,
  getCanonicalTypeDefinition,
  getCanonicalTypeFromExtension,
  getCanonicalTypeFromMime,
  getCanonicalTypeFromMagic,
  isExtensionAllowedForCanonical,
  isMimeAllowedForCanonical,
  areTypesCompatible,
  getAllCanonicalTypes,
} from './type-map.js';

// Filename Safety Validator
export { validateFilename, sanitizeFilename } from './filename.js';

// Extension Extraction & Allowlist Validator
export { extractExtension, validateExtension } from './extension.js';

// Double-Extension Denylist Validator
export { validateDoubleExtension, DANGEROUS_EXECUTABLE_EXTENSIONS } from './double-extension.js';

// Declared MIME Validator & Parser
export { validateDeclaredMime, parseAndNormalizeMime, type ParsedMime } from './mime.js';

// Magic-Byte & Signature Detector (file-type v22 bounded to 4,100 bytes)
export { detectMagic, MAX_MAGIC_BUFFER_BYTES } from './magic.js';

// libmagic CLI Runner (file --mime-type -b)
export { detectMimeWithLibmagic, detectMimeFromBufferWithLibmagic } from './libmagic.js';

// Detector Consistency Validator
export { validateTypeConsistency, type TypeConsistencyInput } from './consistency.js';

// Size Validator
export {
  validateFileSize,
  type FileSizeValidationInput,
  GLOBAL_MAX_FILE_SIZE_BYTES,
} from './size.js';

// Archive Inspection Engine (P16 Two-Phase Safe ZIP / OOXML Inspection)
export * from './archive/index.js';

// Format Inspection Engines (P17 PDF, OOXML, Image, Embedded Signatures, Polyglots)
export * from './format/index.js';
