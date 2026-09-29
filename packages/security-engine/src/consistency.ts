import type { CanonicalFileType, TypeConsistencyResult } from './types.js';
import {
  areTypesCompatible,
  getCanonicalTypeFromExtension,
  getCanonicalTypeFromMagic,
  getCanonicalTypeFromMime,
} from './type-map.js';

export interface TypeConsistencyInput {
  extension?: string | null | undefined;
  declaredMime?: string | null | undefined;
  magicMime?: string | null | undefined;
  magicExt?: string | null | undefined;
}

/**
 * Deterministically compares three independent file-type detectors:
 * 1. Filename Extension
 * 2. Client-Declared MIME Type
 * 3. Detected Magic-Bytes / File Signature
 *
 * Rules:
 * - If magic bytes are detected and conflict with extension -> MAGIC_EXTENSION_MISMATCH
 * - If magic bytes are detected and conflict with declared MIME -> MAGIC_MIME_MISMATCH
 * - If declared MIME conflicts with extension -> MIME_EXTENSION_MISMATCH
 * - If all available detectors agree -> CONSISTENT
 * - If no detectors can determine the file type -> UNDETERMINED
 */
export function validateTypeConsistency(input: TypeConsistencyInput): TypeConsistencyResult {
  const { extension, declaredMime, magicMime, magicExt } = input;
  const discrepancies: string[] = [];

  const extType = getCanonicalTypeFromExtension(extension ?? undefined);
  const mimeType = getCanonicalTypeFromMime(declaredMime ?? undefined);
  const magicType = getCanonicalTypeFromMagic(magicExt ?? undefined, magicMime ?? undefined);

  // Case 1: Magic bytes detection vs Extension
  if (magicType && extType && !areTypesCompatible(magicType, extType)) {
    discrepancies.push(
      `Magic bytes identify '${magicType}', but filename extension claims '${extension}' (${extType})`,
    );
    return {
      consistent: false,
      reasonCode: 'MAGIC_EXTENSION_MISMATCH',
      canonicalType: undefined,
      extensionCanonicalType: extType,
      mimeCanonicalType: mimeType,
      magicCanonicalType: magicType,
      discrepancies,
      reason: `File extension '${extension}' does not match detected file signature '${magicType}'`,
    };
  }

  // Case 2: Magic bytes detection vs Declared MIME
  if (magicType && mimeType && !areTypesCompatible(magicType, mimeType)) {
    discrepancies.push(
      `Magic bytes identify '${magicType}', but declared MIME claims '${declaredMime}' (${mimeType})`,
    );
    return {
      consistent: false,
      reasonCode: 'MAGIC_MIME_MISMATCH',
      canonicalType: undefined,
      extensionCanonicalType: extType,
      mimeCanonicalType: mimeType,
      magicCanonicalType: magicType,
      discrepancies,
      reason: `Declared MIME '${declaredMime}' does not match detected file signature '${magicType}'`,
    };
  }

  // Case 3: Declared MIME vs Extension
  if (mimeType && extType && !areTypesCompatible(mimeType, extType)) {
    discrepancies.push(
      `Declared MIME '${declaredMime}' (${mimeType}) does not match filename extension '${extension}' (${extType})`,
    );
    return {
      consistent: false,
      reasonCode: 'MIME_EXTENSION_MISMATCH',
      canonicalType: undefined,
      extensionCanonicalType: extType,
      mimeCanonicalType: mimeType,
      magicCanonicalType: magicType,
      discrepancies,
      reason: `Declared MIME '${declaredMime}' does not match file extension '${extension}'`,
    };
  }

  // Case 4: Detectors are compatible or consistent
  const canonicalType: CanonicalFileType | undefined = magicType ?? mimeType ?? extType;

  if (!canonicalType) {
    return {
      consistent: false,
      reasonCode: 'UNDETERMINED',
      canonicalType: undefined,
      extensionCanonicalType: undefined,
      mimeCanonicalType: undefined,
      magicCanonicalType: undefined,
      discrepancies: ['No file type could be identified from any detector'],
      reason: 'File type could not be determined from extension, MIME, or magic bytes',
    };
  }

  return {
    consistent: true,
    reasonCode: 'CONSISTENT',
    canonicalType,
    extensionCanonicalType: extType,
    mimeCanonicalType: mimeType,
    magicCanonicalType: magicType,
    discrepancies,
    reason: `All available detectors agree on canonical type '${canonicalType}'`,
  };
}
