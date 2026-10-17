import type { SizeValidationResult } from './types.js';

export const GLOBAL_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB

export interface FileSizeValidationInput {
  actualSizeBytes: number;
  declaredSizeBytes?: number | null | undefined;
  policyMaxBytes: number;
  globalCeilingBytes?: number | undefined;
}

/**
 * Deterministically validates file size against policy limits, declared size, and global ceiling.
 *
 * Rules:
 * 1. Checks actualSizeBytes > 0 and integer -> INVALID_SIZE
 * 2. Checks actualSizeBytes <= globalCeilingBytes (50 MB) -> SIZE_EXCEEDS_GLOBAL_LIMIT
 * 3. Checks actualSizeBytes <= policyMaxBytes -> SIZE_EXCEEDS_POLICY
 * 4. Checks actualSizeBytes === declaredSizeBytes (if declared) -> SIZE_MISMATCH
 */
export function validateFileSize(input: FileSizeValidationInput): SizeValidationResult {
  const { actualSizeBytes, declaredSizeBytes, policyMaxBytes } = input;
  const globalCeiling = input.globalCeilingBytes ?? GLOBAL_MAX_FILE_SIZE_BYTES;

  // 1. Validate actual size is positive integer
  if (
    typeof actualSizeBytes !== 'number' ||
    !Number.isInteger(actualSizeBytes) ||
    actualSizeBytes <= 0
  ) {
    return {
      valid: false,
      reasonCode: 'INVALID_SIZE',
      actualSize: actualSizeBytes,
      declaredSize: declaredSizeBytes ?? undefined,
      maxAllowedSize: policyMaxBytes,
      reason: `Actual file size (${actualSizeBytes}) must be a positive integer greater than 0`,
    };
  }

  // 2. Validate declared size if present
  if (declaredSizeBytes !== undefined && declaredSizeBytes !== null) {
    if (
      typeof declaredSizeBytes !== 'number' ||
      !Number.isInteger(declaredSizeBytes) ||
      declaredSizeBytes <= 0
    ) {
      return {
        valid: false,
        reasonCode: 'INVALID_SIZE',
        actualSize: actualSizeBytes,
        declaredSize: declaredSizeBytes,
        maxAllowedSize: policyMaxBytes,
        reason: `Declared file size (${declaredSizeBytes}) must be a positive integer greater than 0`,
      };
    }

    if (actualSizeBytes !== declaredSizeBytes) {
      return {
        valid: false,
        reasonCode: 'SIZE_MISMATCH',
        actualSize: actualSizeBytes,
        declaredSize: declaredSizeBytes,
        maxAllowedSize: policyMaxBytes,
        reason: `Actual size (${actualSizeBytes} bytes) does not match declared size (${declaredSizeBytes} bytes)`,
      };
    }
  }

  // 3. Check against gateway global ceiling (50 MB)
  if (actualSizeBytes > globalCeiling) {
    return {
      valid: false,
      reasonCode: 'SIZE_EXCEEDS_GLOBAL_LIMIT',
      actualSize: actualSizeBytes,
      declaredSize: declaredSizeBytes ?? undefined,
      maxAllowedSize: globalCeiling,
      reason: `File size (${actualSizeBytes} bytes) exceeds gateway maximum ceiling of ${globalCeiling} bytes (50 MB)`,
    };
  }

  // 4. Check against application policy maxFileSize
  if (actualSizeBytes > policyMaxBytes) {
    return {
      valid: false,
      reasonCode: 'SIZE_EXCEEDS_POLICY',
      actualSize: actualSizeBytes,
      declaredSize: declaredSizeBytes ?? undefined,
      maxAllowedSize: policyMaxBytes,
      reason: `File size (${actualSizeBytes} bytes) exceeds policy maximum limit of ${policyMaxBytes} bytes`,
    };
  }

  return {
    valid: true,
    reasonCode: 'SIZE_VALID',
    actualSize: actualSizeBytes,
    declaredSize: declaredSizeBytes ?? undefined,
    maxAllowedSize: policyMaxBytes,
    reason: 'File size is valid and within all permitted thresholds',
  };
}
