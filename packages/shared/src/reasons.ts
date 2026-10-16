/**
 * @sug/shared/reasons
 * Canonical Reason-Code Registry and Findings Model Definitions for P17.
 *
 * Provides deterministic, stable machine identifiers for all scanner detectors.
 * STRICT NON-GOAL: Reason codes represent raw security findings and detection evidence.
 * They MUST NOT be confused with or converted into P18 terminal decisions (ALLOW/BLOCK/QUARANTINE).
 */

import type { FindingOutcome, SeverityLevel, ConfidenceLevel } from './db.js';

export type CheckId =
  | 'scanner.clamav'
  | 'scanner.yara'
  | 'scanner.archive'
  | 'scanner.pdf'
  | 'scanner.ooxml.macro'
  | 'scanner.ooxml.relationship'
  | 'scanner.image.trailing'
  | 'scanner.signature.embedded'
  | 'scanner.polyglot';

export type CanonicalReasonCode =
  // Universal
  | 'CLEAN'
  | 'SCANNER_ERROR'
  | 'NOT_APPLICABLE'
  | 'REQUIRED_CHECK_MISSING'
  | 'SCANNER_UNAVAILABLE'
  | 'SCAN_TIMEOUT'
  | 'RESULT_IDENTITY_MISMATCH'
  | 'CDR_REQUIRED'
  | 'CDR_REQUIRED_NOT_DONE'
  | 'RISK_THRESHOLD'
  | 'ALL_CHECKS_PASSED'
  | 'DETECTOR_DISAGREEMENT'
  | 'TYPE_UNDETERMINED'
  | 'SCANNER_LIMIT_EXCEEDED'
  | 'MAGIC_EXTENSION_MISMATCH'
  | 'MAGIC_MIME_MISMATCH'
  | 'MIME_EXTENSION_MISMATCH'
  // Malware / Pattern
  | 'MALWARE_DETECTED'
  // Archive (P16)
  | 'ARCHIVE_BOMB_DETECTED'
  | 'COMPRESSION_RATIO_EXCEEDED'
  | 'UNCOMPRESSED_SIZE_EXCEEDED'
  | 'ENTRY_COUNT_EXCEEDED'
  | 'OVERLAPPING_ENTRIES'
  | 'DUPLICATE_ENTRY_NAMES'
  | 'UNSAFE_PATH'
  | 'ZIP_SLIP_DETECTED'
  | 'ENCRYPTED_ARCHIVE_FORBIDDEN'
  | 'UNSUPPORTED_COMPRESSION_METHOD'
  | 'SYMLINK_FORBIDDEN'
  | 'NESTED_ARCHIVE_DEPTH_EXCEEDED'
  | 'CORRUPT_ARCHIVE'
  | 'SIZE_MISMATCH'
  | 'CRC_MISMATCH'
  | 'TIMEOUT_EXCEEDED'
  | 'MEMORY_BUDGET_EXCEEDED'
  | 'ARCHIVE_FORBIDDEN'
  // PDF Active Content (P17)
  | 'ACTIVE_CONTENT_DETECTED'
  | 'PDF_MALFORMED'
  | 'PDF_NORMALIZATION_FAILED'
  // OOXML (P17)
  | 'OOXML_MACRO_DETECTED'
  | 'OOXML_EXTERNAL_RELATIONSHIP'
  // Image (P17)
  | 'IMAGE_TRAILING_DATA_DETECTED'
  // Embedded Signature (P17)
  | 'EMBEDDED_EXECUTABLE_DETECTED'
  // Polyglot (P17)
  | 'POLYGLOT_DETECTED';

export interface ReasonCodeDescriptor {
  readonly reasonCode: CanonicalReasonCode;
  readonly checkId: CheckId | 'universal';
  readonly defaultOutcome: FindingOutcome;
  readonly defaultSeverity: SeverityLevel;
  readonly defaultConfidence: ConfidenceLevel;
  readonly description: string;
}

export const REASON_CODE_REGISTRY: Readonly<Record<CanonicalReasonCode, ReasonCodeDescriptor>> = {
  CLEAN: {
    reasonCode: 'CLEAN',
    checkId: 'universal',
    defaultOutcome: 'PASS',
    defaultSeverity: 'INFO',
    defaultConfidence: 'CONFIRMED',
    description: 'No malicious payload, active content, or structural violation detected.',
  },
  SCANNER_ERROR: {
    reasonCode: 'SCANNER_ERROR',
    checkId: 'universal',
    defaultOutcome: 'ERROR',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Underlying engine, parser, or subprocess encountered an unrecoverable error.',
  },
  NOT_APPLICABLE: {
    reasonCode: 'NOT_APPLICABLE',
    checkId: 'universal',
    defaultOutcome: 'SKIPPED',
    defaultSeverity: 'INFO',
    defaultConfidence: 'CONFIRMED',
    description: 'Detector not applicable to the artifact format or MIME type.',
  },
  REQUIRED_CHECK_MISSING: {
    reasonCode: 'REQUIRED_CHECK_MISSING',
    checkId: 'universal',
    defaultOutcome: 'ERROR',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'A required inspection check mandated by policy was omitted or not performed.',
  },
  SCANNER_UNAVAILABLE: {
    reasonCode: 'SCANNER_UNAVAILABLE',
    checkId: 'universal',
    defaultOutcome: 'ERROR',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description:
      'Underlying scanner daemon or service is offline, unreachable, or signature database is stale.',
  },
  SCAN_TIMEOUT: {
    reasonCode: 'SCAN_TIMEOUT',
    checkId: 'universal',
    defaultOutcome: 'ERROR',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Scanner inspection exceeded execution time ceiling.',
  },
  RESULT_IDENTITY_MISMATCH: {
    reasonCode: 'RESULT_IDENTITY_MISMATCH',
    checkId: 'universal',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description:
      'Scanned artifact identity (hash, version, size) does not match immutable file version identity.',
  },
  CDR_REQUIRED: {
    reasonCode: 'CDR_REQUIRED',
    checkId: 'universal',
    defaultOutcome: 'SUSPICIOUS',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'CONFIRMED',
    description:
      'Policy mandates Content Disarm and Reconstruction (CDR), but no sanitized artifact is available.',
  },
  CDR_REQUIRED_NOT_DONE: {
    reasonCode: 'CDR_REQUIRED_NOT_DONE',
    checkId: 'universal',
    defaultOutcome: 'SUSPICIOUS',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'CONFIRMED',
    description:
      'Policy mandates Content Disarm and Reconstruction (CDR), but no sanitized artifact is available.',
  },
  RISK_THRESHOLD: {
    reasonCode: 'RISK_THRESHOLD',
    checkId: 'universal',
    defaultOutcome: 'SUSPICIOUS',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'HIGH',
    description:
      'Cumulative risk score of findings reaches or exceeds the policy manual review threshold.',
  },
  ALL_CHECKS_PASSED: {
    reasonCode: 'ALL_CHECKS_PASSED',
    checkId: 'universal',
    defaultOutcome: 'PASS',
    defaultSeverity: 'INFO',
    defaultConfidence: 'CONFIRMED',
    description:
      'All policy-mandated security inspection checks passed cleanly without error or threat.',
  },
  DETECTOR_DISAGREEMENT: {
    reasonCode: 'DETECTOR_DISAGREEMENT',
    checkId: 'universal',
    defaultOutcome: 'SUSPICIOUS',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'HIGH',
    description:
      'Contradictory file types identified across magic bytes, extension, or MIME header.',
  },
  TYPE_UNDETERMINED: {
    reasonCode: 'TYPE_UNDETERMINED',
    checkId: 'universal',
    defaultOutcome: 'SUSPICIOUS',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'HIGH',
    description:
      'Artifact file type could not be definitively determined from header or structure.',
  },
  SCANNER_LIMIT_EXCEEDED: {
    reasonCode: 'SCANNER_LIMIT_EXCEEDED',
    checkId: 'universal',
    defaultOutcome: 'SUSPICIOUS',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'HIGH',
    description: 'Scanner resource limit exceeded (size, stream length, or recursion depth).',
  },
  MAGIC_EXTENSION_MISMATCH: {
    reasonCode: 'MAGIC_EXTENSION_MISMATCH',
    checkId: 'universal',
    defaultOutcome: 'SUSPICIOUS',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'HIGH',
    description: 'Detected file signature conflicts with filename extension.',
  },
  MAGIC_MIME_MISMATCH: {
    reasonCode: 'MAGIC_MIME_MISMATCH',
    checkId: 'universal',
    defaultOutcome: 'SUSPICIOUS',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'HIGH',
    description: 'Detected file signature conflicts with client-declared MIME type.',
  },
  MIME_EXTENSION_MISMATCH: {
    reasonCode: 'MIME_EXTENSION_MISMATCH',
    checkId: 'universal',
    defaultOutcome: 'SUSPICIOUS',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'HIGH',
    description: 'Client-declared MIME type conflicts with filename extension.',
  },
  MALWARE_DETECTED: {
    reasonCode: 'MALWARE_DETECTED',
    checkId: 'universal',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 'CONFIRMED',
    description: 'Known malware signature or heuristic threat pattern matched.',
  },
  ARCHIVE_BOMB_DETECTED: {
    reasonCode: 'ARCHIVE_BOMB_DETECTED',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 'CONFIRMED',
    description: 'Archive declared expansion ratio or bomb structure exceeded safety thresholds.',
  },
  COMPRESSION_RATIO_EXCEEDED: {
    reasonCode: 'COMPRESSION_RATIO_EXCEEDED',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description:
      'Decompression ratio exceeded maximum safety limit during streaming decompression.',
  },
  UNCOMPRESSED_SIZE_EXCEEDED: {
    reasonCode: 'UNCOMPRESSED_SIZE_EXCEEDED',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Cumulative uncompressed bytes exceeded safety budget.',
  },
  ENTRY_COUNT_EXCEEDED: {
    reasonCode: 'ENTRY_COUNT_EXCEEDED',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Total archive entries in Central Directory exceeded safety budget.',
  },
  OVERLAPPING_ENTRIES: {
    reasonCode: 'OVERLAPPING_ENTRIES',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 'CONFIRMED',
    description: 'Overlapping physical byte ranges detected (Fifield non-recursive zip bomb).',
  },
  DUPLICATE_ENTRY_NAMES: {
    reasonCode: 'DUPLICATE_ENTRY_NAMES',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'CONFIRMED',
    description: 'Duplicate archive entry names detected in Central Directory.',
  },
  UNSAFE_PATH: {
    reasonCode: 'UNSAFE_PATH',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 'CONFIRMED',
    description:
      'Unsafe path detected in archive entry (absolute path, UNC, or reserved device name).',
  },
  ZIP_SLIP_DETECTED: {
    reasonCode: 'ZIP_SLIP_DETECTED',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 'CONFIRMED',
    description: 'Directory traversal sequence (../) detected in archive entry name.',
  },
  ENCRYPTED_ARCHIVE_FORBIDDEN: {
    reasonCode: 'ENCRYPTED_ARCHIVE_FORBIDDEN',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Encrypted or password-protected archive entry detected.',
  },
  UNSUPPORTED_COMPRESSION_METHOD: {
    reasonCode: 'UNSUPPORTED_COMPRESSION_METHOD',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'CONFIRMED',
    description: 'Compression method other than 0 (Stored) or 8 (Deflate) detected.',
  },
  SYMLINK_FORBIDDEN: {
    reasonCode: 'SYMLINK_FORBIDDEN',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Symbolic link entry detected in archive.',
  },
  NESTED_ARCHIVE_DEPTH_EXCEEDED: {
    reasonCode: 'NESTED_ARCHIVE_DEPTH_EXCEEDED',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Recursive nested archive recursion depth exceeded safety budget.',
  },
  CORRUPT_ARCHIVE: {
    reasonCode: 'CORRUPT_ARCHIVE',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Structural corruption or multiple contradictory EOCD records detected.',
  },
  SIZE_MISMATCH: {
    reasonCode: 'SIZE_MISMATCH',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Actual decompressed byte count does not match declared uncompressed size.',
  },
  CRC_MISMATCH: {
    reasonCode: 'CRC_MISMATCH',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'CRC-32 checksum mismatch in compressed stream.',
  },
  TIMEOUT_EXCEEDED: {
    reasonCode: 'TIMEOUT_EXCEEDED',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Inspection wall-clock duration exceeded timeout budget.',
  },
  MEMORY_BUDGET_EXCEEDED: {
    reasonCode: 'MEMORY_BUDGET_EXCEEDED',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Inspection memory consumption exceeded memory budget.',
  },
  ARCHIVE_FORBIDDEN: {
    reasonCode: 'ARCHIVE_FORBIDDEN',
    checkId: 'scanner.archive',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'Archive processing is forbidden by policy.',
  },
  ACTIVE_CONTENT_DETECTED: {
    reasonCode: 'ACTIVE_CONTENT_DETECTED',
    checkId: 'scanner.pdf',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description:
      'Active executable content indicators detected in PDF (/JavaScript, /Launch, /EmbeddedFiles, /SubmitForm, /XFA).',
  },
  PDF_MALFORMED: {
    reasonCode: 'PDF_MALFORMED',
    checkId: 'scanner.pdf',
    defaultOutcome: 'ERROR',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'PDF structure is corrupted or failed syntactic validation.',
  },
  PDF_NORMALIZATION_FAILED: {
    reasonCode: 'PDF_NORMALIZATION_FAILED',
    checkId: 'scanner.pdf',
    defaultOutcome: 'ERROR',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description: 'PDF normalization tool (qpdf / internal decompressor) failed.',
  },
  OOXML_MACRO_DETECTED: {
    reasonCode: 'OOXML_MACRO_DETECTED',
    checkId: 'scanner.ooxml.macro',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description:
      'Macro-enabled OOXML container, embedded VBA project (vbaProject.bin), or macro ContentType detected.',
  },
  OOXML_EXTERNAL_RELATIONSHIP: {
    reasonCode: 'OOXML_EXTERNAL_RELATIONSHIP',
    checkId: 'scanner.ooxml.relationship',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'MEDIUM',
    defaultConfidence: 'CONFIRMED',
    description:
      'OOXML container contains relationship(s) targeting external resources (TargetMode="External").',
  },
  IMAGE_TRAILING_DATA_DETECTED: {
    reasonCode: 'IMAGE_TRAILING_DATA_DETECTED',
    checkId: 'scanner.image.trailing',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'HIGH',
    defaultConfidence: 'CONFIRMED',
    description:
      'Suspicious payload or trailing bytes detected appended after legitimate image EOF (IEND/EOI/0x3B).',
  },
  EMBEDDED_EXECUTABLE_DETECTED: {
    reasonCode: 'EMBEDDED_EXECUTABLE_DETECTED',
    checkId: 'scanner.signature.embedded',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 'CONFIRMED',
    description:
      'Executable header signature (PE/MZ, ELF, Mach-O) detected embedded inside container at non-zero offset.',
  },
  POLYGLOT_DETECTED: {
    reasonCode: 'POLYGLOT_DETECTED',
    checkId: 'scanner.polyglot',
    defaultOutcome: 'FAIL',
    defaultSeverity: 'CRITICAL',
    defaultConfidence: 'CONFIRMED',
    description:
      'Dual or contradictory valid file format signatures detected (e.g., GIF-ZIP, JPEG-ZIP, PDF-ZIP polyglot).',
  },
};

/**
 * Standard finding record model for P17 scan results.
 */
export interface ScanFindingRecord {
  checkId: CheckId;
  engine: string;
  engineVersion?: string | undefined;
  signatureVersion?: string | undefined;
  outcome: FindingOutcome;
  reasonCode: CanonicalReasonCode;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  evidence: Record<string, unknown>;
  durationMs: number;
  scannedStorageVersionId: string;
  scannedSha256: string;
  scannedSizeBytes: number;
}
