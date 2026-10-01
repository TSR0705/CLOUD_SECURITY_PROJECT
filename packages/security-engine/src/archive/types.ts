/**
 * @sug/security-engine/archive
 * Type definitions and budget contracts for safe two-phase ZIP and OOXML inspection.
 */

import type { SeverityLevel, ConfidenceLevel } from '@sug/shared';
export type { SeverityLevel, ConfidenceLevel };

export type ArchiveStatus = 'CLEAN' | 'REJECTED' | 'ERROR';

export type ArchiveReasonCode =
  | 'CLEAN'
  | 'ARCHIVE_BOMB_DETECTED'
  | 'COMPRESSION_RATIO_EXCEEDED'
  | 'ENTRY_COUNT_EXCEEDED'
  | 'UNCOMPRESSED_SIZE_EXCEEDED'
  | 'COMPRESSED_SIZE_EXCEEDED'
  | 'OVERLAPPING_ENTRIES'
  | 'DUPLICATE_ENTRY_NAMES'
  | 'UNSAFE_PATH'
  | 'ZIP_SLIP_DETECTED'
  | 'ENCRYPTED_ARCHIVE_FORBIDDEN'
  | 'UNSUPPORTED_COMPRESSION_METHOD'
  | 'SYMLINK_FORBIDDEN'
  | 'NESTED_ARCHIVE_DEPTH_EXCEEDED'
  | 'CORRUPT_ARCHIVE'
  | 'MALFORMED_EOCD'
  | 'MULTIPLE_EOCD_DETECTED'
  | 'SIZE_MISMATCH'
  | 'CRC_MISMATCH'
  | 'TIMEOUT_EXCEEDED'
  | 'MEMORY_BUDGET_EXCEEDED'
  | 'ARCHIVE_FORBIDDEN'
  | 'INSPECTION_ERROR';

/**
 * Immutable resource budget for archive inspection.
 * Reconciled with P8 ArchivePolicySchema and hard engineering ceilings.
 */
export interface ArchiveInspectionBudget {
  /** Maximum compressed archive size in bytes (default: 50 MB) */
  maxCompressedSize: number;
  /** Maximum cumulative uncompressed bytes allowed across all entries (default: 100 MB) */
  maxUncompressedSize: number;
  /** Maximum number of entries allowed in central directory (default: 1,000) */
  maxEntries: number;
  /** Maximum nested archive depth allowed (default: 3) */
  maxDepth: number;
  /** Maximum allowed expansion ratio (uncompressed : compressed, default: 100:1) */
  maxRatio: number;
  /** Maximum inspection duration in milliseconds (default: 10,000 ms / 10s) */
  maxExtractionMs: number;
  /** Maximum worker memory RSS in bytes (default: 256 MB) */
  maxMemoryBytes: number;
}

/**
 * Canonical default archive inspection budget (aligned with ADR 0009 & P8 defaults).
 */
export const DEFAULT_ARCHIVE_BUDGET: Readonly<ArchiveInspectionBudget> = Object.freeze({
  maxCompressedSize: 52_428_800, // 50 MB
  maxUncompressedSize: 104_857_600, // 100 MB
  maxEntries: 1_000,
  maxDepth: 3,
  maxRatio: 100, // 100:1
  maxExtractionMs: 10_000, // 10 seconds
  maxMemoryBytes: 268_435_456, // 256 MB RSS
});

/**
 * Metadata for a single entry inspected in the archive.
 */
export interface ArchiveEntryInfo {
  fileName: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number; // 0 = stored, 8 = deflated
  crc32: number;
  relativeOffset: number;
  isEncrypted: boolean;
  isSymlink: boolean;
  isNestedArchive: boolean;
}

/**
 * Result of Phase 1 structural inspection.
 */
export interface StructuralInspectionResult {
  valid: boolean;
  reasonCode: ArchiveReasonCode;
  reason: string;
  entryCount: number;
  totalDeclaredCompressed: number;
  totalDeclaredUncompressed: number;
  entries: ArchiveEntryInfo[];
  eocdOffset: number;
  cdOffset: number;
  cdSize: number;
}

/**
 * Comprehensive result of archive inspection returned to scanner service.
 */
export interface ArchiveInspectionResult {
  status: ArchiveStatus;
  reasonCode: ArchiveReasonCode;
  reason: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  entryCount: number;
  totalCompressedBytes: number;
  totalDecompressedBytes: number;
  compressionRatio: number;
  maxNestingDepth: number;
  durationMs: number;
  /**
   * Process-level Resident Set Size (RSS) in bytes measured during inspection execution.
   * Note: In Node.js, worker_threads share the host OS process memory space;
   * this metric reflects the overall Node.js process RSS during worker execution.
   */
  workerRssBytes: number;
  entries: ArchiveEntryInfo[];
  details?: Record<string, unknown> | undefined;
}

/**
 * Input options passed to inspectArchive.
 */
export interface ArchiveInspectionInput {
  filePath: string;
  budget?: Partial<ArchiveInspectionBudget> | undefined;
  archiveAllowed?: boolean | undefined;
  isOoxml?: boolean | undefined;
  currentDepth?: number | undefined;
  totalDecompressedPrior?: number | undefined;
}
