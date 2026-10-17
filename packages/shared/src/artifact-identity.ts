import crypto from 'node:crypto';

/**
 * Canonical regular expression for a valid SHA-256 hex digest:
 * Exactly 64 hexadecimal characters (case-insensitive for validation, stored lowercase).
 */
export const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/i;

/**
 * Core cryptographic artifact identity representing exactly one quarantined object version.
 *
 * An ArtifactIdentity binds:
 * - Storage location: bucket + objectKey
 * - Storage immutability: exact versionId (never empty, null, or 'latest')
 * - Content integrity: server-computed SHA-256 digest
 * - Payload size: byte length (integer >= 0)
 */
export interface ArtifactIdentity {
  readonly bucket: string;
  readonly objectKey: string;
  readonly versionId: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}

export type IdentityMismatchClass =
  'bucket' | 'object_key' | 'version_id' | 'sha256' | 'size_bytes';

export interface IdentityComparisonResult {
  readonly equal: boolean;
  readonly mismatches: readonly IdentityMismatchClass[];
  readonly reason: string;
}

export interface IdentityValidationResult {
  readonly valid: boolean;
  readonly issues: readonly string[];
  readonly reason: string;
}

export class ArtifactIdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ArtifactIdentityError';
  }
}

export const CANONICAL_SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;

/**
 * Checks whether a value is a valid 64-character hexadecimal SHA-256 string.
 */
export function isValidSha256(raw: unknown): boolean {
  if (typeof raw !== 'string') return false;
  let trimmed = raw.trim().toLowerCase();
  if (trimmed.startsWith('\\x') || trimmed.startsWith('0x')) {
    trimmed = trimmed.slice(2);
  }
  return CANONICAL_SHA256_HEX_REGEX.test(trimmed);
}

/**
 * Normalizes a SHA-256 string to 64 lowercase hexadecimal characters.
 * Throws ArtifactIdentityError if malformed.
 */
export function normalizeSha256(raw: string): string {
  if (typeof raw !== 'string') {
    throw new ArtifactIdentityError('SHA-256 digest must be a string');
  }
  let trimmed = raw.trim().toLowerCase();
  if (trimmed.startsWith('\\x') || trimmed.startsWith('0x')) {
    trimmed = trimmed.slice(2);
  }
  if (!CANONICAL_SHA256_HEX_REGEX.test(trimmed)) {
    throw new ArtifactIdentityError(
      `Invalid SHA-256 digest: expected 64 hex characters, received '${raw}'`,
    );
  }
  return trimmed;
}

/**
 * Converts a SHA-256 digest (hex string or 32-byte Buffer) to canonical 64-char lowercase hex.
 */
export function toCanonicalSha256(raw: string | Buffer | Uint8Array): string {
  if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) {
    if (raw.length !== 32) {
      throw new ArtifactIdentityError(
        `Invalid SHA-256 buffer length: expected 32 bytes, received ${raw.length}`,
      );
    }
    return Buffer.from(raw).toString('hex').toLowerCase();
  }
  return normalizeSha256(raw);
}

/**
 * Validates whether an object conforms to the ArtifactIdentity invariant.
 */
export function validateArtifactIdentity(input: unknown): IdentityValidationResult {
  const issues: string[] = [];

  if (!input || typeof input !== 'object') {
    return {
      valid: false,
      issues: ['Identity input must be a non-null object'],
      reason: 'Identity input must be a non-null object',
    };
  }

  const rec = input as Record<string, unknown>;

  // 1. Bucket
  if (typeof rec.bucket !== 'string' || rec.bucket.trim() === '') {
    issues.push('bucket must be a non-empty string');
  }

  // 2. Object Key
  if (typeof rec.objectKey !== 'string' || rec.objectKey.trim() === '') {
    issues.push('objectKey must be a non-empty string');
  }

  // 3. Version ID (strictly required, cannot be empty, null, or 'latest')
  if (
    typeof rec.versionId !== 'string' ||
    rec.versionId.trim() === '' ||
    rec.versionId.trim().toLowerCase() === 'null' ||
    rec.versionId.trim().toLowerCase() === 'latest'
  ) {
    issues.push(
      "versionId must be a non-empty, non-null storage version identifier (cannot be 'latest')",
    );
  }

  // 4. SHA-256
  if (!isValidSha256(rec.sha256)) {
    issues.push('sha256 must be a valid 64-character hexadecimal digest matching ^[0-9a-f]{64}$');
  }

  // 5. Size Bytes
  if (typeof rec.sizeBytes !== 'number' || !Number.isInteger(rec.sizeBytes) || rec.sizeBytes < 0) {
    issues.push('sizeBytes must be a non-negative integer');
  }

  const valid = issues.length === 0;
  return {
    valid,
    issues,
    reason: valid
      ? 'ArtifactIdentity is valid'
      : `ArtifactIdentity validation failed: ${issues.join('; ')}`,
  };
}

/**
 * Type guard checking if an unknown value is a valid ArtifactIdentity.
 */
export function isArtifactIdentity(val: unknown): val is ArtifactIdentity {
  return validateArtifactIdentity(val).valid;
}

export interface CreateArtifactIdentityInput {
  bucket: string;
  objectKey: string;
  versionId: string;
  sha256: string | Buffer | Uint8Array;
  sizeBytes: number | bigint | string;
}

/**
 * Constructs an immutable, validated ArtifactIdentity instance from database records,
 * S3 PutObject results, or ingest stream metadata.
 */
export function createArtifactIdentity(input: CreateArtifactIdentityInput): ArtifactIdentity {
  const { bucket, objectKey, versionId, sha256, sizeBytes } = input;

  if (typeof bucket !== 'string' || !bucket.trim()) {
    throw new ArtifactIdentityError('bucket is required and must be a non-empty string');
  }

  if (typeof objectKey !== 'string' || !objectKey.trim()) {
    throw new ArtifactIdentityError('objectKey is required and must be a non-empty string');
  }

  const cleanVersionId = typeof versionId === 'string' ? versionId.trim() : '';
  if (
    !cleanVersionId ||
    cleanVersionId.toLowerCase() === 'null' ||
    cleanVersionId.toLowerCase() === 'latest'
  ) {
    throw new ArtifactIdentityError(
      `versionId is strictly required and cannot be empty, 'null', or 'latest' (received '${versionId}')`,
    );
  }

  const canonicalSha = toCanonicalSha256(sha256);

  let numSizeBytes: number;
  if (typeof sizeBytes === 'bigint') {
    numSizeBytes = Number(sizeBytes);
  } else if (typeof sizeBytes === 'string') {
    numSizeBytes = Number(sizeBytes);
  } else if (typeof sizeBytes === 'number') {
    numSizeBytes = sizeBytes;
  } else {
    throw new ArtifactIdentityError('sizeBytes must be a number, bigint, or numeric string');
  }

  if (!Number.isInteger(numSizeBytes) || numSizeBytes < 0) {
    throw new ArtifactIdentityError(
      `sizeBytes must be a non-negative integer, received '${sizeBytes}'`,
    );
  }

  return Object.freeze({
    bucket: bucket.trim(),
    objectKey: objectKey.trim(),
    versionId: cleanVersionId,
    sha256: canonicalSha,
    sizeBytes: numSizeBytes,
  });
}

/**
 * Timing-safe cryptographic comparison of two SHA-256 strings.
 * Safely converts hex strings to 32-byte buffers and invokes crypto.timingSafeEqual.
 * Returns false without throwing if either hash is missing, malformed, or of unequal length.
 */
export function timingSafeSha256Equal(hashA?: string | null, hashB?: string | null): boolean {
  if (typeof hashA !== 'string' || typeof hashB !== 'string') {
    return false;
  }

  let cleanA = hashA.trim().toLowerCase();
  let cleanB = hashB.trim().toLowerCase();
  if (cleanA.startsWith('\\x') || cleanA.startsWith('0x')) cleanA = cleanA.slice(2);
  if (cleanB.startsWith('\\x') || cleanB.startsWith('0x')) cleanB = cleanB.slice(2);

  if (!CANONICAL_SHA256_HEX_REGEX.test(cleanA) || !CANONICAL_SHA256_HEX_REGEX.test(cleanB)) {
    return false;
  }

  const bufA = Buffer.from(cleanA, 'hex');
  const bufB = Buffer.from(cleanB, 'hex');

  if (bufA.length !== 32 || bufB.length !== 32) {
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Cryptographic comparison utility comparing two ArtifactIdentities across:
 * 1. bucket
 * 2. objectKey
 * 3. versionId
 * 4. sha256 (timing-safe)
 * 5. sizeBytes
 *
 * Deterministically records every differing field class into mismatches.
 * Never throws on malformed or mismatched inputs.
 */
export function compareArtifactIdentities(
  a?: ArtifactIdentity | Record<string, unknown> | null,
  b?: ArtifactIdentity | Record<string, unknown> | null,
): IdentityComparisonResult {
  const mismatches: IdentityMismatchClass[] = [];

  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') {
    return {
      equal: false,
      mismatches: ['bucket', 'object_key', 'version_id', 'sha256', 'size_bytes'],
      reason: 'One or both candidate identities are null, undefined, or not objects',
    };
  }

  // 1. Bucket comparison
  if (
    typeof a.bucket !== 'string' ||
    typeof b.bucket !== 'string' ||
    !a.bucket.trim() ||
    !b.bucket.trim() ||
    a.bucket.trim() !== b.bucket.trim()
  ) {
    mismatches.push('bucket');
  }

  // 2. Object key comparison
  if (
    typeof a.objectKey !== 'string' ||
    typeof b.objectKey !== 'string' ||
    !a.objectKey.trim() ||
    !b.objectKey.trim() ||
    a.objectKey.trim() !== b.objectKey.trim()
  ) {
    mismatches.push('object_key');
  }

  // 3. Storage VersionId comparison (must be non-empty, not 'null', not 'latest')
  const vA = typeof a.versionId === 'string' ? a.versionId.trim() : '';
  const vB = typeof b.versionId === 'string' ? b.versionId.trim() : '';
  if (
    !vA ||
    !vB ||
    vA.toLowerCase() === 'null' ||
    vB.toLowerCase() === 'null' ||
    vA.toLowerCase() === 'latest' ||
    vB.toLowerCase() === 'latest' ||
    vA !== vB
  ) {
    mismatches.push('version_id');
  }

  // 4. SHA-256 comparison (timing-safe)
  const shaA = typeof a.sha256 === 'string' ? a.sha256 : '';
  const shaB = typeof b.sha256 === 'string' ? b.sha256 : '';
  if (!timingSafeSha256Equal(shaA, shaB)) {
    mismatches.push('sha256');
  }

  // 5. Size Bytes comparison
  if (
    typeof a.sizeBytes !== 'number' ||
    typeof b.sizeBytes !== 'number' ||
    !Number.isInteger(a.sizeBytes) ||
    !Number.isInteger(b.sizeBytes) ||
    a.sizeBytes < 0 ||
    b.sizeBytes < 0 ||
    a.sizeBytes !== b.sizeBytes
  ) {
    mismatches.push('size_bytes');
  }

  const equal = mismatches.length === 0;
  return {
    equal,
    mismatches,
    reason: equal
      ? 'Artifact identities are completely identical'
      : `Identities differ in: ${mismatches.join(', ')}`,
  };
}
