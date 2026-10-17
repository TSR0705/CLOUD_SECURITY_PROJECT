/**
 * Storage error hierarchy and sanitization
 * Ensures no credentials or sensitive tokens leak in error messages
 */

export type StorageErrorCode =
  | 'ALREADY_EXISTS'
  | 'VERSION_MISSING'
  | 'NOT_FOUND'
  | 'INVALID_REQUEST'
  | 'STORAGE_UNAVAILABLE'
  | 'PERMISSION_DENIED'
  | 'UNKNOWN';

const CREDENTIAL_PATTERNS = [
  /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
  /aws_secret_access_key\s*=\s*[^\s]+/gi,
  /secretAccessKey\s*[:=]\s*['"]?[^\s'",]+['"]?/gi,
  /password\s*[:=]\s*['"]?[^\s'",]+['"]?/gi,
  /Bearer\s+[A-Za-z0-9._~+/-]+=*/g,
  /authorization\s*:\s*[^\r\n]+/gi,
];

/**
 * Strips any potential credential leaks from error strings
 */
export function sanitizeMessage(msg: string): string {
  if (!msg || typeof msg !== 'string') {
    return 'Unknown storage error';
  }
  let sanitized = msg;
  for (const pattern of CREDENTIAL_PATTERNS) {
    sanitized = sanitized.replace(pattern, '[REDACTED]');
  }
  return sanitized;
}

export interface StorageErrorOptions {
  code: StorageErrorCode;
  statusCode: number;
  bucket?: string | undefined;
  key?: string | undefined;
  versionId?: string | undefined;
  cause?: unknown;
}

export class StorageError extends Error {
  readonly code: StorageErrorCode;
  readonly statusCode: number;
  readonly bucket?: string | undefined;
  readonly key?: string | undefined;
  readonly versionId?: string | undefined;

  constructor(message: string, options: StorageErrorOptions) {
    super(sanitizeMessage(message), { cause: options.cause });
    this.name = 'StorageError';
    this.code = options.code;
    this.statusCode = options.statusCode;
    this.bucket = options.bucket;
    this.key = options.key;
    this.versionId = options.versionId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AlreadyExists extends StorageError {
  constructor(bucket: string, key: string, cause?: unknown) {
    super(`Object already exists at bucket "${bucket}" key "${key}"`, {
      code: 'ALREADY_EXISTS',
      statusCode: 412,
      bucket,
      key,
      cause,
    });
    this.name = 'AlreadyExists';
  }
}

export class VersionMissing extends StorageError {
  constructor(bucket: string, key: string, versionId: string, cause?: unknown) {
    super(`Object version "${versionId}" not found for bucket "${bucket}" key "${key}"`, {
      code: 'VERSION_MISSING',
      statusCode: 404,
      bucket,
      key,
      versionId,
      cause,
    });
    this.name = 'VersionMissing';
  }
}

export class NotFound extends StorageError {
  constructor(bucket: string, key: string, cause?: unknown) {
    super(`Object not found at bucket "${bucket}" key "${key}"`, {
      code: 'NOT_FOUND',
      statusCode: 404,
      bucket,
      key,
      cause,
    });
    this.name = 'NotFound';
  }
}

export class InvalidRequest extends StorageError {
  constructor(
    message: string,
    details?: {
      bucket?: string | undefined;
      key?: string | undefined;
      versionId?: string | undefined;
      cause?: unknown;
    },
  ) {
    super(message, {
      code: 'INVALID_REQUEST',
      statusCode: 400,
      bucket: details?.bucket,
      key: details?.key,
      versionId: details?.versionId,
      cause: details?.cause,
    });
    this.name = 'InvalidRequest';
  }
}

export class StorageUnavailable extends StorageError {
  constructor(message: string, cause?: unknown) {
    super(message, {
      code: 'STORAGE_UNAVAILABLE',
      statusCode: 503,
      cause,
    });
    this.name = 'StorageUnavailable';
  }
}

export class PermissionDenied extends StorageError {
  constructor(message: string, cause?: unknown) {
    super(message, {
      code: 'PERMISSION_DENIED',
      statusCode: 403,
      cause,
    });
    this.name = 'PermissionDenied';
  }
}
