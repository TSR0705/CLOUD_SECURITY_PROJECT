/**
 * @sug/storage
 * Storage provider interfaces and adapters
 */

export const StoragePackageName = '@sug/storage' as const;

export interface StorageInfo {
  name: typeof StoragePackageName;
  version: string;
}

export const StorageInfo: StorageInfo = {
  name: StoragePackageName,
  version: '0.1.0',
};

// Error types
export {
  StorageError,
  type StorageErrorCode,
  type StorageErrorOptions,
  AlreadyExists,
  VersionMissing,
  NotFound,
  InvalidRequest,
  StorageUnavailable,
  PermissionDenied,
  sanitizeMessage,
} from './errors.js';

// Provider interface and DTO types
export {
  type StorageBody,
  type PutObjectParams,
  type PutObjectResult,
  type GetObjectParams,
  type GetObjectResult,
  type HeadObjectParams,
  type HeadObjectResult,
  type StorageProvider,
} from './types.js';

// Quarantine key utilities
export {
  buildQuarantineKey,
  isValidQuarantineIdentifier,
  parseQuarantineKey,
} from './quarantine.js';

// S3 Provider implementation
export { S3Provider, type S3ProviderOptions, createS3Provider } from './s3-provider.js';
