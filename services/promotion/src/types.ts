/**
 * @sug/service-promotion/types
 * Core types for exact-artifact promotion and clean storage writer.
 */

import type { DatabaseExecutor, ClaimedPromotionJob } from '@sug/shared';
import type { StorageProvider } from '@sug/storage';
import type { KeyProvider } from '@sug/crypto';

export type { ClaimedPromotionJob };

export type PromotionOutcome =
  | 'PROMOTED'
  | 'HASH_MISMATCH'
  | 'SIZE_MISMATCH'
  | 'ALREADY_EXISTS'
  | 'SUPERSEDED'
  | 'NOT_ALLOW'
  | 'ENCRYPTION_FAILED'
  | 'STORAGE_FAILED'
  | 'AUDIT_FAILED'
  | 'FAILED';

export interface PromotionResult {
  readonly success: boolean;
  readonly outcome: PromotionOutcome;
  readonly fileId: string;
  readonly fileVersionId: string;
  readonly cleanBucket?: string | undefined;
  readonly cleanObjectKey?: string | undefined;
  readonly cleanStorageVersionId?: string | undefined;
  readonly sha256Ciphertext?: string | undefined;
  readonly sha256Plaintext?: string | undefined;
  readonly envelopeLength?: number | undefined;
  readonly error?: string | undefined;
}

export interface PromotionServiceOptions {
  readonly db: DatabaseExecutor;
  readonly storageProvider: StorageProvider;
  readonly cleanBucket: string;
  readonly keyProvider: KeyProvider;
  readonly kekId?: string | undefined;
  readonly workerId?: string | undefined;
  readonly provider?: 'aws' | 'minio' | 'gcp' | undefined;
  readonly logger?: PromotionLogger | undefined;
}

export interface PromotionWorkerOptions extends PromotionServiceOptions {
  readonly pollIntervalMs?: number | undefined;
  readonly leaseTimeoutMs?: number | undefined;
}

export interface PromotionLogger {
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
  debug?(message: string, meta?: Record<string, unknown>): void;
}
