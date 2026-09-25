/**
 * Core type definitions for Phase P6 Application API Key Authentication.
 */

export interface ApiKeyRecord {
  id: string;
  application_id: string;
  key_prefix: string;
  key_hmac: Buffer;
  scopes: string[];
  created_by: string;
  created_at: Date;
  expires_at: Date | null;
  revoked_at: Date | null;
  last_used_at: Date | null;
}

export interface ApplicationRecord {
  id: string;
  name: string;
  owner_user_id: string;
  active_policy_id: string | null;
  webhook_url: string | null;
  webhook_secret: Buffer | null;
  is_active: boolean;
  created_at: Date;
}

export interface AuthenticatedApplication {
  applicationId: string;
  apiKeyId: string;
  keyPrefix: string;
  scopes: string[];
}

export interface CreateApiKeyOptions {
  applicationId: string;
  createdBy: string;
  scopes?: string[] | undefined;
  expiresInDays?: number | undefined;
}

export interface CreateApiKeyResult {
  apiKeyId: string;
  rawKey: string;
  keyPrefix: string;
  applicationId: string;
  scopes: string[];
  expiresAt: Date | null;
}

export interface VerifyApiKeyContext {
  ip?: string | undefined;
  requestId?: string | undefined;
}

export interface VerifyApiKeyResult {
  isValid: boolean;
  app?: AuthenticatedApplication | undefined;
  reason?:
    | 'INVALID_FORMAT'
    | 'KEY_NOT_FOUND'
    | 'KEY_REVOKED'
    | 'KEY_EXPIRED'
    | 'HMAC_MISMATCH'
    | undefined;
}

export interface CreateApplicationOptions {
  name: string;
  ownerUserId: string;
  activePolicyId?: string | undefined;
  webhookUrl?: string | undefined;
}

/**
 * Minimal database interface required by ApiKeyService.
 * Compatible with pg.Pool and pg.PoolClient.
 */
export interface ApiKeyDatabase {
  query<T = unknown>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[]; rowCount?: number | null }>;
}
