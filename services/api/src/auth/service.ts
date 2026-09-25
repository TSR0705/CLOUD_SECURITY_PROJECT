import {
  type ApiKeyDatabase,
  type ApiKeyRecord,
  type ApplicationRecord,
  type CreateApiKeyOptions,
  type CreateApiKeyResult,
  type CreateApplicationOptions,
  type VerifyApiKeyContext,
  type VerifyApiKeyResult,
} from './types.js';
import { generateRawKey, parseRawKey, computeKeyHmac, constantTimeCompare } from './keys.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function toSafeUuid(val?: string | null): string | null {
  if (val && UUID_REGEX.test(val)) {
    return val;
  }
  return null;
}

export interface ApiKeyServiceOptions {
  db: ApiKeyDatabase;
  pepper: string;
}

export class ApiKeyService {
  private readonly db: ApiKeyDatabase;
  private readonly pepper: string;

  constructor(options: ApiKeyServiceOptions) {
    if (!options.db) {
      throw new Error('ApiKeyService requires a database connection');
    }
    if (!options.pepper || typeof options.pepper !== 'string') {
      throw new Error('ApiKeyService requires an application pepper string');
    }
    this.db = options.db;
    this.pepper = options.pepper;
  }

  /**
   * Helper to safely append audit events without risking unhandled database rejections.
   */
  private async safeAuditAppend(
    actorType: 'api_key' | 'user' | 'service',
    actorId: string,
    action: string,
    refs: Record<string, unknown>,
    details: Record<string, unknown>,
  ): Promise<void> {
    try {
      const sanitizedRefs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(refs)) {
        if (v !== undefined && v !== null) {
          sanitizedRefs[k] = v;
        }
      }

      await this.db.query(`SELECT audit_append($1, $2, $3, $4::jsonb, $5::jsonb)`, [
        actorType,
        actorId,
        action,
        JSON.stringify(sanitizedRefs),
        JSON.stringify(details),
      ]);
    } catch {
      // In audit failures during auth, preserve fail-closed semantics without throwing uncaught server errors
    }
  }

  /**
   * Domain helper to create an application record.
   * Keeps application registration at domain level and avoids exposing unauthenticated admin endpoints.
   */
  async createApplication(options: CreateApplicationOptions): Promise<ApplicationRecord> {
    if (!options.name || options.name.length < 3 || options.name.length > 64) {
      throw new Error('Application name must be between 3 and 64 characters');
    }
    if (!toSafeUuid(options.ownerUserId)) {
      throw new Error('ownerUserId must be a valid UUID');
    }

    const res = await this.db.query<ApplicationRecord>(
      `INSERT INTO applications (name, owner_user_id, active_policy_id, webhook_url)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, owner_user_id, active_policy_id, webhook_url, webhook_secret, is_active, created_at`,
      [
        options.name,
        options.ownerUserId,
        toSafeUuid(options.activePolicyId),
        options.webhookUrl ?? null,
      ],
    );

    const row = res.rows[0];
    if (!row) {
      throw new Error('Failed to create application');
    }

    await this.safeAuditAppend(
      'user',
      options.ownerUserId,
      'application.created',
      { application_id: row.id },
      { name: options.name },
    );

    return row;
  }

  /**
   * Generates and stores a new API key for a registered application.
   * Computes HMAC-SHA-256 over the secret using the P4 pepper.
   * Returns the raw API key once to the caller. The raw secret is never stored.
   */
  async createApiKey(options: CreateApiKeyOptions): Promise<CreateApiKeyResult> {
    const appId = toSafeUuid(options.applicationId);
    if (!appId) {
      throw new Error('applicationId must be a valid UUID');
    }
    const createdBy = toSafeUuid(options.createdBy);
    if (!createdBy) {
      throw new Error('createdBy must be a valid UUID');
    }

    const scopes =
      options.scopes && options.scopes.length > 0 ? options.scopes : ['upload', 'read'];
    const expiresAt =
      options.expiresInDays && options.expiresInDays > 0
        ? new Date(Date.now() + options.expiresInDays * 24 * 60 * 60 * 1000)
        : null;

    // 1. Generate high-entropy CSPRNG key components
    const { rawKey, keyPrefix, secret } = generateRawKey();

    // 2. Compute HMAC-SHA-256 with the P4 pepper
    const keyHmac = computeKeyHmac(secret, this.pepper);

    // 3. Persist to PostgreSQL (only the 32-byte HMAC is stored)
    const res = await this.db.query<{ id: string; created_at: Date }>(
      `INSERT INTO api_keys (application_id, key_prefix, key_hmac, scopes, created_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, created_at`,
      [appId, keyPrefix, keyHmac, scopes, createdBy, expiresAt],
    );

    const row = res.rows[0];
    if (!row) {
      throw new Error('Failed to insert API key');
    }

    // 4. Record audit event (Zero secrets or raw keys logged)
    await this.safeAuditAppend(
      'user',
      createdBy,
      'api_key.created',
      { application_id: appId, api_key_id: row.id },
      { key_prefix: keyPrefix, scopes },
    );

    return {
      apiKeyId: row.id,
      rawKey,
      keyPrefix,
      applicationId: appId,
      scopes,
      expiresAt,
    };
  }

  /**
   * Verifies an incoming raw API key against stored HMACs in constant time.
   * Fast, indexed lookup via key_prefix.
   * Returns generic reason codes internally for audit logging without leaking details to callers.
   */
  async verifyApiKey(rawKey: unknown, context?: VerifyApiKeyContext): Promise<VerifyApiKeyResult> {
    const parsed = parseRawKey(rawKey);
    const safeReqId = toSafeUuid(context?.requestId);

    if (!parsed) {
      await this.safeAuditAppend(
        'api_key',
        'unknown',
        'api_key.auth_failure',
        { request_id: safeReqId, ip: context?.ip },
        { reason: 'INVALID_FORMAT' },
      );
      return { isValid: false, reason: 'INVALID_FORMAT' };
    }

    // Lookup row using indexed public key_prefix
    const res = await this.db.query<ApiKeyRecord>(
      `SELECT id, application_id, key_prefix, key_hmac, scopes, expires_at, revoked_at
       FROM api_keys
       WHERE key_prefix = $1`,
      [parsed.keyPrefix],
    );

    const row = res.rows[0];
    if (!row) {
      await this.safeAuditAppend(
        'api_key',
        parsed.keyPrefix,
        'api_key.auth_failure',
        { request_id: safeReqId, ip: context?.ip },
        { reason: 'KEY_NOT_FOUND', key_prefix: parsed.keyPrefix },
      );
      return { isValid: false, reason: 'KEY_NOT_FOUND' };
    }

    // Check revocation
    if (row.revoked_at !== null) {
      await this.safeAuditAppend(
        'api_key',
        row.id,
        'api_key.auth_failure',
        {
          application_id: row.application_id,
          api_key_id: row.id,
          request_id: safeReqId,
          ip: context?.ip,
        },
        { reason: 'KEY_REVOKED', key_prefix: row.key_prefix },
      );
      return { isValid: false, reason: 'KEY_REVOKED' };
    }

    // Check expiration
    if (row.expires_at !== null && new Date(row.expires_at).getTime() < Date.now()) {
      await this.safeAuditAppend(
        'api_key',
        row.id,
        'api_key.auth_failure',
        {
          application_id: row.application_id,
          api_key_id: row.id,
          request_id: safeReqId,
          ip: context?.ip,
        },
        { reason: 'KEY_EXPIRED', key_prefix: row.key_prefix },
      );
      return { isValid: false, reason: 'KEY_EXPIRED' };
    }

    // Compute expected HMAC and compare in constant time
    const expectedHmac = computeKeyHmac(parsed.secret, this.pepper);
    const isMatch = constantTimeCompare(row.key_hmac, expectedHmac);

    if (!isMatch) {
      await this.safeAuditAppend(
        'api_key',
        row.id,
        'api_key.auth_failure',
        {
          application_id: row.application_id,
          api_key_id: row.id,
          request_id: safeReqId,
          ip: context?.ip,
        },
        { reason: 'HMAC_MISMATCH', key_prefix: row.key_prefix },
      );
      return { isValid: false, reason: 'HMAC_MISMATCH' };
    }

    // Successful authentication
    await this.safeAuditAppend(
      'api_key',
      row.id,
      'api_key.auth_success',
      {
        application_id: row.application_id,
        api_key_id: row.id,
        request_id: safeReqId,
        ip: context?.ip,
      },
      { key_prefix: row.key_prefix },
    );

    return {
      isValid: true,
      app: {
        applicationId: row.application_id,
        apiKeyId: row.id,
        keyPrefix: row.key_prefix,
        scopes: row.scopes,
      },
    };
  }

  /**
   * Revokes an existing API key.
   * Revoked keys fail authentication immediately.
   */
  async revokeApiKey(apiKeyId: string, revokedBy?: string): Promise<boolean> {
    const safeKeyId = toSafeUuid(apiKeyId);
    if (!safeKeyId) {
      return false;
    }

    const res = await this.db.query<{ id: string; application_id: string; key_prefix: string }>(
      `UPDATE api_keys
       SET revoked_at = now()
       WHERE id = $1 AND revoked_at IS NULL
       RETURNING id, application_id, key_prefix`,
      [safeKeyId],
    );

    const row = res.rows[0];
    if (!row) {
      return false;
    }

    await this.safeAuditAppend(
      'user',
      toSafeUuid(revokedBy) ?? 'system',
      'api_key.revoked',
      { application_id: row.application_id, api_key_id: row.id },
      { key_prefix: row.key_prefix },
    );

    return true;
  }
}
