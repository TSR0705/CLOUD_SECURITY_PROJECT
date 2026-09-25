import crypto from 'node:crypto';
import type { ApiKeyDatabase } from './types.js';
import type {
  CreateUploadSessionOptions,
  CreateUploadSessionResult,
  AuthorizeSessionResult,
  UploadSessionRecord,
  SecurityPolicyRecord,
} from './session-types.js';
import { generateQuarantineKey, sanitizeOriginalFilename, toSafeUuid } from './session-utils.js';

export const MAX_UPLOAD_FILE_SIZE = 52428800; // 50 MB standard payload ceiling (ADR 0008, Scope)
export const DEFAULT_SESSION_DURATION_SECONDS = 600; // 10 minutes (ADR 0008)
export const MAX_SESSION_DURATION_SECONDS = 900; // 15 minutes max
export const MIN_SESSION_DURATION_SECONDS = 60; // 1 minute min

export class UploadAuthorizationService {
  private readonly db: ApiKeyDatabase;

  constructor({ db }: { db: ApiKeyDatabase }) {
    this.db = db;
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
          if (k === 'request_id') {
            const validUuid = toSafeUuid(v);
            if (validUuid) {
              sanitizedRefs[k] = validUuid;
            }
          } else {
            sanitizedRefs[k] = v;
          }
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
      // In audit failures, preserve fail-closed semantics without throwing uncaught server errors
    }
  }

  /**
   * Creates and reserves a new upload session bound to the authenticated application.
   * Enforces server-side expiration, declared size boundaries, and policy validation.
   */
  async createSession(options: CreateUploadSessionOptions): Promise<CreateUploadSessionResult> {
    const safeAppId = toSafeUuid(options.applicationId);
    if (!safeAppId) {
      throw new Error('applicationId must be a valid UUID');
    }

    const safeKeyId = toSafeUuid(options.apiKeyId);
    if (!safeKeyId) {
      throw new Error('apiKeyId must be a valid UUID');
    }

    // 1. Sanitize and validate filename (strips path traversal, null bytes, control chars)
    const sanitizedFilename = sanitizeOriginalFilename(options.filename);

    // 2. Validate declared size
    if (
      typeof options.declaredSize !== 'number' ||
      !Number.isSafeInteger(options.declaredSize) ||
      options.declaredSize <= 0
    ) {
      throw new Error('declaredSize must be a positive integer');
    }

    if (options.declaredSize > MAX_UPLOAD_FILE_SIZE) {
      throw new Error(
        `declaredSize exceeds maximum allowed file size of ${MAX_UPLOAD_FILE_SIZE} bytes`,
      );
    }

    // 3. Resolve active or specified policy for this application
    let policy: { id: string; document: Record<string, unknown> } | undefined;

    if (options.policyId) {
      const safePolicyId = toSafeUuid(options.policyId);
      if (!safePolicyId) {
        throw new Error('policyId must be a valid UUID');
      }

      const pRes = await this.db.query<SecurityPolicyRecord>(
        `SELECT id, version, document FROM security_policies WHERE id = $1 AND application_id = $2`,
        [safePolicyId, safeAppId],
      );
      if (pRes.rowCount === 0) {
        throw new Error('Specified policyId does not exist or does not belong to this application');
      }
      policy = pRes.rows[0];
    } else {
      const pRes = await this.db.query<SecurityPolicyRecord>(
        `SELECT id, version, document FROM security_policies WHERE application_id = $1 ORDER BY version DESC LIMIT 1`,
        [safeAppId],
      );
      if (pRes.rowCount === 0) {
        throw new Error('NO_ACTIVE_POLICY');
      }
      policy = pRes.rows[0];
    }

    if (!policy) {
      throw new Error('NO_ACTIVE_POLICY');
    }

    // Validate size against policy maxFileSize if defined
    const policyDoc = policy.document;
    const policyMaxSize =
      typeof policyDoc.maxFileSize === 'number' && policyDoc.maxFileSize > 0
        ? policyDoc.maxFileSize
        : MAX_UPLOAD_FILE_SIZE;

    if (options.declaredSize > policyMaxSize) {
      throw new Error(
        `declaredSize exceeds policy maximum allowed file size of ${policyMaxSize} bytes`,
      );
    }

    // 4. Calculate bounded server-side expiration (UTC)
    const rawDuration = options.durationSeconds ?? DEFAULT_SESSION_DURATION_SECONDS;
    const boundedDuration = Math.min(
      Math.max(rawDuration, MIN_SESSION_DURATION_SECONDS),
      MAX_SESSION_DURATION_SECONDS,
    );
    const expiresAt = new Date(Date.now() + boundedDuration * 1000);

    // 5. Generate secure identifiers
    const sessionId = crypto.randomUUID();
    const tokenJti = crypto.randomUUID();

    // 6. Parse optional declared SHA-256
    let sha256Buffer: Buffer | null = null;
    if (options.declaredSha256) {
      const trimmed = options.declaredSha256.trim();
      if (!/^[0-9a-f]{64}$/i.test(trimmed)) {
        throw new Error(
          'declaredSha256 must be a 64-character hex string representing a 32-byte digest',
        );
      }
      sha256Buffer = Buffer.from(trimmed, 'hex');
    }

    const safeClientRef = options.clientRef ? options.clientRef.slice(0, 128) : null;

    // 7. Persist to PostgreSQL (status = 'CREATED')
    const insertRes = await this.db.query<UploadSessionRecord>(
      `INSERT INTO upload_sessions (
         id, application_id, api_key_id, policy_id, client_ref,
         original_filename, declared_mime, declared_size, declared_sha256,
         status, token_jti, expires_at, client_ip
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'CREATED', $10, $11, $12)
       RETURNING *`,
      [
        sessionId,
        safeAppId,
        safeKeyId,
        policy.id,
        safeClientRef,
        sanitizedFilename,
        options.declaredMime.slice(0, 127),
        options.declaredSize,
        sha256Buffer,
        tokenJti,
        expiresAt,
        options.clientIp ?? null,
      ],
    );

    const row = insertRes.rows[0];
    if (!row) {
      throw new Error('Failed to create upload session row');
    }

    const quarantineKey = generateQuarantineKey(safeAppId, sessionId);

    // 8. Transactional Audit Log
    await this.safeAuditAppend(
      'api_key',
      safeKeyId,
      'upload_session.created',
      { application_id: safeAppId, request_id: options.requestId },
      {
        session_id: sessionId,
        original_filename: sanitizedFilename,
        declared_size: options.declaredSize,
        declared_mime: options.declaredMime,
        policy_id: policy.id,
      },
    );

    return {
      sessionId: row.id,
      applicationId: row.application_id,
      status: row.status,
      quarantineKey,
      tokenJti: row.token_jti,
      policyId: row.policy_id,
      expiresAt: row.expires_at.toISOString(),
      maxFileSize: policyMaxSize,
      declaredSize: Number(row.declared_size),
      declaredMime: row.declared_mime,
    };
  }

  /**
   * Retrieves an upload session strictly scoped to the authenticated application.
   * If the session belongs to a different application, returns null to avoid tenancy leakage.
   * Lazily marks expired sessions.
   */
  async getSession(sessionId: string, applicationId: string): Promise<UploadSessionRecord | null> {
    const safeSessionId = toSafeUuid(sessionId);
    const safeAppId = toSafeUuid(applicationId);
    if (!safeSessionId || !safeAppId) {
      return null;
    }

    const res = await this.db.query<UploadSessionRecord>(
      `SELECT * FROM upload_sessions WHERE id = $1 AND application_id = $2`,
      [safeSessionId, safeAppId],
    );

    const session = res.rows[0];
    if (!session) {
      return null;
    }

    // Lazy expiration check
    if (session.status === 'CREATED' && new Date(session.expires_at).getTime() < Date.now()) {
      const expRes = await this.db.query<UploadSessionRecord>(
        `UPDATE upload_sessions SET status = 'EXPIRED' WHERE id = $1 AND status = 'CREATED' RETURNING *`,
        [session.id],
      );
      if (expRes.rowCount && expRes.rowCount > 0) {
        await this.safeAuditAppend(
          'service',
          'api_gateway',
          'upload_session.expired',
          { application_id: safeAppId },
          { session_id: session.id },
        );
        return expRes.rows[0] ?? null;
      }
    }

    return session;
  }

  /**
   * Authorizes and atomically claims an upload session (CREATED -> UPLOADING).
   * Enforces single-use optimistic locking: prevents reuse after completion, after expiration,
   * or concurrent claim races.
   */
  async authorizeSession(
    sessionId: string,
    applicationId: string,
    requestId?: string,
  ): Promise<AuthorizeSessionResult> {
    const safeSessionId = toSafeUuid(sessionId);
    const safeAppId = toSafeUuid(applicationId);
    if (!safeSessionId || !safeAppId) {
      return { isAuthorized: false, reason: 'NOT_FOUND' };
    }

    // Atomic conditional update
    const updateRes = await this.db.query<UploadSessionRecord>(
      `UPDATE upload_sessions
       SET status = 'UPLOADING'
       WHERE id = $1 AND application_id = $2 AND status = 'CREATED' AND expires_at > now()
       RETURNING *`,
      [safeSessionId, safeAppId],
    );

    const session = updateRes.rows[0];
    if (session) {
      await this.safeAuditAppend(
        'api_key',
        session.api_key_id,
        'upload_session.authorized',
        { application_id: safeAppId, request_id: requestId },
        { session_id: safeSessionId },
      );
      return { isAuthorized: true, session };
    }

    // Inspect failure cause without race condition
    const checkRes = await this.db.query<{ status: string; expires_at: Date }>(
      `SELECT status, expires_at FROM upload_sessions WHERE id = $1 AND application_id = $2`,
      [safeSessionId, safeAppId],
    );

    const row = checkRes.rows[0];
    if (!row) {
      return { isAuthorized: false, reason: 'NOT_FOUND' };
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      // Mark expired
      await this.db.query(
        `UPDATE upload_sessions SET status = 'EXPIRED' WHERE id = $1 AND status = 'CREATED'`,
        [safeSessionId],
      );
      await this.safeAuditAppend(
        'service',
        'api_gateway',
        'upload_session.claim_failed',
        { application_id: safeAppId, request_id: requestId },
        { session_id: safeSessionId, reason: 'EXPIRED' },
      );
      return { isAuthorized: false, reason: 'EXPIRED' };
    }

    if (row.status === 'UPLOADING' || row.status === 'UPLOADED') {
      await this.safeAuditAppend(
        'service',
        'api_gateway',
        'upload_session.claim_failed',
        { application_id: safeAppId, request_id: requestId },
        { session_id: safeSessionId, reason: 'ALREADY_CLAIMED' },
      );
      return { isAuthorized: false, reason: 'ALREADY_CLAIMED' };
    }

    return { isAuthorized: false, reason: 'INVALID_STATE' };
  }

  /**
   * Completes an upload session (UPLOADING -> UPLOADED).
   */
  async completeSession(
    sessionId: string,
    applicationId: string,
    requestId?: string,
  ): Promise<UploadSessionRecord | null> {
    const safeSessionId = toSafeUuid(sessionId);
    const safeAppId = toSafeUuid(applicationId);
    if (!safeSessionId || !safeAppId) {
      return null;
    }

    const res = await this.db.query<UploadSessionRecord>(
      `UPDATE upload_sessions
       SET status = 'UPLOADED', completed_at = now()
       WHERE id = $1 AND application_id = $2 AND status = 'UPLOADING'
       RETURNING *`,
      [safeSessionId, safeAppId],
    );

    const row = res.rows[0];
    if (row) {
      await this.safeAuditAppend(
        'api_key',
        row.api_key_id,
        'upload_session.completed',
        { application_id: safeAppId, request_id: requestId },
        { session_id: safeSessionId },
      );
    }

    return row ?? null;
  }

  /**
   * Aborts an upload session (CREATED or UPLOADING -> FAILED).
   */
  async abortSession(
    sessionId: string,
    applicationId: string,
    reason?: string,
    requestId?: string,
  ): Promise<UploadSessionRecord | null> {
    const safeSessionId = toSafeUuid(sessionId);
    const safeAppId = toSafeUuid(applicationId);
    if (!safeSessionId || !safeAppId) {
      return null;
    }

    const res = await this.db.query<UploadSessionRecord>(
      `UPDATE upload_sessions
       SET status = 'FAILED'
       WHERE id = $1 AND application_id = $2 AND status IN ('CREATED', 'UPLOADING')
       RETURNING *`,
      [safeSessionId, safeAppId],
    );

    const row = res.rows[0];
    if (row) {
      await this.safeAuditAppend(
        'api_key',
        row.api_key_id,
        'upload_session.aborted',
        { application_id: safeAppId, request_id: requestId },
        { session_id: safeSessionId, reason: reason ?? 'USER_ABORTED' },
      );
    }

    return row ?? null;
  }
}
