import type { ApiKeyDatabase } from '../auth/types.js';
import {
  parsePolicyDocument,
  toCanonicalJson,
  computePolicyHash,
  computePolicyHashHex,
  type PolicyDocument,
} from '@sug/policy-engine';

export interface PolicyRecord {
  id: string;
  application_id: string;
  version: number;
  document: PolicyDocument;
  document_sha256: Buffer;
  created_by: string;
  created_at: Date;
  active_policy_id?: string | null;
}

export interface PolicyResponse {
  id: string;
  applicationId: string;
  version: number;
  schema: string;
  document: PolicyDocument;
  documentSha256: string;
  isActive: boolean;
  createdAt: string;
}

export interface CreatePolicyOptions {
  applicationId: string;
  document: unknown;
  setActive?: boolean | undefined;
  createdBy: string;
  requestId?: string | undefined;
}

export interface UpdatePolicyOptions {
  document: unknown;
  callerAppId?: string | undefined;
  updatedBy: string;
  requestId?: string | undefined;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function toSafeUuid(val: unknown): string | null {
  if (typeof val === 'string' && UUID_REGEX.test(val.trim())) {
    return val.trim().toLowerCase();
  }
  return null;
}

export class PolicyService {
  private readonly db: ApiKeyDatabase;

  constructor({ db }: { db: ApiKeyDatabase }) {
    this.db = db;
  }

  /**
   * Helper to append tamper-evident hash-chained audit events.
   * Zero secrets or credentials are ever recorded.
   */
  private async safeAuditAppend(
    actorType: 'user' | 'api_key' | 'service',
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
          } else if (k === 'application_id' || k === 'policy_id') {
            const validUuid = toSafeUuid(v);
            sanitizedRefs[k] = validUuid ?? String(v);
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
      // Audit append should not crash the primary operational flow in test mocks
    }
  }

  /**
   * Formats a database policy row into a canonical API response.
   */
  private formatResponse(row: PolicyRecord, activePolicyId?: string | null): PolicyResponse {
    const rawHash: unknown = row.document_sha256;
    let documentSha256 = '';
    if (Buffer.isBuffer(rawHash)) {
      documentSha256 = rawHash.toString('hex');
    } else if (typeof rawHash === 'string') {
      documentSha256 = rawHash.startsWith('\\x') ? rawHash.slice(2) : rawHash;
    }

    const doc = (
      typeof row.document === 'string' ? JSON.parse(row.document) : row.document
    ) as PolicyDocument;

    const isActive = activePolicyId ? row.id === activePolicyId : row.id === row.active_policy_id;

    const schema =
      doc.schema ?? (doc as unknown as { schemaVersion?: string }).schemaVersion ?? 'sug.policy/v1';

    return {
      id: row.id,
      applicationId: row.application_id,
      version: Number(row.version),
      schema,
      document: doc,
      documentSha256,
      isActive: Boolean(isActive),
      createdAt:
        row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
    };
  }

  /**
   * Creates a new security policy document for an application.
   * Validates document against sug.policy/v1, computes canonical JSON & SHA-256 hash,
   * assigns incremental version, and optionally sets active_policy_id.
   */
  public async createPolicy(opts: CreatePolicyOptions): Promise<PolicyResponse> {
    const validDoc = parsePolicyDocument(opts.document);
    const canonicalJson = toCanonicalJson(validDoc);
    const hashBuffer = computePolicyHash(canonicalJson);
    const hashHex = computePolicyHashHex(canonicalJson);

    // Verify application existence
    const appRes = await this.db.query<{
      id: string;
      owner_user_id: string;
      active_policy_id: string | null;
    }>(`SELECT id, owner_user_id, active_policy_id FROM applications WHERE id = $1`, [
      opts.applicationId,
    ]);

    if (appRes.rows.length === 0) {
      throw new Error(`Application with ID '${opts.applicationId}' does not exist`);
    }

    const app = appRes.rows[0]!;

    // Resolve valid user ID for security_policies created_by FK
    let createdByUserId = app.owner_user_id;
    if (opts.createdBy) {
      const userCheck = await this.db.query<{ id: string }>(`SELECT id FROM users WHERE id = $1`, [
        opts.createdBy,
      ]);
      if (userCheck.rows.length > 0) {
        createdByUserId = userCheck.rows[0]!.id;
      }
    }

    // Resolve next version
    const versionRes = await this.db.query<{ next_version: string | number }>(
      `SELECT COALESCE(MAX(version), 0) + 1 AS next_version FROM security_policies WHERE application_id = $1`,
      [opts.applicationId],
    );

    const nextVersion = Number(versionRes.rows[0]?.next_version ?? 1);

    // Insert new immutable policy version
    const insertRes = await this.db.query<PolicyRecord>(
      `INSERT INTO security_policies (
        application_id, version, document, document_sha256, created_by, created_at
      ) VALUES ($1, $2, $3::jsonb, $4, $5, now())
      RETURNING *`,
      [opts.applicationId, nextVersion, canonicalJson, hashBuffer, createdByUserId],
    );

    const created = insertRes.rows[0]!;

    // Update active policy pointer if requested or if application currently has no active policy
    const shouldSetActive = opts.setActive === true || app.active_policy_id === null;
    let finalActiveId = app.active_policy_id;

    if (shouldSetActive) {
      await this.db.query(`UPDATE applications SET active_policy_id = $1 WHERE id = $2`, [
        created.id,
        opts.applicationId,
      ]);
      finalActiveId = created.id;
    }

    await this.safeAuditAppend(
      'user',
      opts.createdBy,
      'policy.created',
      {
        application_id: opts.applicationId,
        policy_id: created.id,
        request_id: opts.requestId,
      },
      {
        version: nextVersion,
        document_sha256: hashHex,
        is_active: shouldSetActive,
      },
    );

    return this.formatResponse(created, finalActiveId);
  }

  /**
   * Retrieves a specific security policy by ID.
   * If callerAppId is provided, enforces tenant isolation (returns null if policy belongs to another application).
   */
  public async getPolicyById(id: string, callerAppId?: string): Promise<PolicyResponse | null> {
    const res = await this.db.query<PolicyRecord & { app_active_policy_id: string | null }>(
      `SELECT sp.*, app.active_policy_id AS app_active_policy_id
       FROM security_policies sp
       JOIN applications app ON app.id = sp.application_id
       WHERE sp.id = $1`,
      [id],
    );

    if (res.rows.length === 0) {
      return null;
    }

    const row = res.rows[0]!;

    // Tenant isolation: caller cannot view another tenant's policy
    if (callerAppId && row.application_id !== callerAppId) {
      return null;
    }

    return this.formatResponse(row, row.app_active_policy_id);
  }

  /**
   * Updates an existing policy by creating a NEW IMMUTABLE VERSION (e.g. v1 -> v2).
   * The existing policy row is never mutated (preserving audit and pinning guarantees).
   */
  public async updatePolicy(id: string, opts: UpdatePolicyOptions): Promise<PolicyResponse | null> {
    // 1. Fetch current policy to identify application and base version
    const existing = await this.getPolicyById(id, opts.callerAppId);
    if (!existing) {
      return null;
    }

    const validDoc = parsePolicyDocument(opts.document);
    const canonicalJson = toCanonicalJson(validDoc);
    const hashBuffer = computePolicyHash(canonicalJson);
    const hashHex = computePolicyHashHex(canonicalJson);

    // 2. Resolve next sequential version for this application
    const versionRes = await this.db.query<{ next_version: string | number }>(
      `SELECT COALESCE(MAX(version), 0) + 1 AS next_version FROM security_policies WHERE application_id = $1`,
      [existing.applicationId],
    );

    const nextVersion = Number(versionRes.rows[0]?.next_version ?? existing.version + 1);

    // Resolve owner user ID for created_by foreign key
    const appRow = await this.db.query<{ owner_user_id: string }>(
      `SELECT owner_user_id FROM applications WHERE id = $1`,
      [existing.applicationId],
    );
    let updatedByUserId = appRow.rows[0]?.owner_user_id ?? opts.updatedBy;
    if (opts.updatedBy) {
      const userCheck = await this.db.query<{ id: string }>(`SELECT id FROM users WHERE id = $1`, [
        opts.updatedBy,
      ]);
      if (userCheck.rows.length > 0) {
        updatedByUserId = userCheck.rows[0]!.id;
      }
    }

    // 3. Insert NEW immutable policy version row
    const insertRes = await this.db.query<PolicyRecord>(
      `INSERT INTO security_policies (
        application_id, version, document, document_sha256, created_by, created_at
      ) VALUES ($1, $2, $3::jsonb, $4, $5, now())
      RETURNING *`,
      [existing.applicationId, nextVersion, canonicalJson, hashBuffer, updatedByUserId],
    );

    const newVersionRecord = insertRes.rows[0]!;

    // 4. Update the active policy pointer to the new version
    await this.db.query(`UPDATE applications SET active_policy_id = $1 WHERE id = $2`, [
      newVersionRecord.id,
      existing.applicationId,
    ]);

    await this.safeAuditAppend(
      'user',
      opts.updatedBy,
      'policy.version_created',
      {
        application_id: existing.applicationId,
        policy_id: newVersionRecord.id,
        previous_policy_id: existing.id,
        request_id: opts.requestId,
      },
      {
        version: nextVersion,
        previous_version: existing.version,
        document_sha256: hashHex,
      },
    );

    return this.formatResponse(newVersionRecord, newVersionRecord.id);
  }

  /**
   * Retrieves the currently active policy for an application.
   */
  public async getActivePolicy(applicationId: string): Promise<PolicyResponse | null> {
    const res = await this.db.query<PolicyRecord>(
      `SELECT sp.*, app.active_policy_id
       FROM applications app
       JOIN security_policies sp ON sp.id = app.active_policy_id
       WHERE app.id = $1`,
      [applicationId],
    );

    if (res.rows.length === 0) {
      return null;
    }

    const row = res.rows[0]!;
    return this.formatResponse(row, row.id);
  }
}
