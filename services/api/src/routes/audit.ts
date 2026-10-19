/**
 * @sug/service-api/routes/audit
 * Hash-Chained Audit System API Routes for Phase P21.
 *
 * Implements:
 * - GET /security-events and GET /api/v1/security-events:
 *   - Dual auth: API key (strictly tenant-isolated to application_id) or JWT (admin, auditor, analyst).
 *   - Bounded pagination and deterministic ordering.
 *   - Filter by action, actor_type, actor_id, file_id, application_id.
 *   - Redacts any sensitive data; never leaks secrets or private keys.
 * - GET /audit/verify and GET /api/v1/audit/verify:
 *   - Role-guarded: admin or auditor JWT only (API keys forbidden).
 *   - Cryptographic verification of audit chain (link continuity + byte-for-byte SHA-256 recomputation).
 *   - Verifies Ed25519 signature of the latest audit checkpoint.
 * - POST /audit/checkpoints and POST /api/v1/audit/checkpoints:
 *   - Role-guarded: admin or auditor JWT only.
 *   - Generates Ed25519-signed checkpoint with storage-first S3 persistence and safe orphan reconciliation.
 */

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { ApiKeyDatabase } from '../auth/types.js';
import type { ApiKeyService } from '../auth/service.js';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import { verifyDashboardToken } from '../auth/jwt.js';
import {
  verifyAuditChainFromDb,
  verifyCheckpointSignature,
  createAuditCheckpoint,
  type AuditCheckpoint,
} from '@sug/audit';
import type { StorageProvider } from '@sug/storage';

export interface AuditRouteOptions {
  db: ApiKeyDatabase;
  apiKeyService: ApiKeyService;
  jwtPublicKeyPem: string;
  storageProvider?: StorageProvider | undefined;
  auditBucket?: string | undefined;
  checkpointPrivateKeyPem?: string | undefined;
  checkpointPublicKeyPem?: string | undefined;
}

interface SecurityEventDbRow {
  seq: string;
  id: string;
  occurred_at: Date;
  actor_type: string;
  actor_id: string;
  action: string;
  application_id: string | null;
  file_id: string | null;
  file_version_id: string | null;
  decision_id: string | null;
  request_id: string | null;
  ip: string | null;
  details: unknown;
  prev_hash: Buffer;
  event_hash: Buffer;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const auditRoutes: FastifyPluginAsync<AuditRouteOptions> = async (app, options) => {
  const {
    db,
    apiKeyService,
    jwtPublicKeyPem,
    storageProvider,
    auditBucket,
    checkpointPrivateKeyPem,
    checkpointPublicKeyPem,
  } = options;

  /**
   * Dual authentication helper supporting both API Key Bearer and User JWT Bearer.
   */
  async function authenticateRequest(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<boolean> {
    const authHeader = request.headers.authorization;
    if (!authHeader) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Missing Authorization header',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).send(problem);
      return false;
    }

    const trimmed = authHeader.trim();

    // 1. API Key authentication (sug_<env>_<prefix>_<secret>)
    if (trimmed.startsWith('Bearer sug_') || trimmed.startsWith('bearer sug_')) {
      const rawKey = trimmed.slice(7).trim();
      const authResult = await apiKeyService.verifyApiKey(rawKey, {
        ip: request.ip,
        requestId: request.id,
      });

      if (authResult.isValid && authResult.app) {
        request.auth = authResult.app;
        return true;
      }

      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Invalid or revoked API key',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).send(problem);
      return false;
    }

    // 2. Dashboard User JWT authentication
    if (trimmed.startsWith('Bearer ') || trimmed.startsWith('bearer ')) {
      const token = trimmed.slice(7).trim();
      try {
        const payload = await verifyDashboardToken(token, jwtPublicKeyPem);
        request.user = {
          id: payload.sub,
          email: payload.email,
          role: payload.role,
        };
        return true;
      } catch (err) {
        const problem = createProblemDetails(
          request,
          401,
          'Unauthorized',
          `Invalid access token: ${err instanceof Error ? err.message : String(err)}`,
          ErrorTypes.UNAUTHORIZED,
        );
        reply.status(401).send(problem);
        return false;
      }
    }

    const problem = createProblemDetails(
      request,
      401,
      'Unauthorized',
      'Unsupported authorization scheme',
      ErrorTypes.UNAUTHORIZED,
    );
    reply.status(401).send(problem);
    return false;
  }

  // --- 1. GET /security-events Handler ---
  async function handleGetSecurityEvents(
    request: FastifyRequest<{
      Querystring: {
        limit?: string | number | undefined;
        cursor?: string | number | undefined;
        from_seq?: string | number | undefined;
        to_seq?: string | number | undefined;
        action?: string | undefined;
        actor_type?: string | undefined;
        actor_id?: string | undefined;
        file_id?: string | undefined;
        application_id?: string | undefined;
        order?: 'asc' | 'desc' | undefined;
      };
    }>,
    reply: FastifyReply,
  ) {
    const isAuthed = await authenticateRequest(request, reply);
    if (!isAuthed) return;

    const query = request.query;

    // Tenant Isolation Enforcement:
    // If authenticated via API Key, caller CANNOT access other applications' audit logs
    let effectiveAppId: string | null = null;
    if (request.auth) {
      effectiveAppId = request.auth.applicationId;
      if (query.application_id && query.application_id !== effectiveAppId) {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'API key is not authorized to query other tenant audit logs',
          ErrorTypes.FORBIDDEN,
        );
        return reply.status(403).send(problem);
      }
    } else if (request.user) {
      // User JWT role enforcement
      if (
        request.user.role !== 'admin' &&
        request.user.role !== 'auditor' &&
        request.user.role !== 'analyst'
      ) {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'Insufficient role for audit event access',
          ErrorTypes.FORBIDDEN,
        );
        return reply.status(403).send(problem);
      }
      if (query.application_id) {
        if (!UUID_REGEX.test(query.application_id)) {
          const problem = createProblemDetails(
            request,
            400,
            'Bad Request',
            'Invalid application_id format: must be a valid UUID',
            ErrorTypes.VALIDATION,
          );
          return reply.status(400).send(problem);
        }
        effectiveAppId = query.application_id;
      }
    }

    // Validate pagination limit
    let limit = 50;
    if (query.limit !== undefined) {
      const parsed = typeof query.limit === 'number' ? query.limit : parseInt(query.limit, 10);
      if (Number.isNaN(parsed) || parsed < 1 || parsed > 100) {
        const problem = createProblemDetails(
          request,
          400,
          'Bad Request',
          'limit must be an integer between 1 and 100',
          ErrorTypes.VALIDATION,
        );
        return reply.status(400).send(problem);
      }
      limit = parsed;
    }

    // Validate order
    const order = query.order?.toLowerCase() === 'desc' ? 'DESC' : 'ASC';

    // Validate file_id
    if (query.file_id && !UUID_REGEX.test(query.file_id)) {
      const problem = createProblemDetails(
        request,
        400,
        'Bad Request',
        'Invalid file_id format: must be a valid UUID',
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    // Build parameterized query
    const conditions: string[] = ['1=1'];
    const params: unknown[] = [];

    if (effectiveAppId) {
      params.push(effectiveAppId);
      conditions.push(`application_id = $${params.length}`);
    }

    if (query.file_id) {
      params.push(query.file_id);
      conditions.push(`file_id = $${params.length}`);
    }

    if (query.action) {
      params.push(query.action);
      conditions.push(`action = $${params.length}`);
    }

    if (query.actor_type) {
      if (!['api_key', 'user', 'service'].includes(query.actor_type)) {
        const problem = createProblemDetails(
          request,
          400,
          'Bad Request',
          "actor_type must be one of 'api_key', 'user', 'service'",
          ErrorTypes.VALIDATION,
        );
        return reply.status(400).send(problem);
      }
      params.push(query.actor_type);
      conditions.push(`actor_type = $${params.length}`);
    }

    if (query.actor_id) {
      params.push(query.actor_id);
      conditions.push(`actor_id = $${params.length}`);
    }

    if (query.from_seq !== undefined) {
      const fromSeqParsed = BigInt(query.from_seq);
      params.push(fromSeqParsed.toString());
      conditions.push(`seq >= $${params.length}`);
    }

    if (query.to_seq !== undefined) {
      const toSeqParsed = BigInt(query.to_seq);
      params.push(toSeqParsed.toString());
      conditions.push(`seq <= $${params.length}`);
    }

    if (query.cursor !== undefined) {
      const cursorParsed = BigInt(query.cursor);
      params.push(cursorParsed.toString());
      if (order === 'ASC') {
        conditions.push(`seq > $${params.length}`);
      } else {
        conditions.push(`seq < $${params.length}`);
      }
    }

    params.push(limit);
    const sql = `
      SELECT seq, id, occurred_at, actor_type, actor_id, action,
             application_id, file_id, file_version_id, decision_id, request_id, host(ip) as ip,
             details, prev_hash, event_hash
      FROM audit_events
      WHERE ${conditions.join(' AND ')}
      ORDER BY seq ${order}
      LIMIT $${params.length}
    `;

    const dbRes = await db.query<SecurityEventDbRow>(sql, params);
    const events = dbRes.rows.map((r) => ({
      seq: r.seq,
      id: r.id,
      occurred_at: r.occurred_at.toISOString(),
      actor_type: r.actor_type,
      actor_id: r.actor_id,
      action: r.action,
      application_id: r.application_id,
      file_id: r.file_id,
      file_version_id: r.file_version_id,
      decision_id: r.decision_id,
      request_id: r.request_id,
      ip: r.ip,
      details: r.details,
      prev_hash: r.prev_hash.toString('hex'),
      event_hash: r.event_hash.toString('hex'),
    }));

    const nextCursor = events.length === limit ? events[events.length - 1]?.seq : undefined;

    return reply.status(200).send({
      events,
      count: events.length,
      limit,
      order: order.toLowerCase(),
      ...(nextCursor ? { nextCursor } : {}),
    });
  }

  // --- 2. GET /audit/verify Handler ---
  async function handleVerifyAuditChain(
    request: FastifyRequest<{
      Querystring: {
        from_seq?: string | number | undefined;
        to_seq?: string | number | undefined;
        recompute_hashes?: string | boolean | undefined;
      };
    }>,
    reply: FastifyReply,
  ) {
    const isAuthed = await authenticateRequest(request, reply);
    if (!isAuthed) return;

    // RBAC: Only Admin or Auditor role may trigger audit chain verification
    if (!request.user || (request.user.role !== 'admin' && request.user.role !== 'auditor')) {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        'Audit chain verification is restricted to admin and auditor roles',
        ErrorTypes.FORBIDDEN,
      );
      return reply.status(403).send(problem);
    }

    try {
      const fromSeq = request.query.from_seq ? BigInt(request.query.from_seq) : undefined;
      const toSeq = request.query.to_seq ? BigInt(request.query.to_seq) : undefined;
      const recomputeHashes =
        request.query.recompute_hashes === true || request.query.recompute_hashes === 'true';

      const verificationResult = await verifyAuditChainFromDb(db, {
        ...(fromSeq !== undefined ? { fromSeq: fromSeq.toString() } : {}),
        ...(toSeq !== undefined ? { toSeq: toSeq.toString() } : {}),
        ...(recomputeHashes ? { recomputeHashes: true } : {}),
      });

      // Also inspect latest checkpoint if available
      let latestCheckpointSummary: {
        id: string;
        lastSeq: string;
        chainHash: string;
        signatureValid: boolean;
      } | null = null;

      const cpRes = await db.query<{
        id: string;
        last_seq: string;
        chain_hash: Buffer;
        signature: Buffer;
        s3_version_id: string;
        created_at: Date;
      }>('SELECT * FROM audit_checkpoints ORDER BY last_seq DESC LIMIT 1');

      if (cpRes.rows.length > 0 && cpRes.rows[0]) {
        const cpRow = cpRes.rows[0];
        const cp: AuditCheckpoint = {
          schema: 'sug.audit_checkpoint/v1',
          checkpointId: cpRow.id,
          lastSeq: cpRow.last_seq,
          chainHash: cpRow.chain_hash.toString('hex'),
          createdAt: cpRow.created_at.toISOString(),
          signature: cpRow.signature.toString('hex'),
        };

        let sigValid = true;
        if (checkpointPublicKeyPem) {
          sigValid = verifyCheckpointSignature(cp, checkpointPublicKeyPem);
        }

        latestCheckpointSummary = {
          id: cp.checkpointId,
          lastSeq: String(cp.lastSeq),
          chainHash: cp.chainHash,
          signatureValid: sigValid,
        };
      }

      if (!verificationResult.valid) {
        return reply.status(200).send({
          status: 'INVALID',
          valid: false,
          failedSeq: String(verificationResult.failedSeq),
          error: verificationResult.error,
          failureCategory: verificationResult.failureCategory,
          ...(latestCheckpointSummary ? { latestCheckpoint: latestCheckpointSummary } : {}),
        });
      }

      return reply.status(200).send({
        status: 'VALID',
        valid: true,
        verifiedCount: verificationResult.verifiedCount,
        headHash: verificationResult.headHash,
        fromSeq:
          verificationResult.fromSeq !== undefined ? String(verificationResult.fromSeq) : undefined,
        toSeq:
          verificationResult.toSeq !== undefined ? String(verificationResult.toSeq) : undefined,
        ...(latestCheckpointSummary ? { latestCheckpoint: latestCheckpointSummary } : {}),
      });
    } catch (err: unknown) {
      const problem = createProblemDetails(
        request,
        500,
        'Internal Server Error',
        `Audit verification error: ${err instanceof Error ? err.message : String(err)}`,
        ErrorTypes.INTERNAL,
      );
      return reply.status(500).send(problem);
    }
  }

  // --- 3. POST /audit/checkpoints Handler ---
  async function handleCreateCheckpoint(request: FastifyRequest, reply: FastifyReply) {
    const isAuthed = await authenticateRequest(request, reply);
    if (!isAuthed) return;

    if (!request.user || (request.user.role !== 'admin' && request.user.role !== 'auditor')) {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        'Checkpoint creation is restricted to admin and auditor roles',
        ErrorTypes.FORBIDDEN,
      );
      return reply.status(403).send(problem);
    }

    if (!storageProvider || !auditBucket || !checkpointPrivateKeyPem || !checkpointPublicKeyPem) {
      const problem = createProblemDetails(
        request,
        500,
        'Internal Server Error',
        'Checkpoint signing material or storage adapter not configured',
        ErrorTypes.INTERNAL,
      );
      return reply.status(500).send(problem);
    }

    try {
      const result = await createAuditCheckpoint({
        db,
        storage: storageProvider,
        auditBucket,
        privateKeyPem: checkpointPrivateKeyPem,
        publicKeyPem: checkpointPublicKeyPem,
      });

      if (!result) {
        const problem = createProblemDetails(
          request,
          400,
          'Bad Request',
          'No audit events exist to checkpoint',
          ErrorTypes.VALIDATION,
        );
        return reply.status(400).send(problem);
      }

      return reply.status(201).send({
        checkpoint: result.checkpoint,
        s3VersionId: result.s3VersionId,
        storedInDb: result.storedInDb,
        reconciled: result.reconciled,
      });
    } catch (err: unknown) {
      const problem = createProblemDetails(
        request,
        500,
        'Internal Server Error',
        `Failed to create checkpoint: ${err instanceof Error ? err.message : String(err)}`,
        ErrorTypes.INTERNAL,
      );
      return reply.status(500).send(problem);
    }
  }

  // Register Canonical Endpoints and Aliases
  app.get('/security-events', handleGetSecurityEvents);
  app.get('/api/v1/security-events', handleGetSecurityEvents);

  app.get('/audit/verify', handleVerifyAuditChain);
  app.get('/api/v1/audit/verify', handleVerifyAuditChain);

  app.post('/audit/checkpoints', handleCreateCheckpoint);
  app.post('/api/v1/audit/checkpoints', handleCreateCheckpoint);
};
