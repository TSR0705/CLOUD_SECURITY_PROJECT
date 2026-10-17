/**
 * @sug/service-api/routes/security-decisions
 * Security Decisions & Human Review API Route for P18.
 *
 * Implements:
 * - GET /api/v1/security-decisions/:id:
 *   - Dual auth: API key (tenant-isolated to application) or JWT (admin, analyst, auditor).
 *   - Returns explainable sug.decision/v1 record and bound artifact identity.
 * - POST /api/v1/security-decisions/:id/review:
 *   - Role-guarded: analyst or admin JWT only (API keys and auditors forbidden).
 *   - Enforces fail-closed workflow: ERROR decisions and failed required checks cannot be overridden to ALLOW.
 *   - Inserts superseding decision, updates file status, and records tamper-evident audit event.
 */

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { ApiKeyDatabase } from '../auth/types.js';
import type { ApiKeyService } from '../auth/service.js';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import { verifyDashboardToken } from '../auth/jwt.js';
import {
  evaluateReview,
  persistDecision,
  ReviewValidationError,
  type ExistingDecision,
  type ReviewAction,
  type DecisionPolicyInput,
} from '@sug/decision-engine';
import type { SecurityDecisions } from '@sug/shared';

export interface SecurityDecisionsRouteOptions {
  db: ApiKeyDatabase;
  apiKeyService: ApiKeyService;
  jwtPublicKeyPem: string;
}

interface DecisionDbRow extends ExistingDecision {
  readonly application_id: string;
  readonly file_id: string;
  readonly policy_document?: unknown;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const problemDetailsSchema = {
  type: 'object' as const,
  properties: {
    type: { type: 'string', example: 'urn:sug:error:validation' },
    title: { type: 'string', example: 'Validation Error' },
    status: { type: 'integer', example: 400 },
    detail: { type: 'string', example: 'Invalid parameter' },
    instance: {
      type: 'string',
      example: '/api/v1/security-decisions/018f3a5e-7a42-7000-8000-000000000001',
    },
    requestId: { type: 'string', example: '018f3a5e-7a42-7000-8000-000000000001' },
  },
  required: ['type', 'title', 'status', 'detail', 'instance', 'requestId'],
};

const decisionDetailResponseSchema = {
  type: 'object' as const,
  properties: {
    id: { type: 'string', format: 'uuid' },
    fileVersionId: { type: 'string', format: 'uuid' },
    scanJobId: { type: ['string', 'null'], format: 'uuid' },
    policyId: { type: 'string', format: 'uuid' },
    decision: {
      type: 'string',
      enum: ['ALLOW', 'BLOCK', 'QUARANTINE', 'ERROR'],
      example: 'ALLOW',
    },
    primaryReason: { type: 'string', example: 'CLEAN' },
    severity: {
      type: 'string',
      enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
      example: 'INFO',
    },
    confidence: {
      type: 'string',
      enum: ['CONFIRMED', 'HIGH', 'MEDIUM', 'LOW'],
      example: 'CONFIRMED',
    },
    riskScore: { type: 'integer', example: 0 },
    policyResult: { type: 'string', example: 'PASS' },
    scannerResult: { type: 'string', example: 'PASS' },
    integrityResult: { type: 'string', example: 'PASS' },
    authorizationResult: { type: 'string', example: 'PASS' },
    boundBucket: { type: 'string', example: 'sug-quarantine' },
    boundKey: { type: 'string', example: 'incoming/app/file' },
    boundStorageVersionId: { type: 'string', example: 'v12345' },
    boundSha256: {
      type: 'string',
      example: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    boundSize: { type: 'integer', example: 1024 },
    record: { type: 'object', additionalProperties: true },
    engineVersion: { type: 'string', example: '1.0.0' },
    decidedBy: { type: 'string', example: 'engine' },
    supersedesId: { type: ['string', 'null'], format: 'uuid' },
    createdAt: { type: 'string', format: 'date-time' },
  },
  required: [
    'id',
    'fileVersionId',
    'policyId',
    'decision',
    'primaryReason',
    'severity',
    'confidence',
    'riskScore',
    'policyResult',
    'scannerResult',
    'integrityResult',
    'authorizationResult',
    'boundBucket',
    'boundKey',
    'boundStorageVersionId',
    'boundSha256',
    'boundSize',
    'record',
    'engineVersion',
    'decidedBy',
    'createdAt',
  ],
};

const reviewRequestBodySchema = {
  type: 'object' as const,
  properties: {
    action: {
      type: 'string',
      enum: ['ALLOW', 'BLOCK'],
      description: 'Review decision outcome',
    },
    justification: {
      type: 'string',
      minLength: 10,
      description: 'Detailed rationale for human override',
    },
  },
  required: ['action', 'justification'],
  additionalProperties: false,
};

export const securityDecisionsRoutes: FastifyPluginAsync<SecurityDecisionsRouteOptions> = async (
  app,
  options,
) => {
  const { db, apiKeyService, jwtPublicKeyPem } = options;

  async function authenticateCaller(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<boolean> {
    const authHeader = request.headers.authorization;
    if (!authHeader) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authorization header missing',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).send(problem);
      return false;
    }

    const trimmed = authHeader.trim();

    // 1. Try P6 API Key authentication
    if (
      trimmed.startsWith('sug_') ||
      trimmed.startsWith('Bearer sug_') ||
      trimmed.startsWith('bearer sug_')
    ) {
      const rawKey = trimmed.replace(/^Bearer\s+/i, '').trim();
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

    // 2. Try User JWT authentication
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

  // Helper to format DB decision row into API JSON format
  function formatDecisionRow(row: DecisionDbRow | ExistingDecision | SecurityDecisions) {
    const shaHex = Buffer.isBuffer(row.bound_sha256)
      ? row.bound_sha256.toString('hex')
      : String(row.bound_sha256);

    return {
      id: String(row.id),
      fileVersionId: row.file_version_id,
      scanJobId: row.scan_job_id,
      policyId: row.policy_id,
      decision: row.decision,
      primaryReason: row.primary_reason,
      severity: row.severity,
      confidence: row.confidence,
      riskScore: row.risk_score,
      policyResult: row.policy_result,
      scannerResult: row.scanner_result,
      integrityResult: row.integrity_result,
      authorizationResult: row.authorization_result,
      boundBucket: row.bound_bucket,
      boundKey: row.bound_key,
      boundStorageVersionId: row.bound_storage_version_id,
      boundSha256: shaHex,
      boundSize: Number(row.bound_size),
      record: row.record,
      engineVersion: row.engine_version,
      decidedBy: row.decided_by,
      supersedesId: row.supersedes_id,
      createdAt:
        row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
    };
  }

  // =========================================================================
  // GET /api/v1/security-decisions/:id
  // =========================================================================
  const getDecisionHandler = async (
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply,
  ) => {
    const authenticated = await authenticateCaller(request, reply);
    if (!authenticated) return;

    const { id } = request.params;

    if (!id || !UUID_REGEX.test(id)) {
      const problem = createProblemDetails(
        request,
        400,
        'Validation Error',
        'Invalid security decision ID format; must be a valid UUID',
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    const queryRes = await db.query<DecisionDbRow>(
      `SELECT sd.*,
              f.application_id,
              f.id AS file_id
       FROM security_decisions sd
       JOIN file_versions fv ON fv.id = sd.file_version_id
       JOIN files f ON f.id = fv.file_id
       WHERE sd.id = $1`,
      [id],
    );

    if (queryRes.rows.length === 0) {
      const problem = createProblemDetails(
        request,
        404,
        'Not Found',
        `Security decision with ID '${id}' not found`,
        ErrorTypes.NOT_FOUND,
      );
      return reply.status(404).send(problem);
    }

    const row = queryRes.rows[0]!;

    // Tenant application ownership check
    if (request.auth) {
      if (request.auth.applicationId !== row.application_id) {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'Access to security decision denied for this application',
          ErrorTypes.FORBIDDEN,
        );
        return reply.status(403).send(problem);
      }
    } else if (request.user) {
      const role = request.user.role;
      if (role !== 'admin' && role !== 'analyst' && role !== 'auditor') {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'Insufficient role permissions to access security decision',
          ErrorTypes.FORBIDDEN,
        );
        return reply.status(403).send(problem);
      }
    }

    return reply.status(200).send(formatDecisionRow(row));
  };

  const getDecisionSchema = {
    schema: {
      tags: ['Decisions'],
      summary: 'Get security decision details',
      description:
        'Retrieves the deterministic security decision, explainable sug.decision/v1 record, and bound artifact identity. Requires API key or authenticated dashboard user, enforcing tenant isolation.',
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid', description: 'Decision UUID' },
        },
        required: ['id'],
      },
      response: {
        200: decisionDetailResponseSchema,
        400: problemDetailsSchema,
        401: problemDetailsSchema,
        403: problemDetailsSchema,
        404: problemDetailsSchema,
      },
    },
  };

  app.get<{ Params: { id: string } }>(
    '/api/v1/security-decisions/:id',
    getDecisionSchema,
    getDecisionHandler,
  );

  app.get<{ Params: { id: string } }>(
    '/security-decisions/:id',
    getDecisionSchema,
    getDecisionHandler,
  );

  // =========================================================================
  // POST /api/v1/security-decisions/:id/review
  // =========================================================================
  const postReviewHandler = async (
    request: FastifyRequest<{
      Params: { id: string };
      Body: { action: ReviewAction; justification: string };
    }>,
    reply: FastifyReply,
  ) => {
    const authenticated = await authenticateCaller(request, reply);
    if (!authenticated) return;

    // RBAC: Only analysts and admins can perform human review!
    if (request.auth) {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        'Human review requires an authenticated analyst or admin user token; API keys are not permitted',
        ErrorTypes.FORBIDDEN,
      );
      return reply.status(403).send(problem);
    }

    if (!request.user || (request.user.role !== 'admin' && request.user.role !== 'analyst')) {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        'Insufficient role permissions for human review; role must be admin or analyst',
        ErrorTypes.FORBIDDEN,
      );
      return reply.status(403).send(problem);
    }

    const { id } = request.params;
    if (!id || !UUID_REGEX.test(id)) {
      const problem = createProblemDetails(
        request,
        400,
        'Validation Error',
        'Invalid security decision ID format; must be a valid UUID',
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    const body = request.body;
    if (!body || typeof body !== 'object') {
      const problem = createProblemDetails(
        request,
        400,
        'Validation Error',
        'Missing request body',
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    const { action, justification } = body;

    // Query target decision with associated file and policy metadata
    const queryRes = await db.query<DecisionDbRow>(
      `SELECT sd.*,
              f.application_id,
              f.id AS file_id,
              sp.document AS policy_document
       FROM security_decisions sd
       JOIN file_versions fv ON fv.id = sd.file_version_id
       JOIN files f ON f.id = fv.file_id
       LEFT JOIN security_policies sp ON sp.id = sd.policy_id
       WHERE sd.id = $1`,
      [id],
    );

    if (queryRes.rows.length === 0) {
      const problem = createProblemDetails(
        request,
        404,
        'Not Found',
        `Security decision with ID '${id}' not found`,
        ErrorTypes.NOT_FOUND,
      );
      return reply.status(404).send(problem);
    }

    const targetRow = queryRes.rows[0]!;
    const fileId = targetRow.file_id;
    const policyDoc = targetRow.policy_document as DecisionPolicyInput | undefined;

    let reviewResult;
    try {
      reviewResult = evaluateReview(
        targetRow,
        {
          action,
          justification,
          reviewer: request.user.email,
          reviewerId: request.user.id,
        },
        policyDoc,
      );
    } catch (err) {
      if (err instanceof ReviewValidationError) {
        const problem = createProblemDetails(
          request,
          err.statusCode,
          'Review Validation Error',
          err.message,
          ErrorTypes.VALIDATION,
        );
        return reply.status(err.statusCode).send(problem);
      }
      throw err;
    }

    // Persist superseding decision, update file status, and append audit log atomically
    const newDecisionRow = await persistDecision(db, reviewResult, {
      fileVersionId: targetRow.file_version_id,
      policyId: targetRow.policy_id,
      scanJobId: targetRow.scan_job_id,
      supersedesId: targetRow.id,
    });

    const newFileStatus = action === 'ALLOW' ? 'SCANNED' : 'BLOCKED';
    await db.query(`UPDATE files SET status = $1 WHERE id = $2`, [newFileStatus, fileId]);

    // Tamper-evident audit event
    await db.query(
      `SELECT audit_append(
        'decision.reviewed',
        'user',
        $1,
        $2::jsonb,
        $3::jsonb
      )`,
      [
        request.user.id,
        JSON.stringify({
          application_id: targetRow.application_id,
          file_id: fileId,
          decision_id: newDecisionRow.id,
        }),
        JSON.stringify({
          priorDecisionId: targetRow.id,
          priorDecision: targetRow.decision,
          newDecision: action,
          justification,
          reviewer: request.user.email,
        }),
      ],
    );

    return reply.status(201).send(formatDecisionRow(newDecisionRow));
  };

  const postReviewSchema = {
    schema: {
      tags: ['Decisions'],
      summary: 'Perform human review on a security decision',
      description:
        'Allows an authorized analyst or admin to review a quarantined decision and emit a superseding ALLOW or BLOCK decision with audit justification. Rejects attempts to override ERROR decisions.',
      params: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid', description: 'Decision UUID to review' },
        },
        required: ['id'],
      },
      body: reviewRequestBodySchema,
      response: {
        201: decisionDetailResponseSchema,
        400: problemDetailsSchema,
        401: problemDetailsSchema,
        403: problemDetailsSchema,
        404: problemDetailsSchema,
      },
    },
  };

  app.post<{
    Params: { id: string };
    Body: { action: ReviewAction; justification: string };
  }>('/api/v1/security-decisions/:id/review', postReviewSchema, postReviewHandler);

  app.post<{
    Params: { id: string };
    Body: { action: ReviewAction; justification: string };
  }>('/security-decisions/:id/review', postReviewSchema, postReviewHandler);
};
