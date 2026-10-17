/**
 * @sug/service-api/routes/scans
 * Scan Findings & Status API Route for P17.
 *
 * Implements GET /api/v1/scans/:id:
 * - Dual authentication: P6 API keys or P7 Dashboard JWTs.
 * - Strict tenant application isolation (403/404 for cross-tenant access).
 * - Deterministic finding order by check_id ASC.
 * - OpenAPI / RFC 7807/9457 compliant error handling.
 */

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { ApiKeyDatabase } from '../auth/types.js';
import type { ApiKeyService } from '../auth/service.js';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import { verifyDashboardToken } from '../auth/jwt.js';

export interface ScansRouteOptions {
  db: ApiKeyDatabase;
  apiKeyService: ApiKeyService;
  jwtPublicKeyPem: string;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const problemDetailsSchema = {
  type: 'object' as const,
  properties: {
    type: { type: 'string', example: 'urn:sug:error:validation' },
    title: { type: 'string', example: 'Validation Error' },
    status: { type: 'integer', example: 400 },
    detail: { type: 'string', example: 'Invalid parameter' },
    instance: { type: 'string', example: '/api/v1/scans/018f3a5e-7a42-7000-8000-000000000001' },
    requestId: { type: 'string', example: '018f3a5e-7a42-7000-8000-000000000001' },
  },
  required: ['type', 'title', 'status', 'detail', 'instance', 'requestId'],
};

const scanDetailResponseSchema = {
  type: 'object' as const,
  properties: {
    id: { type: 'string', format: 'uuid' },
    status: {
      type: 'string',
      enum: ['QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'DEAD'],
      example: 'SUCCEEDED',
    },
    fileVersionId: { type: 'string', format: 'uuid' },
    createdAt: { type: 'string', format: 'date-time' },
    finishedAt: { type: ['string', 'null'], format: 'date-time' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          checkId: { type: 'string', example: 'scanner.clamav' },
          engine: { type: 'string', example: 'clamav' },
          engineVersion: { type: ['string', 'null'], example: '1.4.6' },
          signatureVersion: { type: ['string', 'null'], example: '27200' },
          outcome: {
            type: 'string',
            enum: ['PASS', 'FAIL', 'SUSPICIOUS', 'ERROR', 'SKIPPED'],
            example: 'PASS',
          },
          reasonCode: { type: 'string', example: 'CLEAN' },
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
          evidence: { type: 'object', additionalProperties: true },
          scannedStorageVersionId: { type: 'string', example: '12345' },
          scannedSha256: {
            type: 'string',
            example: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          },
          scannedSize: { type: 'number', example: 1024 },
          durationMs: { type: ['number', 'null'], example: 45 },
          createdAt: { type: 'string', format: 'date-time' },
        },
        required: [
          'id',
          'checkId',
          'engine',
          'outcome',
          'reasonCode',
          'severity',
          'confidence',
          'evidence',
          'scannedStorageVersionId',
          'scannedSha256',
          'scannedSize',
          'createdAt',
        ],
      },
    },
  },
  required: ['id', 'status', 'fileVersionId', 'createdAt', 'finishedAt', 'findings'],
};

export const scansRoutes: FastifyPluginAsync<ScansRouteOptions> = async (app, options) => {
  const { db, apiKeyService, jwtPublicKeyPem } = options;

  /**
   * Dual authenticator supporting either P6 API keys or P7 Dashboard JWTs.
   */
  async function authenticateCaller(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<boolean> {
    const authHeader = request.headers.authorization;
    if (!authHeader || typeof authHeader !== 'string') {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authentication required (API key or dashboard user token)',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).send(problem);
      return false;
    }

    const trimmed = authHeader.trim();

    // 1. Try API Key authentication
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

  app.get<{ Params: { id: string } }>(
    '/api/v1/scans/:id',
    {
      schema: {
        tags: ['Scans'],
        summary: 'Get scan job status and security findings',
        description:
          'Retrieves the status, identity binding, and deterministic security findings for a scan job. Requires API key or authenticated user token, and enforces tenant application isolation.',
        params: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid', description: 'Scan Job UUID' },
          },
          required: ['id'],
        },
        response: {
          200: scanDetailResponseSchema,
          400: problemDetailsSchema,
          401: problemDetailsSchema,
          403: problemDetailsSchema,
          404: problemDetailsSchema,
        },
      },
    },
    async (request, reply) => {
      // 1. Authenticate caller
      const authenticated = await authenticateCaller(request, reply);
      if (!authenticated) return;

      const { id } = request.params;

      // 2. Validate UUID format
      if (!id || !UUID_REGEX.test(id)) {
        const problem = createProblemDetails(
          request,
          400,
          'Validation Error',
          'Invalid scan ID format; must be a valid UUID',
          ErrorTypes.VALIDATION,
        );
        return reply.status(400).send(problem);
      }

      // 3. Query scan job with ownership metadata
      const jobQuery = await db.query<{
        scan_job_id: string;
        scan_status: 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'DEAD';
        created_at: Date | string;
        finished_at: Date | string | null;
        file_version_id: string;
        application_id: string;
      }>(
        `SELECT sj.id AS scan_job_id,
                sj.status AS scan_status,
                sj.created_at,
                sj.finished_at,
                fv.id AS file_version_id,
                f.application_id
         FROM scan_jobs sj
         JOIN file_versions fv ON fv.id = sj.file_version_id
         JOIN files f ON f.id = fv.file_id
         WHERE sj.id = $1`,
        [id],
      );

      if (jobQuery.rows.length === 0) {
        const problem = createProblemDetails(
          request,
          404,
          'Not Found',
          `Scan job with ID '${id}' not found`,
          ErrorTypes.NOT_FOUND,
        );
        return reply.status(404).send(problem);
      }

      const jobRow = jobQuery.rows[0]!;

      // 4. Verify tenant application ownership
      if (request.auth) {
        // API key caller: must match application_id
        if (request.auth.applicationId !== jobRow.application_id) {
          const problem = createProblemDetails(
            request,
            403,
            'Forbidden',
            'Access to scan job denied for this application',
            ErrorTypes.FORBIDDEN,
          );
          return reply.status(403).send(problem);
        }
      } else if (request.user) {
        // User JWT caller: allowed roles
        const userRole = request.user.role;
        if (userRole !== 'admin' && userRole !== 'auditor' && userRole !== 'analyst') {
          const problem = createProblemDetails(
            request,
            403,
            'Forbidden',
            'Insufficient role permissions to access scan job',
            ErrorTypes.FORBIDDEN,
          );
          return reply.status(403).send(problem);
        }
      }

      // 5. Query scan findings, ordered deterministically by check_id ASC
      const resultsQuery = await db.query<{
        id: string;
        check_id: string;
        engine: string;
        engine_version: string | null;
        signature_version: string | null;
        outcome: 'PASS' | 'FAIL' | 'SUSPICIOUS' | 'ERROR' | 'SKIPPED';
        reason_code: string;
        severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
        confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
        evidence: Record<string, unknown>;
        scanned_storage_version_id: string;
        scanned_sha256: Buffer;
        scanned_size: string | number;
        duration_ms: number | null;
        created_at: Date | string;
      }>(
        `SELECT id, check_id, engine, engine_version, signature_version,
                outcome, reason_code, severity, confidence, evidence,
                scanned_storage_version_id, scanned_sha256, scanned_size,
                duration_ms, created_at
         FROM scan_results
         WHERE scan_job_id = $1
         ORDER BY check_id ASC`,
        [id],
      );

      const findings = resultsQuery.rows.map((row) => ({
        id: row.id,
        checkId: row.check_id,
        engine: row.engine,
        engineVersion: row.engine_version,
        signatureVersion: row.signature_version,
        outcome: row.outcome,
        reasonCode: row.reason_code,
        severity: row.severity,
        confidence: row.confidence,
        evidence: typeof row.evidence === 'string' ? JSON.parse(row.evidence) : row.evidence,
        scannedStorageVersionId: row.scanned_storage_version_id,
        scannedSha256: Buffer.isBuffer(row.scanned_sha256)
          ? row.scanned_sha256.toString('hex')
          : String(row.scanned_sha256),
        scannedSize: Number(row.scanned_size),
        durationMs: row.duration_ms,
        createdAt:
          row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
      }));

      const createdAtStr =
        jobRow.created_at instanceof Date
          ? jobRow.created_at.toISOString()
          : String(jobRow.created_at);
      const finishedAtStr = jobRow.finished_at
        ? jobRow.finished_at instanceof Date
          ? jobRow.finished_at.toISOString()
          : String(jobRow.finished_at)
        : null;

      return reply.status(200).send({
        id: jobRow.scan_job_id,
        status: jobRow.scan_status,
        fileVersionId: jobRow.file_version_id,
        createdAt: createdAtStr,
        finishedAt: finishedAtStr,
        findings,
      });
    },
  );
};
