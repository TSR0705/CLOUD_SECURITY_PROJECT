/**
 * @sug/test/integration/api/security-decisions
 * Integration test suite for Security Decisions & Human Review API endpoints (Phase P18).
 *
 * Implements:
 * - GET /api/v1/security-decisions/:id
 * - POST /api/v1/security-decisions/:id/review
 *
 * Verifies:
 * - Dual auth (API key vs Dashboard user JWT)
 * - Strict tenant application isolation (Application B cannot view Application A's decisions)
 * - Role-based access control (Auditor is read-only; Analyst & Admin can review; API keys forbidden from review)
 * - Fail-closed review validation:
 *   - Justification >= 10 characters required
 *   - Cannot override ERROR to ALLOW
 *   - Cannot override critical threat BLOCK to ALLOW
 *   - Creates superseding decision and audit event
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import type { FastifyInstance } from 'fastify';
import { createApp } from '../../../services/api/src/app.js';
import type { ApiKeyService } from '../../../services/api/src/auth/service.js';
import type { ApiKeyDatabase } from '../../../services/api/src/auth/types.js';
import { createDashboardToken } from '../../../services/api/src/auth/jwt.js';
import type { Config } from '@sug/shared/config';

describe('API Integration — Security Decisions & Human Review Endpoints (Phase P18)', () => {
  const TEST_PEPPER = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const JWT_KEY_PAIR = crypto.generateKeyPairSync('ed25519');
  const jwtPrivateKeyPem = JWT_KEY_PAIR.privateKey
    .export({ type: 'pkcs8', format: 'pem' })
    .toString();

  const appIdA = '018f3a5e-7a42-7000-8000-000000000001';
  const appIdB = '018f3a5e-7a42-7000-8000-000000000002';
  const validKeyA = 'sug_a1b2c3d4_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const validKeyB = 'sug_b1b2c3d4_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  const decisionIdA = '018f3a5e-7a42-7000-8000-000000000010';
  const fileVersionIdA = '018f3a5e-7a42-7000-8000-000000000020';
  const fileIdA = '018f3a5e-7a42-7000-8000-000000000030';
  const policyIdA = '018f3a5e-7a42-7000-8000-000000000040';
  const dummySha = crypto.createHash('sha256').update('test-content-a').digest('hex');

  let app: FastifyInstance;
  let mockDbRows: Record<string, Record<string, unknown>>;
  let auditLogs: unknown[] = [];
  let fileUpdates: unknown[] = [];

  const mockConfig = {
    nodeEnv: 'test',
    logLevel: 'silent',
    port: 3000,
    host: '0.0.0.0',
    serviceName: 'sug-api',
    database: {
      url: 'postgres://sug_admin:dummy@127.0.0.1:5432/sug',
      host: '127.0.0.1',
      port: 5432,
      user: 'sug_admin',
      name: 'sug',
    },
    storage: {
      s3: {
        endpoint: 'http://localhost:4566',
        region: 'us-east-1',
        quarantineBucket: 'sug-quarantine-local',
        cleanBucket: 'sug-clean-local',
        accessKeyId: 'test',
      },
      gcs: {
        endpoint: 'http://localhost:4443',
        replicaBucket: 'sug-replica-local',
        projectId: 'sug-local-project',
      },
      services: {
        api: { accessKeyId: 'test' },
        scanner: { accessKeyId: 'test' },
        promoter: { accessKeyId: 'test' },
        replicator: { accessKeyId: 'test' },
      },
    },
    secrets: {
      pepper: TEST_PEPPER,
      kek: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      jwtPrivateKey: jwtPrivateKeyPem,
      checkpointPrivateKey: 'dummy',
    },
    toRedacted: () => ({}) as unknown as ReturnType<Config['toRedacted']>,
    toJSON: () => ({}),
  } as unknown as Config;

  beforeEach(async () => {
    auditLogs = [];
    fileUpdates = [];

    mockDbRows = {
      [decisionIdA]: {
        id: decisionIdA,
        file_version_id: fileVersionIdA,
        scan_job_id: null,
        policy_id: policyIdA,
        decision: 'QUARANTINE',
        primary_reason: 'DETECTOR_DISAGREEMENT',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        risk_score: 30,
        policy_result: 'PASS',
        scanner_result: 'WARN',
        integrity_result: 'PASS',
        authorization_result: 'PASS',
        bound_bucket: 'sug-quarantine-local',
        bound_key: 'quarantine/app-a/file-a',
        bound_storage_version_id: 'v-101',
        bound_sha256: Buffer.from(dummySha, 'hex'),
        bound_size: 1024,
        record: {
          schema: 'sug.decision/v1',
          decision: 'QUARANTINE',
          rule: 'R4',
          primaryReason: 'DETECTOR_DISAGREEMENT',
          severity: 'MEDIUM',
          confidence: 'HIGH',
          riskScore: 30,
          riskThreshold: 50,
          policy: { id: policyIdA, name: 'default', version: 1, sha256: dummySha },
          artifactIdentity: {
            bucket: 'sug-quarantine-local',
            objectKey: 'quarantine/app-a/file-a',
            versionId: 'v-101',
            sha256: dummySha,
            sizeBytes: 1024,
          },
          resultsSummary: {
            policyResult: 'PASS',
            scannerResult: 'WARN',
            integrityResult: 'PASS',
            authorizationResult: 'PASS',
          },
          reasons: ['DETECTOR_DISAGREEMENT'],
          findingReferences: [],
          ruleTrace: ['R4: TRIGGERED (DETECTOR_DISAGREEMENT)'],
          engineVersion: '1.0.0',
          decidedAt: new Date().toISOString(),
          decidedBy: 'engine',
        },
        engine_version: '1.0.0',
        decided_by: 'engine',
        supersedes_id: null,
        created_at: new Date(),
        application_id: appIdA,
        file_id: fileIdA,
        policy_document: {
          id: policyIdA,
          name: 'default',
          version: 1,
          sha256: dummySha,
          manualReviewThreshold: 25,
        },
      },
    };

    const mockDb = {
      query: vi.fn().mockImplementation(async (sql: string, params: unknown[] = []) => {
        // Query decision by ID
        if (sql.includes('FROM security_decisions sd')) {
          const id = params[0] as string;
          const row = mockDbRows[id];
          return { rows: row ? [row] : [] };
        }

        // Insert new superseding decision
        if (sql.includes('INSERT INTO security_decisions')) {
          const newId = crypto.randomUUID();
          const insertedRow = {
            id: newId,
            file_version_id: params[0],
            scan_job_id: params[1],
            policy_id: params[2],
            decision: params[3],
            primary_reason: params[4],
            severity: params[5],
            confidence: params[6],
            risk_score: params[7],
            policy_result: params[8],
            scanner_result: params[9],
            integrity_result: params[10],
            authorization_result: params[11],
            bound_bucket: params[12],
            bound_key: params[13],
            bound_storage_version_id: params[14],
            bound_sha256: params[15],
            bound_size: params[16],
            record: JSON.parse(params[17]),
            engine_version: params[18],
            decided_by: params[19],
            supersedes_id: params[20],
            created_at: new Date(),
          };
          mockDbRows[newId] = {
            ...insertedRow,
            application_id: appIdA,
            file_id: fileIdA,
          };
          return { rows: [insertedRow] };
        }

        // Update file status
        if (sql.includes('UPDATE files SET status')) {
          fileUpdates.push({ status: params[0], fileId: params[1] });
          return { rowCount: 1 };
        }

        // Append audit event
        if (sql.includes('audit_append')) {
          auditLogs.push(params);
          return { rowCount: 1 };
        }

        return { rows: [] };
      }),
    };

    const mockApiKeyService = {
      verifyApiKey: vi.fn().mockImplementation(async (rawKey: string) => {
        if (rawKey === validKeyA) {
          return {
            isValid: true,
            app: {
              applicationId: appIdA,
              name: 'App A',
              scopes: ['upload', 'read'],
            },
          };
        }
        if (rawKey === validKeyB) {
          return {
            isValid: true,
            app: {
              applicationId: appIdB,
              name: 'App B',
              scopes: ['upload', 'read'],
            },
          };
        }
        return { isValid: false, reason: 'INVALID_KEY' };
      }),
    };

    app = await createApp({
      config: mockConfig,
      db: { checkReachability: async () => {} },
      storage: { checkReachability: async () => {} },
      authDb: mockDb as unknown as ApiKeyDatabase,
      apiKeyService: mockApiKeyService as unknown as ApiKeyService,
    });
  });

  afterEach(async () => {
    if (app) {
      await app.close();
    }
  });

  describe('GET /api/v1/security-decisions/:id', () => {
    it('rejects unauthenticated requests with 401 Problem Details', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/security-decisions/${decisionIdA}`,
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:unauthorized');
      expect(body.title).toBe('Unauthorized');
    });

    it('rejects invalid UUID parameter with 400 Problem Details', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/security-decisions/not-a-valid-uuid',
        headers: { authorization: `Bearer ${validKeyA}` },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:validation');
      expect(body.detail.toLowerCase()).toContain('uuid');
    });

    it('returns 404 Problem Details when decision does not exist', async () => {
      const nonExistentId = crypto.randomUUID();
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/security-decisions/${nonExistentId}`,
        headers: { authorization: `Bearer ${validKeyA}` },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:not-found');
    });

    it('enforces tenant application boundary (returns 403 when App B accesses App A decision)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/security-decisions/${decisionIdA}`,
        headers: { authorization: `Bearer ${validKeyB}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:forbidden');
      expect(body.detail).toContain('denied for this application');
    });

    it('returns 200 with complete decision details for authorized API key matching application', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/security-decisions/${decisionIdA}`,
        headers: { authorization: `Bearer ${validKeyA}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.id).toBe(decisionIdA);
      expect(body.decision).toBe('QUARANTINE');
      expect(body.primaryReason).toBe('DETECTOR_DISAGREEMENT');
      expect(body.riskScore).toBe(30);
      expect(body.boundSha256).toBe(dummySha);
      expect(body.record.schema).toBe('sug.decision/v1');
    });

    it('allows access to authorized user JWT (auditor role)', async () => {
      const auditorToken = await createDashboardToken(
        {
          id: crypto.randomUUID(),
          email: 'auditor@company.internal',
          role: 'auditor',
        },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/security-decisions/${decisionIdA}`,
        headers: { authorization: `Bearer ${auditorToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.id).toBe(decisionIdA);
      expect(body.decision).toBe('QUARANTINE');
    });
  });

  describe('POST /api/v1/security-decisions/:id/review', () => {
    it('rejects API key callers with 403 Forbidden (human review requires user token)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/security-decisions/${decisionIdA}/review`,
        headers: { authorization: `Bearer ${validKeyA}` },
        payload: {
          action: 'ALLOW',
          justification: 'Attempting to review with API key credentials',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:forbidden');
      expect(body.detail).toContain('API keys are not permitted');
    });

    it('rejects auditor user role with 403 Forbidden (requires analyst or admin)', async () => {
      const auditorToken = await createDashboardToken(
        {
          id: crypto.randomUUID(),
          email: 'auditor@company.internal',
          role: 'auditor',
        },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/security-decisions/${decisionIdA}/review`,
        headers: { authorization: `Bearer ${auditorToken}` },
        payload: {
          action: 'ALLOW',
          justification: 'Auditor attempting to approve upload',
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:forbidden');
      expect(body.detail).toContain('must be admin or analyst');
    });

    it('rejects short justifications (< 10 chars) with 400 Problem Details', async () => {
      const analystToken = await createDashboardToken(
        {
          id: crypto.randomUUID(),
          email: 'analyst@company.internal',
          role: 'analyst',
        },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/security-decisions/${decisionIdA}/review`,
        headers: { authorization: `Bearer ${analystToken}` },
        payload: {
          action: 'ALLOW',
          justification: 'Too short',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:validation');
    });

    it('FAIL-CLOSED: Rejects attempting to override ERROR decision to ALLOW', async () => {
      const errorDecisionId = crypto.randomUUID();
      mockDbRows[errorDecisionId] = {
        ...mockDbRows[decisionIdA],
        id: errorDecisionId,
        decision: 'ERROR',
        primary_reason: 'REQUIRED_CHECK_MISSING',
        severity: 'HIGH',
      };

      const analystToken = await createDashboardToken(
        {
          id: crypto.randomUUID(),
          email: 'analyst@company.internal',
          role: 'analyst',
        },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/security-decisions/${errorDecisionId}/review`,
        headers: { authorization: `Bearer ${analystToken}` },
        payload: {
          action: 'ALLOW',
          justification: 'Attempting to override scanner failure to allow',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.detail).toContain('Cannot override ERROR decision');
    });

    it('FAIL-CLOSED: Rejects attempting to override critical threat BLOCK to ALLOW', async () => {
      const malwareDecisionId = crypto.randomUUID();
      mockDbRows[malwareDecisionId] = {
        ...mockDbRows[decisionIdA],
        id: malwareDecisionId,
        decision: 'BLOCK',
        primary_reason: 'MALWARE_DETECTED',
        severity: 'CRITICAL',
      };

      const analystToken = await createDashboardToken(
        {
          id: crypto.randomUUID(),
          email: 'analyst@company.internal',
          role: 'analyst',
        },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/security-decisions/${malwareDecisionId}/review`,
        headers: { authorization: `Bearer ${analystToken}` },
        payload: {
          action: 'ALLOW',
          justification: 'Attempting to allow confirmed malware file',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.detail).toContain('Cannot override critical threat BLOCK decision');
    });

    it('succeeds when analyst overrides QUARANTINE to ALLOW with valid justification', async () => {
      const analystId = crypto.randomUUID();
      const analystToken = await createDashboardToken(
        {
          id: analystId,
          email: 'analyst@company.internal',
          role: 'analyst',
        },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/security-decisions/${decisionIdA}/review`,
        headers: { authorization: `Bearer ${analystToken}` },
        payload: {
          action: 'ALLOW',
          justification: 'Verified as false positive active content after inspection',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.decision).toBe('ALLOW');
      expect(body.primaryReason).toBe('HUMAN_REVIEW_ALLOW');
      expect(body.supersedesId).toBe(decisionIdA);

      // Verify file status was updated to SCANNED
      expect(fileUpdates).toHaveLength(1);
      expect(fileUpdates[0]!.status).toBe('SCANNED');

      // Verify tamper-evident audit log was appended
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0]![0]).toBe(analystId);
    });

    it('succeeds when admin overrides QUARANTINE to BLOCK with valid justification', async () => {
      const adminId = crypto.randomUUID();
      const adminToken = await createDashboardToken(
        {
          id: adminId,
          email: 'admin@company.internal',
          role: 'admin',
        },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/security-decisions/${decisionIdA}/review`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: {
          action: 'BLOCK',
          justification: 'Confirmed policy violation upon manual analysis',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.decision).toBe('BLOCK');
      expect(body.primaryReason).toBe('HUMAN_REVIEW_BLOCK');
      expect(body.supersedesId).toBe(decisionIdA);

      // Verify file status was updated to BLOCKED
      expect(fileUpdates).toHaveLength(1);
      expect(fileUpdates[0]!.status).toBe('BLOCKED');
    });
  });
});
