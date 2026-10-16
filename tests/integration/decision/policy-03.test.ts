/**
 * @sug/test/integration/decision/policy-03
 * Canonical End-to-End Decision & Human Review Integration Test (policy-03).
 *
 * Tests the complete lifecycle:
 * 1. Policy specification with required checks and manual review thresholds.
 * 2. Immutable file version artifact identity binding.
 * 3. Scanner findings evaluation via pure decide(policy, fileVersion, findings).
 * 4. Deterministic decision persistence in PostgreSQL security_decisions.
 * 5. Retrieval through Edge API (GET /api/v1/security-decisions/:id).
 * 6. Analyst human review execution (POST /api/v1/security-decisions/:id/review).
 * 7. Verification of superseding decision row, file status transition, and audit trail.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import type { FastifyInstance } from 'fastify';
import { createApp } from '../../../services/api/src/app.js';
import { createDashboardToken } from '../../../services/api/src/auth/jwt.js';
import type { ApiKeyDatabase } from '../../../services/api/src/auth/types.js';
import type { ApiKeyService } from '../../../services/api/src/auth/service.js';
import type { DatabaseExecutor } from '@sug/shared';
import {
  decide,
  persistDecision,
  type DecisionPolicyInput,
  type FileVersionIdentityInput,
  type FindingInput,
} from '../../../packages/decision-engine/src/index.js';
import type { Config } from '@sug/shared/config';

describe('policy-03 — End-to-End Deterministic Decision & Human Review Lifecycle', () => {
  const TEST_PEPPER = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const JWT_KEY_PAIR = crypto.generateKeyPairSync('ed25519');
  const jwtPrivateKeyPem = JWT_KEY_PAIR.privateKey
    .export({ type: 'pkcs8', format: 'pem' })
    .toString();

  const appId = '018f3a5e-7a42-7000-8000-000000000001';
  const fileId = '018f3a5e-7a42-7000-8000-000000000010';
  const fileVersionId = '018f3a5e-7a42-7000-8000-000000000020';
  const scanJobId = '018f3a5e-7a42-7000-8000-000000000030';
  const policyId = '018f3a5e-7a42-7000-8000-000000000040';

  const dummyContent = 'policy-03-test-content-suspicious-doc';
  const dummySha = crypto.createHash('sha256').update(dummyContent).digest('hex');
  const validApiKey =
    'sug_a1b2c3d4_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  let app: FastifyInstance;
  const dbDecisions: Record<string, Record<string, unknown>> = {};
  const auditLogEntries: unknown[] = [];
  const fileStatusHistory: string[] = ['PENDING'];

  const policy: DecisionPolicyInput = {
    id: policyId,
    name: 'corporate-strict-policy',
    version: 1,
    sha256: dummySha,
    requiredChecks: ['clamav.instream', 'yara.rules'],
    riskThreshold: 60,
    manualReviewThreshold: 20,
    disagreementAction: 'QUARANTINE',
  };

  const artifactIdentity: FileVersionIdentityInput = {
    bucket: 'sug-quarantine-local',
    objectKey: `quarantine/${appId}/${fileId}`,
    storageVersionId: 'storage-ver-1001',
    sha256: dummySha,
    sizeBytes: Buffer.byteLength(dummyContent),
  };

  const findings: FindingInput[] = [
    {
      checkId: 'scanner.clamav',
      engine: 'clamav',
      engineVersion: '1.4.0',
      signatureVersion: '27200',
      outcome: 'PASS',
      reasonCode: 'CLEAN',
      severity: 'INFO',
      confidence: 'CONFIRMED',
      scannedStorageVersionId: artifactIdentity.storageVersionId,
      scannedSha256: dummySha,
      scannedSizeBytes: artifactIdentity.sizeBytes,
    },
    {
      checkId: 'scanner.yara',
      engine: 'yara-x',
      engineVersion: '0.12.0',
      signatureVersion: 'v1.0.0',
      outcome: 'PASS',
      reasonCode: 'CLEAN',
      severity: 'INFO',
      confidence: 'CONFIRMED',
      scannedStorageVersionId: artifactIdentity.storageVersionId,
      scannedSha256: dummySha,
      scannedSizeBytes: artifactIdentity.sizeBytes,
    },
    {
      checkId: 'scanner.detector',
      engine: 'file-type',
      engineVersion: '1.0.0',
      signatureVersion: null,
      outcome: 'WARN',
      reasonCode: 'DETECTOR_DISAGREEMENT',
      severity: 'MEDIUM',
      confidence: 'HIGH',
      scannedStorageVersionId: artifactIdentity.storageVersionId,
      scannedSha256: dummySha,
      scannedSizeBytes: artifactIdentity.sizeBytes,
    },
  ];

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

  const mockDb = {
    query: vi.fn().mockImplementation(async (sql: string, params: unknown[] = []) => {
      // 1. Query decision by ID
      if (sql.includes('FROM security_decisions sd')) {
        const id = params[0] as string;
        const row = dbDecisions[id];
        return { rows: row ? [row] : [] };
      }

      // 2. Insert decision
      if (sql.includes('INSERT INTO security_decisions')) {
        const newId = crypto.randomUUID();
        const row = {
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
        dbDecisions[newId] = {
          ...row,
          application_id: appId,
          file_id: fileId,
          policy_document: policy,
        };
        return { rows: [row] };
      }

      // 3. Update file status
      if (sql.includes('UPDATE files SET status')) {
        fileStatusHistory.push(params[0]);
        return { rowCount: 1 };
      }

      // 4. Audit append
      if (sql.includes('audit_append')) {
        auditLogEntries.push(params);
        return { rowCount: 1 };
      }

      return { rows: [] };
    }),
  };

  const mockApiKeyService = {
    verifyApiKey: vi.fn().mockImplementation(async (rawKey: string) => {
      if (rawKey === validApiKey) {
        return {
          isValid: true,
          app: {
            applicationId: appId,
            name: 'Policy-03 App',
            scopes: ['upload', 'read'],
          },
        };
      }
      return { isValid: false, reason: 'INVALID_KEY' };
    }),
  };

  beforeAll(async () => {
    app = await createApp({
      config: mockConfig,
      db: { checkReachability: async () => {} },
      storage: { checkReachability: async () => {} },
      authDb: mockDb as unknown as ApiKeyDatabase,
      apiKeyService: mockApiKeyService as unknown as ApiKeyService,
    });
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('policy-03: Executes upload -> decide() -> persistence -> GET API -> human review override -> superseding ALLOW', async () => {
    // Step 1: Execute deterministic decision engine
    const initialResult = decide(policy, artifactIdentity, findings);

    // Rule R4 triggers QUARANTINE due to DETECTOR_DISAGREEMENT
    expect(initialResult.decision).toBe('QUARANTINE');
    expect(initialResult.rule).toBe('R4');
    expect(initialResult.primaryReason).toBe('DETECTOR_DISAGREEMENT');
    expect(initialResult.riskScore).toBe(25);
    expect(initialResult.record.schema).toBe('sug.decision/v1');
    expect(initialResult.record.artifactIdentity.sha256).toBe(dummySha);

    // Step 2: Persist decision to database
    const initialDecisionRow = await persistDecision(
      mockDb as unknown as DatabaseExecutor,
      initialResult,
      {
        fileVersionId,
        policyId,
        scanJobId,
      },
    );

    expect(initialDecisionRow.id).toBeDefined();
    const initialDecisionId = initialDecisionRow.id;

    // Step 3: Retrieve decision via Edge API GET /api/v1/security-decisions/:id
    const getRes = await app.inject({
      method: 'GET',
      url: `/api/v1/security-decisions/${initialDecisionId}`,
      headers: { authorization: `Bearer ${validApiKey}` },
    });

    expect(getRes.statusCode).toBe(200);
    const getBody = JSON.parse(getRes.body);
    expect(getBody.id).toBe(initialDecisionId);
    expect(getBody.decision).toBe('QUARANTINE');
    expect(getBody.boundSha256).toBe(dummySha);
    expect(getBody.record.rule).toBe('R4');
    expect(getBody.record.primaryReason).toBe('DETECTOR_DISAGREEMENT');

    // Step 4: Security Analyst performs human review override
    const analystId = crypto.randomUUID();
    const analystToken = await createDashboardToken(
      {
        id: analystId,
        email: 'analyst@secops.internal',
        role: 'analyst',
      },
      jwtPrivateKeyPem,
    );

    const reviewRes = await app.inject({
      method: 'POST',
      url: `/api/v1/security-decisions/${initialDecisionId}/review`,
      headers: { authorization: `Bearer ${analystToken}` },
      payload: {
        action: 'ALLOW',
        justification:
          'Reviewed detector disagreement; file headers verified benign for application ingestion',
      },
    });

    expect(reviewRes.statusCode).toBe(201);
    const reviewBody = JSON.parse(reviewRes.body);

    // Step 5: Verify the superseding decision record
    expect(reviewBody.decision).toBe('ALLOW');
    expect(reviewBody.primaryReason).toBe('HUMAN_REVIEW_ALLOW');
    expect(reviewBody.supersedesId).toBe(initialDecisionId);
    expect(reviewBody.record.supersedesId).toBe(initialDecisionId);
    expect(reviewBody.record.rule).toBe('HUMAN_REVIEW');
    expect(reviewBody.record.humanReview?.justification).toContain(
      'Reviewed detector disagreement',
    );
    expect(reviewBody.record.humanReview?.reviewer).toBe('analyst@secops.internal');

    // Step 6: Verify file status transition to SCANNED
    expect(fileStatusHistory).toContain('SCANNED');

    // Step 7: Verify tamper-evident audit event recorded
    expect(auditLogEntries.length).toBeGreaterThan(0);
    const auditEntry = auditLogEntries[0]!;
    expect(auditEntry[0]).toBe(analystId); // actor
    const auditPayload = JSON.parse(auditEntry[2]);
    expect(auditPayload.priorDecisionId).toBe(initialDecisionId);
    expect(auditPayload.priorDecision).toBe('QUARANTINE');
    expect(auditPayload.newDecision).toBe('ALLOW');

    // Step 8: Verify retrieving the new superseding decision via GET API
    const getSupersedingRes = await app.inject({
      method: 'GET',
      url: `/api/v1/security-decisions/${reviewBody.id}`,
      headers: { authorization: `Bearer ${validApiKey}` },
    });

    expect(getSupersedingRes.statusCode).toBe(200);
    const getSupersedingBody = JSON.parse(getSupersedingRes.body);
    expect(getSupersedingBody.decision).toBe('ALLOW');
    expect(getSupersedingBody.supersedesId).toBe(initialDecisionId);
  });
});
