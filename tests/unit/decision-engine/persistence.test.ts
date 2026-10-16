/**
 * @sug/test/unit/decision-engine/persistence
 * Unit tests for persistDecision in packages/decision-engine.
 */

import { describe, it, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import type { DatabaseExecutor } from '@sug/shared';
import {
  persistDecision,
  type DecisionResult,
  type DecisionRecordV1,
} from '../../../packages/decision-engine/src/index.js';

describe('Decision Engine — Persistence Unit Tests', () => {
  const dummySha = crypto.createHash('sha256').update('persistence-test').digest('hex');
  const dummyFileVersionId = crypto.randomUUID();
  const dummyPolicyId = crypto.randomUUID();
  const dummyScanJobId = crypto.randomUUID();
  const dummySupersedesId = crypto.randomUUID();

  const dummyRecord: DecisionRecordV1 = {
    schema: 'sug.decision/v1',
    decision: 'ALLOW',
    rule: 'R7',
    primaryReason: 'ALL_CHECKS_PASSED',
    severity: 'INFO',
    confidence: 'CONFIRMED',
    riskScore: 0,
    riskThreshold: 50,
    policy: {
      id: dummyPolicyId,
      name: 'test-policy',
      version: 1,
      sha256: dummySha,
    },
    artifactIdentity: {
      bucket: 'sug-quarantine-local',
      objectKey: 'quarantine/app-1/file-1',
      versionId: 'v-100',
      sha256: dummySha,
      sizeBytes: 1024,
    },
    resultsSummary: {
      policyResult: 'PASS',
      scannerResult: 'PASS',
      integrityResult: 'PASS',
      authorizationResult: 'PASS',
    },
    findingReferences: [],
    reasons: ['ALL_CHECKS_PASSED'],
    ruleTrace: ['R7: CLEAN_ALLOW'],
    engineVersion: '1.0.0',
    decidedAt: new Date().toISOString(),
    decidedBy: 'engine',
  };

  const dummyResult: DecisionResult = {
    decision: 'ALLOW',
    primaryReason: 'ALL_CHECKS_PASSED',
    severity: 'INFO',
    confidence: 'CONFIRMED',
    riskScore: 0,
    rule: 'R7',
    policyResult: 'PASS',
    scannerResult: 'PASS',
    integrityResult: 'PASS',
    authorizationResult: 'PASS',
    boundBucket: 'sug-quarantine-local',
    boundKey: 'quarantine/app-1/file-1',
    boundStorageVersionId: 'v-100',
    boundSha256: dummySha,
    boundSize: 1024,
    record: dummyRecord,
    engineVersion: '1.0.0',
    decidedBy: 'engine',
  };

  it('persists a decision result with all required fields into database', async () => {
    let capturedQuery = '';
    let capturedValues: unknown[] = [];

    const mockDb: DatabaseExecutor = {
      query: vi.fn().mockImplementation(async (query: string, values?: unknown[]) => {
        capturedQuery = query;
        capturedValues = values ?? [];
        return {
          rows: [
            {
              id: '018f3a5e-7a42-7000-8000-000000000001',
              file_version_id: dummyFileVersionId,
              policy_id: dummyPolicyId,
              scan_job_id: dummyScanJobId,
              decision: 'ALLOW',
              bound_sha256: Buffer.from(dummySha, 'hex'),
            },
          ],
        };
      }),
    };

    const res = await persistDecision(mockDb, dummyResult, {
      fileVersionId: dummyFileVersionId,
      policyId: dummyPolicyId,
      scanJobId: dummyScanJobId,
      supersedesId: dummySupersedesId,
    });

    expect(res.id).toBe('018f3a5e-7a42-7000-8000-000000000001');
    expect(capturedQuery).toContain('INSERT INTO security_decisions');
    expect(capturedValues[0]).toBe(dummyFileVersionId);
    expect(capturedValues[1]).toBe(dummyScanJobId);
    expect(capturedValues[2]).toBe(dummyPolicyId);
    expect(capturedValues[3]).toBe('ALLOW');
    expect(Buffer.isBuffer(capturedValues[15])).toBe(true);
    expect(capturedValues[20]).toBe(dummySupersedesId);
  });

  it('handles optional scanJobId and supersedesId gracefully when omitted', async () => {
    let capturedValues: unknown[] = [];

    const mockDb: DatabaseExecutor = {
      query: vi.fn().mockImplementation(async (_q: string, values?: unknown[]) => {
        capturedValues = values ?? [];
        return {
          rows: [
            {
              id: '018f3a5e-7a42-7000-8000-000000000002',
              file_version_id: dummyFileVersionId,
              policy_id: dummyPolicyId,
              decision: 'ALLOW',
            },
          ],
        };
      }),
    };

    const res = await persistDecision(mockDb, dummyResult, {
      fileVersionId: dummyFileVersionId,
      policyId: dummyPolicyId,
    });

    expect(res.id).toBe('018f3a5e-7a42-7000-8000-000000000002');
    expect(capturedValues[1]).toBeNull(); // scan_job_id null
    expect(capturedValues[20]).toBeNull(); // supersedes_id null
  });

  it('extracts supersedesId from record if not explicitly in params', async () => {
    let capturedValues: unknown[] = [];

    const mockDb: DatabaseExecutor = {
      query: vi.fn().mockImplementation(async (_q: string, values?: unknown[]) => {
        capturedValues = values ?? [];
        return {
          rows: [{ id: '018f3a5e-7a42-7000-8000-000000000003' }],
        };
      }),
    };

    const recordWithSupersedes: DecisionRecordV1 = {
      ...dummyRecord,
      supersedesId: 'prior-decision-id',
    };

    await persistDecision(
      mockDb,
      { ...dummyResult, record: recordWithSupersedes },
      {
        fileVersionId: dummyFileVersionId,
        policyId: dummyPolicyId,
      },
    );

    expect(capturedValues[20]).toBe('prior-decision-id');
  });
});
