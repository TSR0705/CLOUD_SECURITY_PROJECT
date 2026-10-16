/**
 * @sug/test/unit/decision-engine/review
 * Unit test suite for Human Review Workflow (Phase P18).
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  evaluateReview,
  ReviewValidationError,
  type ExistingDecision,
  type ReviewRequest,
  type ReviewAction,
  type DecisionPolicyInput,
} from '../../../packages/decision-engine/src/index.js';

describe('Deterministic Decision Engine — Human Review Workflow (Phase P18)', () => {
  const dummySha = crypto.createHash('sha256').update('test-content').digest('hex');
  const dummyId = crypto.randomUUID();
  const fileVersionId = crypto.randomUUID();
  const policyId = crypto.randomUUID();

  const baseDecision: ExistingDecision = {
    id: dummyId,
    file_version_id: fileVersionId,
    policy_id: policyId,
    scan_job_id: crypto.randomUUID(),
    decision: 'QUARANTINE',
    primary_reason: 'DETECTOR_DISAGREEMENT',
    severity: 'MEDIUM',
    confidence: 'CONFIRMED',
    risk_score: 35,
    policy_result: 'PASS',
    scanner_result: 'WARN',
    integrity_result: 'PASS',
    authorization_result: 'PASS',
    bound_bucket: 'sug-quarantine-local',
    bound_key: 'quarantine/app-01/file-01',
    bound_storage_version_id: 'v-1',
    bound_sha256: Buffer.from(dummySha, 'hex'),
    bound_size: 2048,
    record: {
      schema: 'sug.decision/v1',
      decision: 'QUARANTINE',
      rule: 'R4_DISAGREEMENT',
      primaryReason: 'DETECTOR_DISAGREEMENT',
      severity: 'MEDIUM',
      confidence: 'CONFIRMED',
      riskScore: 35,
      riskThreshold: 50,
      policy: { id: policyId, name: 'default', version: 1, sha256: 'a'.repeat(64) },
      artifactIdentity: {
        bucket: 'sug-quarantine-local',
        objectKey: 'quarantine/app-01/file-01',
        versionId: 'v-1',
        sha256: dummySha,
        sizeBytes: 2048,
      },
      resultsSummary: {
        policyResult: 'PASS',
        scannerResult: 'WARN',
        integrityResult: 'PASS',
        authorizationResult: 'PASS',
      },
      reasons: ['DETECTOR_DISAGREEMENT'],
      findingReferences: [],
      ruleTrace: [],
      engineVersion: '1.0.0',
      decidedAt: new Date().toISOString(),
      decidedBy: 'engine',
    },
    engine_version: '1.0.0',
    decided_by: 'engine',
    created_at: new Date(),
  };

  const defaultPolicy: DecisionPolicyInput = {
    id: policyId,
    name: 'default',
    version: 1,
    sha256: 'a'.repeat(64),
    requiredChecks: ['clamav.instream'],
    riskThreshold: 50,
    manualReviewThreshold: 25,
  };

  it('allows overriding a QUARANTINE decision to ALLOW with valid justification (>= 10 chars)', () => {
    const reviewReq: ReviewRequest = {
      action: 'ALLOW',
      justification: 'Verified as false positive by tier-2 security analyst',
      reviewer: 'analyst@corp.internal',
      reviewerId: crypto.randomUUID(),
    };

    const res = evaluateReview(baseDecision, reviewReq, defaultPolicy);
    expect(res.decision).toBe('ALLOW');
    expect(res.primaryReason).toBe('HUMAN_REVIEW_ALLOW');
    expect(res.rule).toBe('HUMAN_REVIEW');
    expect(res.decidedBy).toBe('human:analyst@corp.internal');
    expect(res.record.supersedesId).toBe(dummyId);
    expect(res.boundSha256).toBe(dummySha);
    expect(res.record.humanReview?.justification).toBe(reviewReq.justification);
    expect(res.record.humanReview?.reviewer).toBe(reviewReq.reviewer);
  });

  it('allows overriding a QUARANTINE decision to BLOCK with valid justification', () => {
    const reviewReq: ReviewRequest = {
      action: 'BLOCK',
      justification: 'Confirmed suspicious active content, rejecting upload',
      reviewer: 'senior-analyst@corp.internal',
    };

    const res = evaluateReview(baseDecision, reviewReq, defaultPolicy);
    expect(res.decision).toBe('BLOCK');
    expect(res.primaryReason).toBe('HUMAN_REVIEW_BLOCK');
    expect(res.rule).toBe('HUMAN_REVIEW');
    expect(res.decidedBy).toBe('human:senior-analyst@corp.internal');
    expect(res.record.supersedesId).toBe(dummyId);
  });

  it('allows overriding a non-critical BLOCK (e.g. high cumulative risk score) to ALLOW with justification', () => {
    const scoreBlockDecision: ExistingDecision = {
      ...baseDecision,
      decision: 'BLOCK',
      primary_reason: 'RISK_SCORE_THRESHOLD_EXCEEDED',
      severity: 'HIGH',
      risk_score: 55,
    };

    const reviewReq: ReviewRequest = {
      action: 'ALLOW',
      justification: 'Multiple medium heuristics were evaluated and confirmed benign',
      reviewer: 'lead-secops@corp.internal',
    };

    const res = evaluateReview(scoreBlockDecision, reviewReq, defaultPolicy);
    expect(res.decision).toBe('ALLOW');
    expect(res.primaryReason).toBe('HUMAN_REVIEW_ALLOW');
  });

  describe('Fail-Closed Invariants & Validation', () => {
    it('FAIL-CLOSED: Rejects attempting to override ERROR decision to ALLOW', () => {
      const errorDecision: ExistingDecision = {
        ...baseDecision,
        decision: 'ERROR',
        primary_reason: 'REQUIRED_CHECK_MISSING',
        severity: 'HIGH',
      };

      const reviewReq: ReviewRequest = {
        action: 'ALLOW',
        justification: 'Attempting to bypass missing scanner checks',
        reviewer: 'attacker@corp.internal',
      };

      expect(() => evaluateReview(errorDecision, reviewReq, defaultPolicy)).toThrowError(
        ReviewValidationError,
      );
      expect(() => evaluateReview(errorDecision, reviewReq, defaultPolicy)).toThrowError(
        /Cannot override ERROR decision/i,
      );
    });

    it('FAIL-CLOSED: Rejects attempting to override confirmed MALWARE_DETECTED to ALLOW', () => {
      const malwareDecision: ExistingDecision = {
        ...baseDecision,
        decision: 'BLOCK',
        primary_reason: 'MALWARE_DETECTED',
        severity: 'CRITICAL',
      };

      const reviewReq: ReviewRequest = {
        action: 'ALLOW',
        justification: 'Customer urgently requested this malware file anyway',
        reviewer: 'analyst@corp.internal',
      };

      expect(() => evaluateReview(malwareDecision, reviewReq, defaultPolicy)).toThrowError(
        ReviewValidationError,
      );
      expect(() => evaluateReview(malwareDecision, reviewReq, defaultPolicy)).toThrowError(
        /Cannot override critical threat BLOCK decision/i,
      );
    });

    it('FAIL-CLOSED: Rejects attempting to override ARCHIVE_BOMB_DETECTED or ZIP_SLIP_DETECTED to ALLOW', () => {
      const bombDecision: ExistingDecision = {
        ...baseDecision,
        decision: 'BLOCK',
        primary_reason: 'ARCHIVE_BOMB_DETECTED',
        severity: 'HIGH',
      };

      const reviewReq: ReviewRequest = {
        action: 'ALLOW',
        justification: 'Decompression ratio is expected for this specific zip',
        reviewer: 'analyst@corp.internal',
      };

      expect(() => evaluateReview(bombDecision, reviewReq, defaultPolicy)).toThrowError(
        ReviewValidationError,
      );
    });

    it('rejects short justifications (< 10 chars)', () => {
      const reviewReq: ReviewRequest = {
        action: 'ALLOW',
        justification: 'Too short',
        reviewer: 'analyst@corp.internal',
      };

      expect(() => evaluateReview(baseDecision, reviewReq, defaultPolicy)).toThrowError(
        ReviewValidationError,
      );
      expect(() => evaluateReview(baseDecision, reviewReq, defaultPolicy)).toThrowError(
        /at least 10 characters/i,
      );
    });

    it('rejects invalid review actions or empty reviewer', () => {
      expect(() =>
        evaluateReview(baseDecision, {
          action: 'INVALID' as unknown as ReviewAction,
          justification: 'Valid length justification here',
          reviewer: 'analyst@corp.internal',
        }),
      ).toThrowError(/Invalid review action/i);

      expect(() =>
        evaluateReview(baseDecision, {
          action: 'ALLOW',
          justification: 'Valid length justification here',
          reviewer: '   ',
        }),
      ).toThrowError(/Reviewer identity is required/i);
    });

    it('rejects missing target decision or null review payload', () => {
      expect(() =>
        evaluateReview(null as unknown as ExistingDecision, {
          action: 'ALLOW',
          justification: 'abc',
          reviewer: 'x',
        }),
      ).toThrowError(/Target security decision does not exist/i);

      expect(() => evaluateReview(baseDecision, null as unknown as ReviewRequest)).toThrowError(
        /Review payload is required/i,
      );
    });
  });
});
