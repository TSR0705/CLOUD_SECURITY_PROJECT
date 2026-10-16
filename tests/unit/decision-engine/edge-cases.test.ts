/**
 * @sug/test/unit/decision-engine/edge-cases
 * Unit tests specifically covering remaining branches in packages/decision-engine
 * for 100% branch and statement coverage.
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import {
  decide,
  calculateRiskScore,
  checkMatches,
  isRequiredCheckSatisfied,
  evaluateReview,
  type DecisionPolicyInput,
  type FileVersionIdentityInput,
  type FindingInput,
  type ExistingDecision,
  type SeverityLevel,
  type ConfidenceLevel,
  type FindingOutcome,
  type DecisionRecordV1,
} from '../../../packages/decision-engine/src/index.js';

describe('Decision Engine — Branch Coverage Edge Cases', () => {
  const dummySha = crypto.createHash('sha256').update('branch-corpus').digest('hex');
  const validIdentity: FileVersionIdentityInput = {
    bucket: 'sug-quarantine-local',
    objectKey: 'quarantine/app/file',
    storageVersionId: 'v-1',
    sha256: dummySha,
    sizeBytes: 500,
  };

  const defaultPolicy: DecisionPolicyInput = {
    id: '018f3a5e-7a42-7000-8000-000000000001',
    name: 'test-policy',
    version: 1,
    sha256: dummySha,
    requiredChecks: ['clamav.instream'],
    riskThreshold: 50,
    manualReviewThreshold: 25,
  };

  describe('risk.ts branch coverage', () => {
    it('returns 0 when findings is null or empty', () => {
      expect(calculateRiskScore(null as unknown as FindingInput[])).toBe(0);
      expect(calculateRiskScore([])).toBe(0);
    });

    it('skips PASS and SKIPPED outcomes', () => {
      const score = calculateRiskScore([
        {
          checkId: 'check-1',
          engine: 'e1',
          outcome: 'PASS',
          reasonCode: 'CLEAN',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 100,
        },
        {
          checkId: 'check-2',
          engine: 'e2',
          outcome: 'SKIPPED',
          reasonCode: 'SKIPPED',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 100,
        },
      ]);
      expect(score).toBe(0);
    });

    it('handles ERROR outcome with CRITICAL, ERROR, LOW, and undefined severities', () => {
      // ERROR with severity CRITICAL -> 100
      expect(
        calculateRiskScore([
          {
            checkId: 'c1',
            engine: 'e1',
            outcome: 'ERROR',
            severity: 'CRITICAL',
            reasonCode: 'TIMEOUT',
            scannedStorageVersionId: 'v-1',
            scannedSha256: dummySha,
            scannedSizeBytes: 100,
          },
        ]),
      ).toBe(100);

      // ERROR with severity ERROR -> 100
      expect(
        calculateRiskScore([
          {
            checkId: 'c1',
            engine: 'e1',
            outcome: 'ERROR',
            severity: 'ERROR',
            reasonCode: 'TIMEOUT',
            scannedStorageVersionId: 'v-1',
            scannedSha256: dummySha,
            scannedSizeBytes: 100,
          },
        ]),
      ).toBe(100);

      // ERROR with severity LOW -> 10
      expect(
        calculateRiskScore([
          {
            checkId: 'c1',
            engine: 'e1',
            outcome: 'ERROR',
            severity: 'LOW',
            reasonCode: 'MINOR_ERROR',
            scannedStorageVersionId: 'v-1',
            scannedSha256: dummySha,
            scannedSizeBytes: 100,
          },
        ]),
      ).toBe(10);

      // ERROR with severity undefined -> fallback 100
      expect(
        calculateRiskScore([
          {
            checkId: 'c1',
            engine: 'e1',
            outcome: 'ERROR',
            reasonCode: 'ERR',
            scannedStorageVersionId: 'v-1',
            scannedSha256: dummySha,
            scannedSizeBytes: 100,
          },
        ]),
      ).toBe(100);
    });

    it('handles SUSPICIOUS and WARN outcomes with different severities and clamps at 100', () => {
      const score = calculateRiskScore([
        {
          checkId: 'c1',
          engine: 'e1',
          outcome: 'SUSPICIOUS',
          severity: 'HIGH', // 75
          reasonCode: 'SUSPICIOUS_CONTENT',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 100,
        },
        {
          checkId: 'c2',
          engine: 'e2',
          outcome: 'WARN',
          severity: 'MEDIUM', // 25
          reasonCode: 'WARN_DISAGREEMENT',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 100,
        },
        {
          checkId: 'c3',
          engine: 'e3',
          outcome: 'FAIL',
          severity: 'LOW', // 10
          reasonCode: 'MINOR_FAIL',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 100,
        },
      ]);
      // 75 + 25 + 10 = 110 -> clamped to 100
      expect(score).toBe(100);
    });
  });

  describe('mapping.ts branch coverage', () => {
    it('matches exact IDs and prefix-stripped check IDs', () => {
      expect(checkMatches('clamav.instream', 'clamav.instream')).toBe(true);
      expect(checkMatches('scanner.clamav', 'clamav.instream')).toBe(true);
      expect(checkMatches('clamav.instream', 'scanner.clamav')).toBe(true);
      expect(checkMatches('validator.filename', 'filename.safe')).toBe(true);
      expect(checkMatches('custom.check', 'scanner.custom.check')).toBe(true);
      expect(checkMatches('custom.check', 'unrelated.check')).toBe(false);
    });

    it('isRequiredCheckSatisfied handles empty and matched finding lists', () => {
      expect(isRequiredCheckSatisfied('clamav.instream', [])).toBe(false);
      expect(isRequiredCheckSatisfied('clamav.instream', ['scanner.clamav'])).toBe(true);
      expect(isRequiredCheckSatisfied('clamav.instream', ['unrelated.check'])).toBe(false);
    });
  });

  describe('engine.ts branch coverage', () => {
    it('normalizes string sizeBytes and bigint sizeBytes in identity', () => {
      const stringSizeIdentity: FileVersionIdentityInput = {
        bucket: 'sug-quarantine-local',
        objectKey: 'quarantine/app/file',
        storageVersionId: 'v-1',
        sha256: dummySha,
        sizeBytes: '2048',
      };

      const res = decide(defaultPolicy, stringSizeIdentity, [
        {
          checkId: 'scanner.clamav',
          engine: 'clamav',
          outcome: 'PASS',
          reasonCode: 'CLEAN',
          severity: 'INFO',
          confidence: 'CONFIRMED',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 2048,
        },
      ]);
      expect(res.decision).toBe('ALLOW');
      expect(res.boundSize).toBe(2048);
    });

    it('handles finding normalization: string scannedSizeBytes, bigint scannedSizeBytes, evidence vs details', () => {
      const res = decide(defaultPolicy, validIdentity, [
        {
          checkId: 'scanner.clamav',
          engine: 'clamav',
          engineVersion: '1.4.0',
          signatureVersion: '27200',
          outcome: 'PASS',
          reasonCode: 'CLEAN',
          severity: 'INFO',
          confidence: 'CONFIRMED',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 500n,
          durationMs: 12.5,
          evidence: { match: 'test' },
        },
      ]);
      expect(res.decision).toBe('ALLOW');

      const resWithDetails = decide(defaultPolicy, validIdentity, [
        {
          checkId: 'scanner.clamav',
          engine: 'clamav',
          outcome: 'PASS',
          reasonCode: 'CLEAN',
          severity: 'INFO',
          confidence: 'CONFIRMED',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: '500',
          details: { match: 'test-details' },
        },
      ]);
      expect(resWithDetails.decision).toBe('ALLOW');
    });

    it('handles finding with invalid sha256 or negative durationMs gracefully', () => {
      const res = decide(defaultPolicy, validIdentity, [
        {
          checkId: 'scanner.clamav',
          engine: 'clamav',
          outcome: 'PASS',
          reasonCode: 'CLEAN',
          severity: 'invalid-severity' as unknown as SeverityLevel,
          confidence: 'invalid-confidence' as unknown as ConfidenceLevel,
          scannedStorageVersionId: 'v-1',
          scannedSha256: 'invalid-sha-throws',
          scannedSizeBytes: 500,
          durationMs: -10,
        },
      ]);
      // Scanned sha mismatch triggers R1
      expect(res.decision).toBe('ERROR');
      expect(res.rule).toBe('R1');
      expect(res.primaryReason).toBe('RESULT_IDENTITY_MISMATCH');
    });

    it('evaluates disagreementAction: FLAG without blocking or quarantining', () => {
      const flagPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        disagreementAction: 'FLAG',
      };

      const res = decide(flagPolicy, validIdentity, [
        {
          checkId: 'scanner.clamav',
          engine: 'clamav',
          outcome: 'PASS',
          reasonCode: 'CLEAN',
          severity: 'INFO',
          confidence: 'CONFIRMED',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 500,
        },
        {
          checkId: 'scanner.detector',
          engine: 'detector',
          outcome: 'WARN',
          reasonCode: 'DETECTOR_DISAGREEMENT',
          severity: 'LOW',
          confidence: 'HIGH',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 500,
        },
      ]);
      // Disagreement action is FLAG, so R4 does not trigger.
      // Total risk score is 10 (LOW), below manualReviewThreshold (25) -> ALLOW (R7)
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
    });

    it('handles policy without requiredChecks', () => {
      const noReqPolicy: DecisionPolicyInput = {
        id: crypto.randomUUID(),
        name: 'no-req',
        version: 1,
        sha256: dummySha,
        requiredChecks: [],
      };

      const res = decide(noReqPolicy, validIdentity, []);
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
    });
  });

  describe('review.ts branch coverage', () => {
    const baseDecision: ExistingDecision = {
      id: crypto.randomUUID(),
      file_version_id: crypto.randomUUID(),
      policy_id: crypto.randomUUID(),
      scan_job_id: null,
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
      bound_key: 'quarantine/app/file',
      bound_storage_version_id: 'v-1',
      bound_sha256: Buffer.from(dummySha, 'hex'),
      bound_size: 500,
      record: null as unknown as DecisionRecordV1,
      engine_version: '1.0.0',
      decided_by: 'engine',
      created_at: new Date(),
    };

    it('evaluates review with missing existingRecord or missing policy', () => {
      const res = evaluateReview(baseDecision, {
        action: 'ALLOW',
        justification: 'Reviewed and confirmed clean for ingestion',
        reviewer: 'secops-lead@company.internal',
      });

      expect(res.decision).toBe('ALLOW');
      expect(res.record.policy.name).toBe('reviewed-policy');
      expect(res.record.findingReferences).toEqual([]);
    });

    it('evaluates review action BLOCK', () => {
      const res = evaluateReview(baseDecision, {
        action: 'BLOCK',
        justification: 'Confirmed dangerous behavior, blocking permanently',
        reviewer: 'secops-lead@company.internal',
      });

      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('HUMAN_REVIEW_BLOCK');
    });

    it('evaluates fallback weights and outcomes in risk calculation', () => {
      // outcome ERROR with unknown severity -> tests ?? 100
      const scoreErrUnknown = calculateRiskScore([
        {
          checkId: 'c1',
          engine: 'e1',
          outcome: 'ERROR',
          severity: 'UNKNOWN_SEV' as unknown as SeverityLevel,
          reasonCode: 'ERR',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 100,
        },
      ]);
      expect(scoreErrUnknown).toBe(100);

      // outcome FAIL with undefined severity -> tests ?? 'INFO' -> weight 0
      const scoreFailUndefined = calculateRiskScore([
        {
          checkId: 'c1',
          engine: 'e1',
          outcome: 'FAIL',
          reasonCode: 'FAIL_INFO',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 100,
        },
      ]);
      expect(scoreFailUndefined).toBe(0);

      // outcome FAIL with unknown severity -> tests ?? 0
      const scoreFailUnknown = calculateRiskScore([
        {
          checkId: 'c1',
          engine: 'e1',
          outcome: 'FAIL',
          severity: 'UNKNOWN_SEV' as unknown as SeverityLevel,
          reasonCode: 'FAIL_UNKNOWN',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 100,
        },
      ]);
      expect(scoreFailUnknown).toBe(0);
    });

    it('handles empty findings with required checks in engine -> R2 CHECK_MISSING', () => {
      const res = decide(defaultPolicy, validIdentity, []);
      expect(res.decision).toBe('ERROR');
      expect(res.rule).toBe('R2');
      expect(res.primaryReason).toBe('CHECK_MISSING');
    });

    it('handles empty reasonCode on errors and threats with default fallbacks', () => {
      const errorFindingNoReason: FindingInput = {
        checkId: 'scanner.clamav',
        engine: 'clamav',
        outcome: 'ERROR',
        reasonCode: '',
        severity: 'ERROR',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1',
        scannedSha256: dummySha,
        scannedSizeBytes: 500,
      };

      const resError = decide(defaultPolicy, validIdentity, [errorFindingNoReason]);
      expect(resError.decision).toBe('ERROR');
      expect(resError.rule).toBe('R2');
      expect(resError.primaryReason).toBe('UNKNOWN');

      const threatFindingNoReason: FindingInput = {
        checkId: 'scanner.clamav',
        engine: 'clamav',
        outcome: 'FAIL',
        reasonCode: '',
        severity: 'CRITICAL',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1',
        scannedSha256: dummySha,
        scannedSizeBytes: 500,
      };

      const resThreat = decide(defaultPolicy, validIdentity, [threatFindingNoReason]);
      expect(resThreat.decision).toBe('BLOCK');
      expect(resThreat.rule).toBe('R3');
      expect(resThreat.primaryReason).toBe('UNKNOWN');
    });

    it('exercises all normalizeIdentity fallbacks and validation branches', () => {
      // null policy and null identity
      expect(
        decide(
          null as unknown as DecisionPolicyInput,
          null as unknown as FileVersionIdentityInput,
          null as unknown as FindingInput[],
        ),
      ).toMatchObject({
        decision: 'ERROR',
        rule: 'R1',
        primaryReason: 'DECISION_IDENTITY_MISMATCH',
      });

      // valid identity with null findings
      expect(
        decide(
          { ...defaultPolicy, requiredChecks: [] },
          validIdentity,
          null as unknown as FindingInput[],
        ),
      ).toMatchObject({
        decision: 'ALLOW',
        rule: 'R7',
      });

      // non-string bucket
      expect(
        decide(defaultPolicy, { ...validIdentity, bucket: 123 as unknown as string }, []),
      ).toMatchObject({
        decision: 'ERROR',
        rule: 'R1',
      });

      // whitespace bucket
      expect(decide(defaultPolicy, { ...validIdentity, bucket: '   ' }, [])).toMatchObject({
        decision: 'ERROR',
        rule: 'R1',
      });

      // object_key fallback when objectKey is undefined
      const snakeKeyIdentity: FileVersionIdentityInput = {
        bucket: 'sug-quarantine-local',
        object_key: 'quarantine/app/file',
        storage_version_id: 'v-1',
        sha256: dummySha,
        size_bytes: 500,
      };
      expect(
        decide(defaultPolicy, snakeKeyIdentity, [
          {
            checkId: 'scanner.clamav',
            engine: 'clamav',
            outcome: 'PASS',
            reasonCode: 'CLEAN',
            severity: 'INFO',
            confidence: 'CONFIRMED',
            scannedStorageVersionId: 'v-1',
            scannedSha256: dummySha,
            scannedSizeBytes: 500,
          },
        ]),
      ).toMatchObject({ decision: 'ALLOW', rule: 'R7' });

      // empty sha256 -> !canonicalSha branch
      expect(decide(defaultPolicy, { ...validIdentity, sha256: '' }, [])).toMatchObject({
        decision: 'ERROR',
        rule: 'R1',
      });

      // non-integer sizeBytes (e.g. 10.5)
      expect(decide(defaultPolicy, { ...validIdentity, sizeBytes: 10.5 }, [])).toMatchObject({
        decision: 'ERROR',
        rule: 'R1',
      });

      // non-number sizeBytes
      expect(
        decide(defaultPolicy, { ...validIdentity, sizeBytes: undefined as unknown as number }, []),
      ).toMatchObject({
        decision: 'ERROR',
        rule: 'R1',
      });
    });

    it('exercises normalizeFinding and sort tie-breakers', () => {
      // Buffer sha256 in finding, missing checkId, engine, severity, confidence, reasonCode
      const minimalFinding: FindingInput = {
        checkId: undefined as unknown as string,
        engine: undefined as unknown as string,
        outcome: undefined as unknown as FindingOutcome,
        reasonCode: undefined as unknown as string,
        severity: undefined as unknown as SeverityLevel,
        confidence: undefined as unknown as ConfidenceLevel,
        scannedStorageVersionId: undefined as unknown as string,
        scannedSha256: Buffer.from(dummySha, 'hex'),
        scannedSizeBytes: undefined as unknown as number,
      };

      const res = decide(defaultPolicy, validIdentity, [minimalFinding]);
      // scannedStorageVersionId mismatch -> R1 ERROR
      expect(res.decision).toBe('ERROR');
      expect(res.rule).toBe('R1');

      // Sort tie-breaker: two findings with equal severity and equal confidence
      const finding1: FindingInput = {
        checkId: 'scanner.b',
        engine: 'clamav',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1',
        scannedSha256: dummySha,
        scannedSizeBytes: 500,
      };
      const finding2: FindingInput = {
        checkId: 'scanner.a',
        engine: 'clamav',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1',
        scannedSha256: dummySha,
        scannedSizeBytes: 500,
      };
      const sortRes = decide({ ...defaultPolicy, requiredChecks: [] }, validIdentity, [
        finding1,
        finding2,
      ]);
      expect(sortRes.decision).toBe('ALLOW');
      // Sort tie-breaker: two findings with equal severity but different confidence
      const findingConfHigh: FindingInput = {
        checkId: 'scanner.high_conf',
        engine: 'clamav',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'HIGH',
        scannedStorageVersionId: 'v-1',
        scannedSha256: dummySha,
        scannedSizeBytes: 500,
      };
      const findingConfConfirmed: FindingInput = {
        checkId: 'scanner.confirmed_conf',
        engine: 'clamav',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1',
        scannedSha256: dummySha,
        scannedSizeBytes: 500,
      };
      const sortConfRes = decide({ ...defaultPolicy, requiredChecks: [] }, validIdentity, [
        findingConfHigh,
        findingConfConfirmed,
      ]);
      expect(sortConfRes.decision).toBe('ALLOW');
      expect(sortConfRes.record.findingReferences[0]!.checkId).toBe('scanner.confirmed_conf');

      // Finding with empty scannedSha256 string
      const emptyShaFinding: FindingInput = {
        checkId: 'scanner.empty_sha',
        engine: 'clamav',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1',
        scannedSha256: '',
        scannedSizeBytes: 500,
      };
      expect(decide(defaultPolicy, validIdentity, [emptyShaFinding])).toMatchObject({
        decision: 'ERROR',
        rule: 'R1',
      });

      // Missing objectKey and object_key
      expect(
        decide(
          defaultPolicy,
          { ...validIdentity, objectKey: undefined, object_key: undefined },
          [],
        ),
      ).toMatchObject({
        decision: 'ERROR',
        rule: 'R1',
      });

      // Missing storageVersionId and storage_version_id
      expect(
        decide(
          defaultPolicy,
          { ...validIdentity, storageVersionId: undefined, storage_version_id: undefined },
          [],
        ),
      ).toMatchObject({
        decision: 'ERROR',
        rule: 'R1',
      });
    });

    it('exercises decide fallbacks when policy properties are omitted', () => {
      const minimalPolicy: DecisionPolicyInput = {
        id: undefined,
        name: undefined,
        version: undefined,
        sha256: undefined,
        riskThreshold: undefined,
        manualReviewThreshold: undefined,
      };

      const res = decide(minimalPolicy, validIdentity, [
        {
          checkId: 'scanner.clamav',
          engine: 'clamav',
          outcome: 'PASS',
          reasonCode: 'CLEAN',
          severity: 'INFO',
          confidence: 'CONFIRMED',
          scannedStorageVersionId: 'v-1',
          scannedSha256: dummySha,
          scannedSizeBytes: 500,
        },
      ]);
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
      expect(res.record.riskThreshold).toBe(50);
    });
  });
});
