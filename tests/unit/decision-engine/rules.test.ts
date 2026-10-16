/**
 * @sug/test/unit/decision-engine/rules
 * Unit test suite for Deterministic Decision Engine (Rules R1–R7, R2/R3 precedence).
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  decide,
  ENGINE_VERSION,
  type DecisionPolicyInput,
  type FileVersionIdentityInput,
  type FindingInput,
} from '../../../packages/decision-engine/src/index.js';

describe('Deterministic Decision Engine — Rules R1–R7 & Precedence (Phase P18)', () => {
  const dummySha = crypto.createHash('sha256').update('clean-file-content').digest('hex');
  const validIdentity: FileVersionIdentityInput = {
    bucket: 'sug-quarantine-local',
    objectKey: 'quarantine/app-01/file-01',
    storageVersionId: 'v-1001',
    sha256: dummySha,
    sizeBytes: 1024,
  };

  const defaultPolicy: DecisionPolicyInput = {
    id: '018f3a5e-7a42-7000-8000-000000000001',
    name: 'corporate-default',
    version: 1,
    sha256: 'a'.repeat(64),
    requiredChecks: ['clamav.instream', 'yara.rules'],
    riskThreshold: 50,
  };

  const cleanFindings: FindingInput[] = [
    {
      checkId: 'scanner.clamav',
      engine: 'clamav',
      engineVersion: '1.4.0',
      signatureVersion: '27200',
      outcome: 'PASS',
      reasonCode: 'CLEAN',
      severity: 'INFO',
      confidence: 'CONFIRMED',
      scannedStorageVersionId: 'v-1001',
      scannedSha256: dummySha,
      scannedSizeBytes: 1024,
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
      scannedStorageVersionId: 'v-1001',
      scannedSha256: dummySha,
      scannedSizeBytes: 1024,
    },
  ];

  describe('Rule R1 — Artifact Identity Verification', () => {
    it('fails closed (BLOCK / RESULT_IDENTITY_MISMATCH) if fileVersion identity is null or missing fields', () => {
      const resNull = decide(
        defaultPolicy,
        null as unknown as FileVersionIdentityInput,
        cleanFindings,
      );
      expect(resNull.decision).toBe('BLOCK');
      expect(resNull.primaryReason).toBe('RESULT_IDENTITY_MISMATCH');
      expect(resNull.rule).toBe('R1');

      const resMissingKey = decide(
        defaultPolicy,
        { ...validIdentity, objectKey: '' },
        cleanFindings,
      );
      expect(resMissingKey.decision).toBe('BLOCK');
      expect(resMissingKey.primaryReason).toBe('RESULT_IDENTITY_MISMATCH');
      expect(resMissingKey.rule).toBe('R1');

      const resMissingBucket = decide(
        defaultPolicy,
        { ...validIdentity, bucket: '' },
        cleanFindings,
      );
      expect(resMissingBucket.decision).toBe('BLOCK');
      expect(resMissingBucket.rule).toBe('R1');

      const resBadVersion = decide(
        defaultPolicy,
        { ...validIdentity, storageVersionId: 'null' },
        cleanFindings,
      );
      expect(resBadVersion.decision).toBe('BLOCK');
      expect(resBadVersion.rule).toBe('R1');

      const resLatestVersion = decide(
        defaultPolicy,
        { ...validIdentity, storageVersionId: 'latest' },
        cleanFindings,
      );
      expect(resLatestVersion.decision).toBe('BLOCK');
      expect(resLatestVersion.rule).toBe('R1');
    });

    it('fails closed (BLOCK / RESULT_IDENTITY_MISMATCH) on invalid SHA-256 or negative size', () => {
      const resBadSha = decide(
        defaultPolicy,
        { ...validIdentity, sha256: 'not-a-valid-sha' },
        cleanFindings,
      );
      expect(resBadSha.decision).toBe('BLOCK');
      expect(resBadSha.primaryReason).toBe('RESULT_IDENTITY_MISMATCH');
      expect(resBadSha.rule).toBe('R1');

      const resNegSize = decide(defaultPolicy, { ...validIdentity, sizeBytes: -5 }, cleanFindings);
      expect(resNegSize.decision).toBe('BLOCK');
      expect(resNegSize.rule).toBe('R1');
    });

    it('fails closed (BLOCK / RESULT_IDENTITY_MISMATCH) if finding scannedSha256 does not match fileVersion identity', () => {
      const mismatchedFinding: FindingInput = {
        ...cleanFindings[0]!,
        scannedSha256: 'b'.repeat(64),
      };

      const res = decide(defaultPolicy, validIdentity, [mismatchedFinding, cleanFindings[1]!]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('RESULT_IDENTITY_MISMATCH');
      expect(res.rule).toBe('R1');
      expect(res.riskScore).toBe(100);
      expect(res.severity).toBe('HIGH');
      expect(res.confidence).toBe('CONFIRMED');
    });

    it('fails closed (BLOCK / RESULT_IDENTITY_MISMATCH) if finding scannedStorageVersionId does not match', () => {
      const mismatchedFinding: FindingInput = {
        ...cleanFindings[0]!,
        scannedStorageVersionId: 'v-9999-wrong',
      };

      const res = decide(defaultPolicy, validIdentity, [mismatchedFinding, cleanFindings[1]!]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('RESULT_IDENTITY_MISMATCH');
      expect(res.rule).toBe('R1');
    });

    it('fails closed (BLOCK / RESULT_IDENTITY_MISMATCH) if finding scannedSizeBytes does not match', () => {
      const mismatchedFinding: FindingInput = {
        ...cleanFindings[0]!,
        scannedSizeBytes: 999999,
      };

      const res = decide(defaultPolicy, validIdentity, [mismatchedFinding, cleanFindings[1]!]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('RESULT_IDENTITY_MISMATCH');
      expect(res.rule).toBe('R1');
    });

    it('supports alternative snake_case identity field naming and Buffer SHA256 input', () => {
      const snakeIdentity: FileVersionIdentityInput = {
        bucket: 'sug-quarantine-local',
        object_key: 'quarantine/app-01/file-01',
        storage_version_id: 'v-1001',
        sha256_ingest: Buffer.from(dummySha, 'hex'),
        size_bytes: 1024n,
      };

      const res = decide(defaultPolicy, snakeIdentity, cleanFindings);
      expect(res.decision).toBe('ALLOW');
      expect(res.boundSha256).toBe(dummySha);
    });
  });

  describe('Rule R2 — Required Checks & Scanner Errors', () => {
    it('fails closed (ERROR / REQUIRED_CHECK_MISSING) when a required check is omitted from findings', () => {
      // Policy requires clamav and yara; findings only contain clamav
      const res = decide(defaultPolicy, validIdentity, [cleanFindings[0]!]);
      expect(res.decision).toBe('ERROR');
      expect(res.primaryReason).toBe('REQUIRED_CHECK_MISSING');
      expect(res.rule).toBe('R2');
      expect(res.scannerResult).toBe('ERROR');
      expect(res.riskScore).toBe(100);
    });

    it('fails closed (ERROR / SCANNER_UNAVAILABLE) when scanner daemon is offline or signatures stale', () => {
      const unavailableFinding: FindingInput = {
        checkId: 'scanner.clamav',
        engine: 'clamav',
        engineVersion: '1.4.0',
        signatureVersion: 'stale-7-days',
        outcome: 'ERROR',
        reasonCode: 'SCANNER_UNAVAILABLE',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [unavailableFinding, cleanFindings[1]!]);
      expect(res.decision).toBe('ERROR');
      expect(res.primaryReason).toBe('SCANNER_UNAVAILABLE');
      expect(res.rule).toBe('R2');
      expect(res.scannerResult).toBe('ERROR');
      expect(res.riskScore).toBe(100);
    });

    it('fails closed (ERROR / SCAN_TIMEOUT) when scanner execution times out', () => {
      const timeoutFinding: FindingInput = {
        checkId: 'scanner.clamav',
        engine: 'clamav',
        engineVersion: '1.4.0',
        signatureVersion: '27200',
        outcome: 'ERROR',
        reasonCode: 'SCAN_TIMEOUT',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [timeoutFinding, cleanFindings[1]!]);
      expect(res.decision).toBe('ERROR');
      expect(res.primaryReason).toBe('SCAN_TIMEOUT');
      expect(res.rule).toBe('R2');
      expect(res.scannerResult).toBe('ERROR');
    });

    it('fails closed (ERROR / CLAMAV_SCAN_TIMEOUT) when a specific error reason code is emitted', () => {
      const errorFinding: FindingInput = {
        checkId: 'scanner.clamav',
        engine: 'clamav',
        engineVersion: '1.4.0',
        signatureVersion: '27200',
        outcome: 'ERROR',
        reasonCode: 'CLAMAV_SCAN_TIMEOUT',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [errorFinding, cleanFindings[1]!]);
      expect(res.decision).toBe('ERROR');
      expect(res.primaryReason).toBe('CLAMAV_SCAN_TIMEOUT');
      expect(res.rule).toBe('R2');
      expect(res.scannerResult).toBe('ERROR');
      expect(res.riskScore).toBe(100);
    });

    it('does not trigger R2 ERROR if an optional (non-required) check has an error', () => {
      const optionalErrorFinding: FindingInput = {
        checkId: 'scanner.experimental',
        engine: 'experimental',
        engineVersion: '1.0.0',
        signatureVersion: null,
        outcome: 'ERROR',
        reasonCode: 'EXPERIMENTAL_ERROR',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [...cleanFindings, optionalErrorFinding]);
      // Optional check error with LOW severity adds low risk, not triggering R2 ERROR
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
    });
  });

  describe('Rule R3 — Threat Detection (Malware & High-Risk Indicators)', () => {
    it('produces BLOCK on CRITICAL finding (e.g. MALWARE_DETECTED)', () => {
      const malwareFinding: FindingInput = {
        checkId: 'scanner.clamav',
        engine: 'clamav',
        engineVersion: '1.4.0',
        signatureVersion: '27200',
        outcome: 'FAIL',
        reasonCode: 'MALWARE_DETECTED',
        severity: 'CRITICAL',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
        details: { threatName: 'Win.Test.EICAR_HDB-1' },
      };

      const res = decide(defaultPolicy, validIdentity, [malwareFinding, cleanFindings[1]!]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('MALWARE_DETECTED');
      expect(res.rule).toBe('R3');
      expect(res.severity).toBe('CRITICAL');
      expect(res.confidence).toBe('CONFIRMED');
      expect(res.scannerResult).toBe('FAIL');
    });

    it('produces BLOCK on HIGH severity finding (e.g. OFFICE_MACRO_PRESENT)', () => {
      const macroPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        requiredChecks: ['clamav.instream', 'office.macros'],
      };

      const macroFinding: FindingInput = {
        checkId: 'scanner.format.ooxml_macro',
        engine: 'format-detector',
        engineVersion: '1.0.0',
        signatureVersion: null,
        outcome: 'FAIL',
        reasonCode: 'OFFICE_MACRO_PRESENT',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(macroPolicy, validIdentity, [cleanFindings[0]!, macroFinding]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('OFFICE_MACRO_PRESENT');
      expect(res.rule).toBe('R3');
      expect(res.severity).toBe('HIGH');
    });
  });

  describe('R2 / R3 Precedence — Threat (BLOCK) Wins Over Scanner Error (ERROR)', () => {
    it('CRITICAL threat takes precedence over missing required check -> BLOCK, NOT ERROR', () => {
      const malwareFinding: FindingInput = {
        checkId: 'scanner.clamav',
        engine: 'clamav',
        engineVersion: '1.4.0',
        signatureVersion: '27200',
        outcome: 'FAIL',
        reasonCode: 'MALWARE_DETECTED',
        severity: 'CRITICAL',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      // YARA check is required by defaultPolicy, but absent in findings!
      // R2 would say ERROR (missing check), but R3 says BLOCK (malware detected).
      // Precedence requirement: BLOCK wins.
      const res = decide(defaultPolicy, validIdentity, [malwareFinding]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('MALWARE_DETECTED');
      expect(res.rule).toBe('R3');
      expect(res.severity).toBe('CRITICAL');
    });

    it('HIGH threat takes precedence over scanner timeout/error -> BLOCK, NOT ERROR', () => {
      const yaraThreat: FindingInput = {
        checkId: 'scanner.yara',
        engine: 'yara-x',
        engineVersion: '0.12.0',
        signatureVersion: 'v1.0.0',
        outcome: 'FAIL',
        reasonCode: 'YARA_MATCH',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const clamavError: FindingInput = {
        checkId: 'scanner.clamav',
        engine: 'clamav',
        engineVersion: '1.4.0',
        signatureVersion: '27200',
        outcome: 'ERROR',
        reasonCode: 'CLAMAV_TIMEOUT',
        severity: 'ERROR',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      // Both threat and error present: Threat MUST win
      const res = decide(defaultPolicy, validIdentity, [clamavError, yaraThreat]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('YARA_MATCH');
      expect(res.rule).toBe('R3');
      expect(res.severity).toBe('HIGH');
    });

    it('Scanner error takes precedence when only LOW/INFO findings exist -> ERROR', () => {
      const clamavError: FindingInput = {
        checkId: 'scanner.clamav',
        engine: 'clamav',
        engineVersion: '1.4.0',
        signatureVersion: '27200',
        outcome: 'ERROR',
        reasonCode: 'CLAMAV_CONNECTION_REFUSED',
        severity: 'ERROR',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const yaraPass: FindingInput = {
        checkId: 'scanner.yara',
        engine: 'yara-x',
        engineVersion: '0.12.0',
        signatureVersion: 'v1.0.0',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [clamavError, yaraPass]);
      expect(res.decision).toBe('ERROR');
      expect(res.primaryReason).toBe('CLAMAV_CONNECTION_REFUSED');
      expect(res.rule).toBe('R2');
    });
  });

  describe('Rule R4 — Disagreements and Quarantine', () => {
    it('quarantines when disagreementAction is QUARANTINE and detector disagreement occurs', () => {
      const disagreementPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        disagreementAction: 'QUARANTINE',
      };

      const disagreementFinding: FindingInput = {
        checkId: 'scanner.detector',
        engine: 'file-type',
        engineVersion: '1.0.0',
        signatureVersion: null,
        outcome: 'WARN',
        reasonCode: 'DETECTOR_DISAGREEMENT',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(disagreementPolicy, validIdentity, [
        ...cleanFindings,
        disagreementFinding,
      ]);
      expect(res.decision).toBe('QUARANTINE');
      expect(res.primaryReason).toBe('DETECTOR_DISAGREEMENT');
      expect(res.rule).toBe('R4');
    });

    it('blocks when disagreementAction is BLOCK and detector disagreement occurs', () => {
      const blockPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        disagreementAction: 'BLOCK',
      };

      const disagreementFinding: FindingInput = {
        checkId: 'scanner.detector',
        engine: 'file-type',
        engineVersion: '1.0.0',
        signatureVersion: null,
        outcome: 'WARN',
        reasonCode: 'DETECTOR_DISAGREEMENT',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(blockPolicy, validIdentity, [...cleanFindings, disagreementFinding]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('DETECTOR_DISAGREEMENT');
      expect(res.rule).toBe('R4');
    });
  });

  describe('Rule R3 — Threat Detection (Malware, Exploits, Archive Bombs & Structural Failures)', () => {
    it('blocks on ARCHIVE_BOMB_DETECTED (HIGH/CRITICAL severity)', () => {
      const archivePolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        requiredChecks: ['clamav.instream', 'yara.rules', 'archive.structure'],
      };

      const bombFinding: FindingInput = {
        checkId: 'scanner.archive.integrity',
        engine: 'security-engine-archive',
        engineVersion: '1.0.0',
        signatureVersion: null,
        outcome: 'FAIL',
        reasonCode: 'ARCHIVE_BOMB_DETECTED',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(archivePolicy, validIdentity, [...cleanFindings, bombFinding]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('ARCHIVE_BOMB_DETECTED');
      expect(res.rule).toBe('R3');
      expect(res.integrityResult).toBe('FAIL');
    });

    it('blocks on ZIP_SLIP_DETECTED or OVERLAPPING_ENTRIES', () => {
      const zipSlipFinding: FindingInput = {
        checkId: 'scanner.archive.integrity',
        engine: 'security-engine-archive',
        engineVersion: '1.0.0',
        signatureVersion: null,
        outcome: 'FAIL',
        reasonCode: 'ZIP_SLIP_DETECTED',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [...cleanFindings, zipSlipFinding]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('ZIP_SLIP_DETECTED');
      expect(res.rule).toBe('R3');
      expect(res.integrityResult).toBe('FAIL');
    });
  });

  describe('Rule R4 — Medium-Severity and Suspicious Findings', () => {
    it('quarantines on medium severity FAIL finding under default onSuspicious (e.g. OOXML external relationship)', () => {
      const relFinding: FindingInput = {
        checkId: 'scanner.ooxml.relationship',
        engine: 'ooxml',
        outcome: 'FAIL',
        reasonCode: 'OOXML_EXTERNAL_RELATIONSHIP',
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [...cleanFindings, relFinding]);
      expect(res.decision).toBe('QUARANTINE');
      expect(res.rule).toBe('R4');
      expect(res.primaryReason).toBe('OOXML_EXTERNAL_RELATIONSHIP');
    });

    it('quarantines on medium severity archive finding (e.g. DUPLICATE_ENTRY_NAMES) and sets integrityResult to FAIL', () => {
      const dupFinding: FindingInput = {
        checkId: 'scanner.archive.integrity',
        engine: 'security-engine-archive',
        outcome: 'FAIL',
        reasonCode: 'DUPLICATE_ENTRY_NAMES',
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [...cleanFindings, dupFinding]);
      expect(res.decision).toBe('QUARANTINE');
      expect(res.rule).toBe('R4');
      expect(res.primaryReason).toBe('DUPLICATE_ENTRY_NAMES');
      expect(res.integrityResult).toBe('FAIL');
    });

    it('blocks on medium severity FAIL finding when policy.onSuspicious === "BLOCK"', () => {
      const blockPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        onSuspicious: 'BLOCK',
      };

      const relFinding: FindingInput = {
        checkId: 'scanner.ooxml.relationship',
        engine: 'ooxml',
        outcome: 'FAIL',
        reasonCode: 'OOXML_EXTERNAL_RELATIONSHIP',
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(blockPolicy, validIdentity, [...cleanFindings, relFinding]);
      expect(res.decision).toBe('BLOCK');
      expect(res.rule).toBe('R4');
      expect(res.primaryReason).toBe('OOXML_EXTERNAL_RELATIONSHIP');
    });

    it('triggers policy.onSuspicious (QUARANTINE) on explicit SUSPICIOUS outcome finding', () => {
      const suspiciousFinding: FindingInput = {
        checkId: 'scanner.format.custom',
        engine: 'custom',
        outcome: 'SUSPICIOUS',
        reasonCode: 'ANOMALOUS_METADATA',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [...cleanFindings, suspiciousFinding]);
      expect(res.decision).toBe('QUARANTINE');
      expect(res.rule).toBe('R4');
      expect(res.primaryReason).toBe('ANOMALOUS_METADATA');
    });

    it('triggers policy.onSuspicious (BLOCK) on explicit SUSPICIOUS outcome finding when onSuspicious is BLOCK', () => {
      const blockPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        onSuspicious: 'BLOCK',
      };

      const suspiciousFinding: FindingInput = {
        checkId: 'scanner.format.custom',
        engine: 'custom',
        outcome: 'SUSPICIOUS',
        reasonCode: 'ANOMALOUS_METADATA',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(blockPolicy, validIdentity, [...cleanFindings, suspiciousFinding]);
      expect(res.decision).toBe('BLOCK');
      expect(res.rule).toBe('R4');
      expect(res.primaryReason).toBe('ANOMALOUS_METADATA');
    });

    it('quarantines when disagreementAction is QUARANTINE and detector disagreement occurs', () => {
      const disagreementPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        disagreementAction: 'QUARANTINE',
      };

      const disagreementFinding: FindingInput = {
        checkId: 'scanner.detector',
        engine: 'file-type',
        engineVersion: '1.0.0',
        signatureVersion: null,
        outcome: 'WARN',
        reasonCode: 'DETECTOR_DISAGREEMENT',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(disagreementPolicy, validIdentity, [
        ...cleanFindings,
        disagreementFinding,
      ]);
      expect(res.decision).toBe('QUARANTINE');
      expect(res.primaryReason).toBe('DETECTOR_DISAGREEMENT');
      expect(res.rule).toBe('R4');
    });

    it('quarantines by default when detector disagreement occurs and disagreementAction is not configured', () => {
      const disagreementFinding: FindingInput = {
        checkId: 'scanner.detector',
        engine: 'file-type',
        engineVersion: '1.0.0',
        signatureVersion: null,
        outcome: 'WARN',
        reasonCode: 'DETECTOR_DISAGREEMENT',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [...cleanFindings, disagreementFinding]);
      expect(res.decision).toBe('QUARANTINE');
      expect(res.primaryReason).toBe('DETECTOR_DISAGREEMENT');
      expect(res.rule).toBe('R4');
    });

    it('blocks when disagreementAction is BLOCK and detector disagreement occurs', () => {
      const blockPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        disagreementAction: 'BLOCK',
      };

      const disagreementFinding: FindingInput = {
        checkId: 'scanner.detector',
        engine: 'file-type',
        engineVersion: '1.0.0',
        signatureVersion: null,
        outcome: 'WARN',
        reasonCode: 'DETECTOR_DISAGREEMENT',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(blockPolicy, validIdentity, [...cleanFindings, disagreementFinding]);
      expect(res.decision).toBe('BLOCK');
      expect(res.primaryReason).toBe('DETECTOR_DISAGREEMENT');
      expect(res.rule).toBe('R4');
    });

    it('flags detector disagreement when disagreementAction is FLAG without triggering R4', () => {
      const flagPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        disagreementAction: 'FLAG',
      };

      const disagreementFinding: FindingInput = {
        checkId: 'scanner.detector',
        engine: 'file-type',
        outcome: 'WARN',
        reasonCode: 'DETECTOR_DISAGREEMENT',
        severity: 'MEDIUM',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(flagPolicy, validIdentity, [...cleanFindings, disagreementFinding]);
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
    });
  });

  describe('Rule R5 — Required Content Disarm and Reconstruction (CDR)', () => {
    it('quarantines with CDR_REQUIRED_NOT_DONE when cdrRequired is true and no CDR check exists', () => {
      const cdrPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        cdrRequired: true,
      };

      const res = decide(cdrPolicy, validIdentity, cleanFindings);
      expect(res.decision).toBe('QUARANTINE');
      expect(res.rule).toBe('R5');
      expect(res.primaryReason).toBe('CDR_REQUIRED_NOT_DONE');
      expect(res.severity).toBe('MEDIUM');
      expect(res.scannerResult).toBe('SUSPICIOUS');
    });

    it('blocks with CDR_REQUIRED_NOT_DONE when cdrRequired is true and onSuspicious is BLOCK', () => {
      const cdrBlockPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        cdrRequired: true,
        onSuspicious: 'BLOCK',
      };

      const res = decide(cdrBlockPolicy, validIdentity, cleanFindings);
      expect(res.decision).toBe('BLOCK');
      expect(res.rule).toBe('R5');
      expect(res.primaryReason).toBe('CDR_REQUIRED_NOT_DONE');
    });

    it('quarantines with CDR_REQUIRED_NOT_DONE when cdrRequired is true and CDR check failed', () => {
      const cdrPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        cdrRequired: true,
      };

      const failedCdrFinding: FindingInput = {
        checkId: 'scanner.cdr',
        engine: 'cdr-disarm',
        outcome: 'FAIL',
        reasonCode: 'CDR_PROCESSING_FAILED',
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(cdrPolicy, validIdentity, [...cleanFindings, failedCdrFinding]);
      expect(res.decision).toBe('QUARANTINE');
    });

    it('allows file when cdrRequired is true and a sanitized CDR check with PASS is present', () => {
      const cdrPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        cdrRequired: true,
      };

      const cdrFinding: FindingInput = {
        checkId: 'scanner.cdr',
        engine: 'cdr-disarm',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(cdrPolicy, validIdentity, [...cleanFindings, cdrFinding]);
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
      expect(res.primaryReason).toBe('ALL_CHECKS_PASSED');
    });
  });

  describe('Rule R6 — Manual-Review Risk Threshold', () => {
    it('quarantines with RISK_THRESHOLD when cumulative risk score reaches manualReviewThreshold', () => {
      const quarantinePolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        manualReviewThreshold: 25,
      };

      // 3 low-risk findings (10 points each): 10 + 10 + 10 = 30 >= 25
      const low1: FindingInput = {
        checkId: 'scanner.opt1',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_1',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };
      const low2: FindingInput = {
        checkId: 'scanner.opt2',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_2',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };
      const low3: FindingInput = {
        checkId: 'scanner.opt3',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_3',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(quarantinePolicy, validIdentity, [...cleanFindings, low1, low2, low3]);
      expect(res.decision).toBe('QUARANTINE');
      expect(res.rule).toBe('R6');
      expect(res.primaryReason).toBe('RISK_THRESHOLD');
      expect(res.riskScore).toBe(30);
    });

    it('blocks with RISK_THRESHOLD when risk score meets manualReviewThreshold and policy.onSuspicious === "BLOCK"', () => {
      const blockPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        manualReviewThreshold: 20,
        onSuspicious: 'BLOCK',
      };

      const low1: FindingInput = {
        checkId: 'scanner.opt1',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_1',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };
      const low2: FindingInput = {
        checkId: 'scanner.opt2',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_2',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(blockPolicy, validIdentity, [...cleanFindings, low1, low2]);
      expect(res.decision).toBe('BLOCK');
      expect(res.rule).toBe('R6');
      expect(res.primaryReason).toBe('RISK_THRESHOLD');
      expect(res.riskScore).toBe(20);
    });

    it('boundary: risk score equal to manualReviewThreshold (score === threshold) triggers R6', () => {
      const boundaryPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        manualReviewThreshold: 20,
      };

      const low1: FindingInput = {
        checkId: 'scanner.opt1',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_1',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };
      const low2: FindingInput = {
        checkId: 'scanner.opt2',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_2',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(boundaryPolicy, validIdentity, [...cleanFindings, low1, low2]);
      expect(res.decision).toBe('QUARANTINE');
      expect(res.rule).toBe('R6');
      expect(res.primaryReason).toBe('RISK_THRESHOLD');
      expect(res.riskScore).toBe(20);
    });

    it('boundary: risk score immediately below manualReviewThreshold (score === threshold - 1) allows file', () => {
      const boundaryPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        manualReviewThreshold: 21,
      };

      const low1: FindingInput = {
        checkId: 'scanner.opt1',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_1',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };
      const low2: FindingInput = {
        checkId: 'scanner.opt2',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_2',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(boundaryPolicy, validIdentity, [...cleanFindings, low1, low2]);
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
      expect(res.primaryReason).toBe('ALL_CHECKS_PASSED');
      expect(res.riskScore).toBe(20);
    });

    it('allows clean file with a nonzero risk score below review threshold', () => {
      const normalPolicy: DecisionPolicyInput = {
        ...defaultPolicy,
        manualReviewThreshold: 50,
      };

      const low1: FindingInput = {
        checkId: 'scanner.opt1',
        engine: 'opt',
        outcome: 'WARN',
        reasonCode: 'LOW_NOTE_1',
        severity: 'LOW',
        confidence: 'LOW',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(normalPolicy, validIdentity, [...cleanFindings, low1]);
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
      expect(res.primaryReason).toBe('ALL_CHECKS_PASSED');
      expect(res.riskScore).toBe(10);
    });
  });

  describe('Rule R7 — Clean Allow & Fail-Closed Fallback', () => {
    it('produces ALLOW when all required checks pass cleanly and risk score is 0', () => {
      const res = decide(defaultPolicy, validIdentity, cleanFindings);
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
      expect(res.primaryReason).toBe('ALL_CHECKS_PASSED');
      expect(res.severity).toBe('INFO');
      expect(res.confidence).toBe('CONFIRMED');
      expect(res.riskScore).toBe(0);
      expect(res.policyResult).toBe('PASS');
      expect(res.scannerResult).toBe('PASS');
      expect(res.integrityResult).toBe('PASS');
      expect(res.authorizationResult).toBe('PASS');
    });

    it('produces ALLOW when risk score is below manual review threshold and all checks are clear', () => {
      const res = decide(defaultPolicy, validIdentity, cleanFindings);
      expect(res.decision).toBe('ALLOW');
      expect(res.rule).toBe('R7');
      expect(res.primaryReason).toBe('ALL_CHECKS_PASSED');
    });

    it('produces an explainable sug.decision/v1 record with complete provenance', () => {
      const res = decide(defaultPolicy, validIdentity, cleanFindings);
      const record = res.record;

      expect(record.schema).toBe('sug.decision/v1');
      expect(record.decision).toBe('ALLOW');
      expect(record.rule).toBe('R7');
      expect(record.engineVersion).toBe(ENGINE_VERSION);
      expect(typeof record.decidedAt).toBe('string');
      expect(record.policy.id).toBe(defaultPolicy.id);
      expect(record.artifactIdentity.sha256).toBe(dummySha);
      expect(record.artifactIdentity.sizeBytes).toBe(1024);
      expect(record.findingReferences).toHaveLength(2);
      expect(record.ruleTrace.length).toBeGreaterThan(0);
    });

    it('sorts reasons deterministically', () => {
      const findingZ: FindingInput = {
        checkId: 'scanner.z',
        engine: 'engine-z',
        engineVersion: '1.0',
        signatureVersion: null,
        outcome: 'INFO',
        reasonCode: 'Z_REASON',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const findingA: FindingInput = {
        checkId: 'scanner.a',
        engine: 'engine-a',
        engineVersion: '1.0',
        signatureVersion: null,
        outcome: 'INFO',
        reasonCode: 'A_REASON',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        scannedStorageVersionId: 'v-1001',
        scannedSha256: dummySha,
        scannedSizeBytes: 1024,
      };

      const res = decide(defaultPolicy, validIdentity, [...cleanFindings, findingZ, findingA]);
      expect(res.decision).toBe('ALLOW');
      // Reasons should contain A_REASON before Z_REASON
      const idxA = res.record.reasons.indexOf('A_REASON');
      const idxZ = res.record.reasons.indexOf('Z_REASON');
      expect(idxA).toBeLessThan(idxZ);
    });
  });
});
