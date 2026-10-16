/**
 * @sug/test/unit/decision-engine/property
 * 10,000-case Property-Based Test for Phase P18.
 *
 * Invariant: Any ERROR or missing check on a required check NEVER yields ALLOW.
 *
 * Exercises:
 * - 10,000 randomized test cases generated with a deterministic seeded PRNG (seed: 0xDEADBEEF).
 * - Random required checks, findings permutations, error types, and threat combinations.
 * - Asserts decision !== 'ALLOW' across all 10,000 iterations.
 * - Confirms both R3 threat BLOCK and R2 scanner ERROR paths are exercised.
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  decide,
  type DecisionPolicyInput,
  type FileVersionIdentityInput,
  type FindingInput,
  type SeverityLevel,
  type FindingOutcome,
} from '../../../packages/decision-engine/src/index.js';

// Deterministic 32-bit Mulberry32 PRNG
function createPrng(seed: number) {
  let s = seed >>> 0;
  return function next(): number {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe('Deterministic Decision Engine — 10,000-Case Property Invariant (Phase P18)', () => {
  const CHECK_CATALOG = [
    { policyCheck: 'clamav.instream', findingCheck: 'scanner.clamav', engine: 'clamav' },
    { policyCheck: 'yara.rules', findingCheck: 'scanner.yara', engine: 'yara-x' },
    {
      policyCheck: 'archive.structure',
      findingCheck: 'scanner.archive.integrity',
      engine: 'archive',
    },
    { policyCheck: 'office.macros', findingCheck: 'scanner.format.ooxml_macro', engine: 'format' },
    {
      policyCheck: 'format.pdf_active',
      findingCheck: 'scanner.format.pdf_active',
      engine: 'format',
    },
  ];

  const SEVERITIES: SeverityLevel[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ERROR'];
  const OUTCOMES: FindingOutcome[] = ['PASS', 'WARN', 'FAIL', 'ERROR', 'INFO'];
  const ERROR_REASONS = [
    'SCANNER_TIMEOUT',
    'CONNECTION_REFUSED',
    'PARSER_CRASH',
    'RESOURCE_LIMIT_EXCEEDED',
    'INTERNAL_ERROR',
  ];
  const THREAT_REASONS = [
    'MALWARE_DETECTED',
    'YARA_MATCH',
    'ARCHIVE_BOMB_DETECTED',
    'ZIP_SLIP_DETECTED',
    'SUSPICIOUS_HEURISTIC',
  ];

  it('guarantees invariant: Any ERROR or missing check on a required check never yields ALLOW (10,000 iterations)', () => {
    const prng = createPrng(0xdeadbeef);

    const dummySha = crypto.createHash('sha256').update('property-test-corpus').digest('hex');
    const validIdentity: FileVersionIdentityInput = {
      bucket: 'sug-quarantine-test',
      objectKey: 'quarantine/property-app/property-file',
      storageVersionId: 'v-property-1',
      sha256: dummySha,
      sizeBytes: 4096,
    };

    let countBlocks = 0;
    let countErrors = 0;
    let countQuarantines = 0;

    const TOTAL_ITERATIONS = 10000;

    for (let i = 0; i < TOTAL_ITERATIONS; i++) {
      // 1. Pick 1 to 5 required checks
      const numRequired = 1 + Math.floor(prng() * CHECK_CATALOG.length);
      const shuffledCatalog = [...CHECK_CATALOG].sort(() => prng() - 0.5);
      const selectedChecks = shuffledCatalog.slice(0, numRequired);
      const requiredCheckNames = selectedChecks.map((c) => c.policyCheck);

      const policy: DecisionPolicyInput = {
        id: `018f3a5e-7a42-7000-8000-${i.toString(16).padStart(12, '0')}`,
        name: `property-policy-${i}`,
        version: 1,
        sha256: dummySha,
        requiredChecks: requiredCheckNames,
        riskThreshold: 30 + Math.floor(prng() * 50), // 30-80
        manualReviewThreshold: 10 + Math.floor(prng() * 20), // 10-30
      };

      // 2. Select at least one required check to fail or be omitted
      // 0: omit the required check entirely
      // 1: generate an ERROR outcome/severity on the required check
      const failureMode = prng() < 0.5 ? 'OMIT' : 'ERROR_FINDING';
      const failingCheckIndex = Math.floor(prng() * selectedChecks.length);

      const findings: FindingInput[] = [];

      for (let j = 0; j < selectedChecks.length; j++) {
        const item = selectedChecks[j]!;

        if (j === failingCheckIndex) {
          if (failureMode === 'OMIT') {
            // Omit this required check from findings
            continue;
          } else {
            // Generate ERROR finding
            const errReason = ERROR_REASONS[Math.floor(prng() * ERROR_REASONS.length)]!;
            findings.push({
              checkId: item.findingCheck,
              engine: item.engine,
              engineVersion: '1.0.0',
              signatureVersion: 'sig-1',
              outcome: 'ERROR',
              reasonCode: errReason,
              severity: 'ERROR',
              confidence: 'CONFIRMED',
              scannedStorageVersionId: validIdentity.storageVersionId,
              scannedSha256: validIdentity.sha256,
              scannedSizeBytes: validIdentity.sizeBytes,
            });
            continue;
          }
        }

        // For other required checks, generate random outcome
        const isClean = prng() < 0.7;
        if (isClean) {
          findings.push({
            checkId: item.findingCheck,
            engine: item.engine,
            engineVersion: '1.0.0',
            signatureVersion: 'sig-1',
            outcome: 'PASS',
            reasonCode: 'CLEAN',
            severity: 'INFO',
            confidence: 'CONFIRMED',
            scannedStorageVersionId: validIdentity.storageVersionId,
            scannedSha256: validIdentity.sha256,
            scannedSizeBytes: validIdentity.sizeBytes,
          });
        } else {
          // May inject a threat (testing R2/R3 precedence)
          const threatReason = THREAT_REASONS[Math.floor(prng() * THREAT_REASONS.length)]!;
          const sev: SeverityLevel = prng() < 0.5 ? 'CRITICAL' : 'HIGH';
          findings.push({
            checkId: item.findingCheck,
            engine: item.engine,
            engineVersion: '1.0.0',
            signatureVersion: 'sig-1',
            outcome: 'FAIL',
            reasonCode: threatReason,
            severity: sev,
            confidence: 'CONFIRMED',
            scannedStorageVersionId: validIdentity.storageVersionId,
            scannedSha256: validIdentity.sha256,
            scannedSizeBytes: validIdentity.sizeBytes,
          });
        }
      }

      // Optionally inject 0-2 non-required checks
      const extraChecksCount = Math.floor(prng() * 3);
      for (let k = 0; k < extraChecksCount; k++) {
        const extraSev = SEVERITIES[Math.floor(prng() * SEVERITIES.length)]!;
        const extraOutcome = OUTCOMES[Math.floor(prng() * OUTCOMES.length)]!;
        findings.push({
          checkId: `scanner.optional.${k}`,
          engine: 'optional-detector',
          engineVersion: '1.0.0',
          signatureVersion: null,
          outcome: extraOutcome,
          reasonCode: 'OPTIONAL_CHECK',
          severity: extraSev,
          confidence: 'MEDIUM',
          scannedStorageVersionId: validIdentity.storageVersionId,
          scannedSha256: validIdentity.sha256,
          scannedSizeBytes: validIdentity.sizeBytes,
        });
      }

      // Execute deterministic decision
      const result = decide(policy, validIdentity, findings);

      // INVARIANT ASSERTION: MUST NEVER BE ALLOW
      expect(result.decision).not.toBe('ALLOW');

      if (result.decision === 'BLOCK') {
        countBlocks++;
      } else if (result.decision === 'ERROR') {
        countErrors++;
      } else if (result.decision === 'QUARANTINE') {
        countQuarantines++;
      }
    }

    // Verify statistical diversity across the 10,000 cases:
    // Both BLOCK (R3/R5 precedence) and ERROR (R2) must be substantially represented!
    expect(countErrors).toBeGreaterThan(1000);
    expect(countBlocks).toBeGreaterThan(1000);
    expect(countErrors + countBlocks + countQuarantines).toBe(TOTAL_ITERATIONS);
  });
});
