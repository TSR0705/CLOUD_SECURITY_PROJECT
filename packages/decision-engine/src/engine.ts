/**
 * @sug/decision-engine/engine
 * Deterministic decision engine evaluating rules R1–R7 with R2/R3 precedence.
 */

import { Buffer } from 'node:buffer';
import { timingSafeSha256Equal, toCanonicalSha256 } from '@sug/shared';
import type {
  DecisionResult,
  DecisionPolicyInput,
  FileVersionIdentityInput,
  FindingInput,
  FindingReference,
  DecisionRecordV1,
  SeverityLevel,
  ConfidenceLevel,
  ScannerSummaryResult,
} from './types.js';
import { DECISION_RECORD_SCHEMA } from './types.js';
import { calculateRiskScore } from './risk.js';
import { isRequiredCheckSatisfied, checkMatches } from './mapping.js';

export const ENGINE_VERSION = '1.0.0' as const;

export const SEVERITY_RANK: Readonly<Record<SeverityLevel, number>> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export const CONFIDENCE_RANK: Readonly<Record<ConfidenceLevel, number>> = {
  CONFIRMED: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const ARCHIVE_STRUCTURAL_REASONS = new Set([
  'ARCHIVE_BOMB_DETECTED',
  'ZIP_SLIP_DETECTED',
  'UNSAFE_PATH',
  'OVERLAPPING_ENTRIES',
  'ENCRYPTED_ARCHIVE_FORBIDDEN',
  'UNSUPPORTED_COMPRESSION_METHOD',
  'CORRUPT_ARCHIVE',
  'DUPLICATE_ENTRY_NAMES',
  'ARCHIVE_FORBIDDEN',
  'SYMLINK_FORBIDDEN',
  'CRC_MISMATCH',
  'SIZE_MISMATCH',
  'TIMEOUT_EXCEEDED',
  'MEMORY_BUDGET_EXCEEDED',
]);

const DISAGREEMENT_REASONS = new Set(['DETECTOR_DISAGREEMENT', 'TYPE_UNDETERMINED']);

interface NormalizedIdentity {
  bucket: string;
  objectKey: string;
  storageVersionId: string;
  sha256: string;
  sizeBytes: number;
}

interface NormalizedFinding {
  checkId: string;
  engine: string;
  engineVersion: string | null;
  signatureVersion: string | null;
  outcome: FindingInput['outcome'];
  reasonCode: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  scannedStorageVersionId: string;
  scannedSha256: string;
  scannedSizeBytes: number;
  durationMs: number | null;
  evidence: Record<string, unknown>;
}

function normalizeIdentity(input: FileVersionIdentityInput): NormalizedIdentity | null {
  if (!input) return null;

  const bucket = typeof input.bucket === 'string' ? input.bucket.trim() : '';
  const rawKey = input.objectKey ?? input.object_key;
  const objectKey = typeof rawKey === 'string' ? rawKey.trim() : '';
  const rawVersion = input.storageVersionId ?? input.storage_version_id;
  const storageVersionId = typeof rawVersion === 'string' ? rawVersion.trim() : '';

  if (!bucket || !objectKey) return null;
  if (
    !storageVersionId ||
    storageVersionId.toLowerCase() === 'null' ||
    storageVersionId.toLowerCase() === 'latest'
  ) {
    return null;
  }

  const sha256Raw = input.sha256 ?? input.sha256_ingest;
  let canonicalSha = '';
  try {
    if (Buffer.isBuffer(sha256Raw) || (typeof sha256Raw === 'string' && sha256Raw.length > 0)) {
      canonicalSha = toCanonicalSha256(sha256Raw);
    }
  } catch {
    return null;
  }
  if (!canonicalSha) {
    return null;
  }

  const sizeRaw = input.sizeBytes ?? input.size_bytes;
  let sizeBytes = -1;
  if (typeof sizeRaw === 'bigint') {
    sizeBytes = Number(sizeRaw);
  } else if (typeof sizeRaw === 'number') {
    sizeBytes = sizeRaw;
  } else if (typeof sizeRaw === 'string') {
    sizeBytes = Number(sizeRaw.trim());
  }

  if (!Number.isInteger(sizeBytes) || sizeBytes < 0) {
    return null;
  }

  return {
    bucket,
    objectKey,
    storageVersionId,
    sha256: canonicalSha,
    sizeBytes,
  };
}

function normalizeFinding(f: FindingInput): NormalizedFinding {
  let canonicalSha = '';
  try {
    if (
      Buffer.isBuffer(f.scannedSha256) ||
      (typeof f.scannedSha256 === 'string' && f.scannedSha256.length > 0)
    ) {
      canonicalSha = toCanonicalSha256(f.scannedSha256);
    }
  } catch {
    canonicalSha = '';
  }

  let size = -1;
  if (typeof f.scannedSizeBytes === 'bigint') {
    size = Number(f.scannedSizeBytes);
  } else if (typeof f.scannedSizeBytes === 'number') {
    size = f.scannedSizeBytes;
  } else if (typeof f.scannedSizeBytes === 'string') {
    size = Number(f.scannedSizeBytes);
  }

  const sevRaw = f.severity ? String(f.severity).toUpperCase() : 'INFO';
  const severity: SeverityLevel =
    sevRaw === 'CRITICAL' ||
    sevRaw === 'HIGH' ||
    sevRaw === 'MEDIUM' ||
    sevRaw === 'LOW' ||
    sevRaw === 'ERROR'
      ? (sevRaw as SeverityLevel)
      : 'INFO';

  const confRaw = f.confidence ? String(f.confidence).toUpperCase() : 'HIGH';
  const confidence: ConfidenceLevel =
    confRaw === 'CONFIRMED' || confRaw === 'HIGH' || confRaw === 'MEDIUM' || confRaw === 'LOW'
      ? (confRaw as ConfidenceLevel)
      : 'HIGH';

  const scannedStorageVersionId =
    typeof f.scannedStorageVersionId === 'string' ? f.scannedStorageVersionId : '';

  const durationMs =
    typeof f.durationMs === 'number' && Number.isFinite(f.durationMs) && f.durationMs >= 0
      ? f.durationMs
      : null;

  const evidence =
    f.evidence && typeof f.evidence === 'object' && !Array.isArray(f.evidence)
      ? (f.evidence as Record<string, unknown>)
      : f.details && typeof f.details === 'object' && !Array.isArray(f.details)
        ? (f.details as Record<string, unknown>)
        : {};

  return {
    checkId: f.checkId ? String(f.checkId).trim() : 'unknown',
    engine: f.engine ? String(f.engine).trim() : 'unknown',
    engineVersion: typeof f.engineVersion === 'string' ? f.engineVersion.trim() : null,
    signatureVersion: typeof f.signatureVersion === 'string' ? f.signatureVersion.trim() : null,
    outcome: f.outcome || 'INFO',
    reasonCode: f.reasonCode ? String(f.reasonCode).trim() : 'UNKNOWN',
    severity,
    confidence,
    scannedStorageVersionId,
    scannedSha256: canonicalSha,
    scannedSizeBytes: size,
    durationMs,
    evidence,
  };
}

/**
 * Deterministically sort findings by severity (descending), confidence (descending), and checkId (ascending).
 */
function sortFindings(findings: readonly NormalizedFinding[]): NormalizedFinding[] {
  return [...findings].sort((a, b) => {
    const sDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sDiff !== 0) return sDiff;
    const cDiff = CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence];
    if (cDiff !== 0) return cDiff;
    return a.checkId.localeCompare(b.checkId);
  });
}

/**
 * Pure, deterministic decision engine implementing Rules R1–R7 with R2/R3 precedence.
 *
 * @param policy Evaluated security policy
 * @param fileVersion Immutable file version artifact identity
 * @param findings Collection of scanner findings
 * @returns Deterministic, explainable DecisionResult
 */
export function decide(
  policy: DecisionPolicyInput,
  fileVersion: FileVersionIdentityInput,
  findings: readonly FindingInput[],
): DecisionResult {
  const normIdentity = normalizeIdentity(fileVersion);

  const fallbackBucket = typeof fileVersion?.bucket === 'string' ? fileVersion.bucket : 'unknown';
  const rawFallbackKey = fileVersion?.objectKey ?? fileVersion?.object_key;
  const fallbackKey = typeof rawFallbackKey === 'string' ? rawFallbackKey : 'unknown';
  const rawFallbackVersion = fileVersion?.storageVersionId ?? fileVersion?.storage_version_id;
  const fallbackVersion = typeof rawFallbackVersion === 'string' ? rawFallbackVersion : 'unknown';
  const rawFallbackSha = fileVersion?.sha256 ?? fileVersion?.sha256_ingest;
  const fallbackSha = typeof rawFallbackSha === 'string' ? rawFallbackSha : '0'.repeat(64);
  const fallbackSize = 0;

  // Step 0: If artifact identity itself is invalid or missing, immediately fail closed with BLOCK on R1
  if (!normIdentity) {
    const nowIso = new Date().toISOString();
    const invalidRecord: DecisionRecordV1 = {
      schema: DECISION_RECORD_SCHEMA,
      decision: 'BLOCK',
      rule: 'R1',
      primaryReason: 'RESULT_IDENTITY_MISMATCH',
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      riskScore: 100,
      riskThreshold: policy?.riskThreshold ?? 50,
      policy: {
        id: policy?.id ?? '00000000-0000-0000-0000-000000000000',
        name: policy?.name ?? 'unknown',
        version: policy?.version ?? 1,
        sha256: policy?.sha256 ?? '',
      },
      artifactIdentity: {
        bucket: fallbackBucket,
        objectKey: fallbackKey,
        versionId: fallbackVersion,
        sha256: fallbackSha,
        sizeBytes: fallbackSize,
      },
      resultsSummary: {
        policyResult: 'FAIL',
        scannerResult: 'FAIL',
        integrityResult: 'FAIL',
        authorizationResult: 'PASS',
      },
      findingReferences: [],
      reasons: ['RESULT_IDENTITY_MISMATCH'],
      ruleTrace: ['R1: FAIL (invalid fileVersion artifact identity)'],
      engineVersion: ENGINE_VERSION,
      decidedAt: nowIso,
      decidedBy: 'engine',
    };

    return {
      decision: 'BLOCK',
      primaryReason: 'RESULT_IDENTITY_MISMATCH',
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      riskScore: 100,
      rule: 'R1',
      policyResult: 'FAIL',
      scannerResult: 'FAIL',
      integrityResult: 'FAIL',
      authorizationResult: 'PASS',
      boundBucket: fallbackBucket,
      boundKey: fallbackKey,
      boundStorageVersionId: fallbackVersion,
      boundSha256: fallbackSha,
      boundSize: fallbackSize,
      record: invalidRecord,
      engineVersion: ENGINE_VERSION,
      decidedBy: 'engine',
    };
  }

  const validIdentity: NormalizedIdentity = normIdentity;

  const rawFindings = Array.isArray(findings) ? findings : [];
  const normalizedFindings = rawFindings.map(normalizeFinding);
  const sortedFindings = sortFindings(normalizedFindings);

  const findingReferences: FindingReference[] = [...normalizedFindings]
    .sort((a, b) => a.checkId.localeCompare(b.checkId))
    .map((f) => ({
      checkId: f.checkId,
      engine: f.engine,
      outcome: f.outcome,
      reasonCode: f.reasonCode,
      severity: f.severity,
      confidence: f.confidence,
    }));

  const riskThreshold = policy.riskThreshold ?? 50;
  const manualReviewThreshold = policy.manualReviewThreshold ?? 25;

  function buildResult(
    decision: DecisionResult['decision'],
    rule: DecisionResult['rule'],
    primaryReason: string,
    severity: SeverityLevel,
    confidence: ConfidenceLevel,
    riskScore: number,
    policyResult: 'PASS' | 'FAIL',
    scannerResult: ScannerSummaryResult,
    integrityResult: 'PASS' | 'FAIL',
    ruleTrace: string[],
    authorizationResult: 'PASS' | 'FAIL' = 'PASS',
  ): DecisionResult {
    const allReasons = new Set<string>();
    allReasons.add(primaryReason);
    for (const f of normalizedFindings) {
      allReasons.add(f.reasonCode);
    }
    const reasonsSorted = Array.from(allReasons).sort((a, b) => a.localeCompare(b));

    const record: DecisionRecordV1 = {
      schema: DECISION_RECORD_SCHEMA,
      decision,
      rule,
      primaryReason,
      severity,
      confidence,
      riskScore,
      riskThreshold,
      policy: {
        id: policy.id ?? '00000000-0000-0000-0000-000000000000',
        name: policy.name ?? 'unknown',
        version: policy.version ?? 1,
        sha256: policy.sha256 ?? '',
      },
      artifactIdentity: {
        bucket: validIdentity.bucket,
        objectKey: validIdentity.objectKey,
        versionId: validIdentity.storageVersionId,
        sha256: validIdentity.sha256,
        sizeBytes: validIdentity.sizeBytes,
      },
      resultsSummary: {
        policyResult,
        scannerResult,
        integrityResult,
        authorizationResult,
      },
      findingReferences,
      reasons: reasonsSorted,
      ruleTrace,
      engineVersion: ENGINE_VERSION,
      decidedAt: new Date().toISOString(),
      decidedBy: 'engine',
    };

    return {
      decision,
      primaryReason,
      severity,
      confidence,
      riskScore,
      rule,
      policyResult,
      scannerResult,
      integrityResult,
      authorizationResult,
      boundBucket: validIdentity.bucket,
      boundKey: validIdentity.objectKey,
      boundStorageVersionId: validIdentity.storageVersionId,
      boundSha256: validIdentity.sha256,
      boundSize: validIdentity.sizeBytes,
      record,
      engineVersion: ENGINE_VERSION,
      decidedBy: 'engine',
    };
  }

  // =========================================================================
  // RULE R1: Result Identity Verification
  // Scanned hash, storage version ID, and size on findings must equal ingest identity.
  // Mismatch strictly issues BLOCK / RESULT_IDENTITY_MISMATCH per Table 2.3 & T5.
  // =========================================================================
  for (const f of normalizedFindings) {
    const hashMatch = timingSafeSha256Equal(f.scannedSha256, validIdentity.sha256);
    const verMatch = f.scannedStorageVersionId === validIdentity.storageVersionId;
    const sizeMatch = f.scannedSizeBytes === validIdentity.sizeBytes;

    if (!hashMatch || !verMatch || !sizeMatch) {
      return buildResult(
        'BLOCK',
        'R1',
        'RESULT_IDENTITY_MISMATCH',
        'HIGH',
        'CONFIRMED',
        100,
        'FAIL',
        'FAIL',
        'FAIL',
        ['R1: FAIL (finding scanned identity does not match immutable fileVersion identity)'],
      );
    }
  }

  // =========================================================================
  // Evaluate Candidate Conditions for R2 (Errors/Missing), R3 (Threats), R5 (Archive)
  // =========================================================================
  const requiredChecks = policy.requiredChecks ?? [];
  const findingCheckIds = normalizedFindings.map((f) => f.checkId);

  // 1. R2 Missing required checks check
  let r2MissingCheck: string | null = null;
  if (requiredChecks.length > 0 && normalizedFindings.length === 0) {
    r2MissingCheck = requiredChecks[0]!;
  } else {
    for (const req of requiredChecks) {
      if (!isRequiredCheckSatisfied(req, findingCheckIds)) {
        r2MissingCheck = req;
        break;
      }
    }
  }

  // 2. R2 Scanner error check (on required checks or general errors)
  const requiredCheckErrors = normalizedFindings.filter(
    (f) =>
      f.outcome === 'ERROR' &&
      (requiredChecks.length === 0 ||
        requiredChecks.some((req) => isRequiredCheckSatisfied(req, [f.checkId]))),
  );

  const r2Matches = r2MissingCheck !== null || requiredCheckErrors.length > 0;

  // 3. R5 Archive Integrity / Structural Violations (e.g. bomb, slip, corrupt, unsafe path)
  const archiveStructuralFindings = sortedFindings.filter(
    (f) =>
      ARCHIVE_STRUCTURAL_REASONS.has(f.reasonCode) ||
      (f.checkId.startsWith('scanner.archive') &&
        (f.outcome === 'FAIL' || f.severity === 'CRITICAL' || f.severity === 'HIGH')),
  );
  const r5Matches = archiveStructuralFindings.length > 0;

  // 4. R3 Threat Findings check (Malware, YARA matches, Macros, Active content, etc. - excluding purely archive structural ones)
  const threatFindings = sortedFindings.filter(
    (f) =>
      f.outcome === 'FAIL' &&
      (f.severity === 'CRITICAL' || f.severity === 'HIGH') &&
      !ARCHIVE_STRUCTURAL_REASONS.has(f.reasonCode),
  );
  const r3Matches = threatFindings.length > 0;

  // =========================================================================
  // R2 / R3 / R5 PRECEDENCE:
  // Threat detection (R3) and Archive integrity attacks (R5) outrank scanner errors (R2).
  // If an attacker uploads malware or a zip bomb, and a scanner times out on another check,
  // the gateway MUST emit BLOCK (R3 or R5), NOT ERROR (R2).
  // =========================================================================
  if (r3Matches) {
    const primaryThreat = threatFindings[0]!;
    return buildResult(
      'BLOCK',
      'R3',
      primaryThreat.reasonCode,
      primaryThreat.severity,
      primaryThreat.confidence,
      100,
      'FAIL',
      'FAIL',
      'PASS',
      ['R1: PASS', `R3: TRIGGERED (${primaryThreat.reasonCode})`],
    );
  }

  if (r5Matches) {
    const primaryStructural = archiveStructuralFindings[0]!;
    return buildResult(
      'BLOCK',
      'R5',
      primaryStructural.reasonCode,
      primaryStructural.severity,
      primaryStructural.confidence,
      100,
      'FAIL',
      'FAIL',
      'FAIL',
      ['R1: PASS', `R5: TRIGGERED (${primaryStructural.reasonCode})`],
    );
  }

  if (r2Matches) {
    const errorReason =
      r2MissingCheck !== null ? 'REQUIRED_CHECK_MISSING' : requiredCheckErrors[0]!.reasonCode;

    return buildResult(
      'ERROR',
      'R2',
      errorReason,
      'HIGH',
      'CONFIRMED',
      100,
      'FAIL',
      'ERROR',
      'PASS',
      ['R1: PASS', `R2: TRIGGERED (${errorReason})`],
    );
  }

  // =========================================================================
  // RULE R4: Detector Disagreement / Type Undetermined
  // Discrepancy between magic bytes, file extension, and MIME.
  // =========================================================================
  const disagreementFindings = sortedFindings.filter((f) => DISAGREEMENT_REASONS.has(f.reasonCode));

  const disagreementAction = policy.disagreementAction ?? policy.onSuspicious ?? 'QUARANTINE';

  if (disagreementFindings.length > 0 && disagreementAction !== 'FLAG') {
    const primaryDisagreement = disagreementFindings[0]!;
    const score = Math.max(25, calculateRiskScore(rawFindings));
    const dec = disagreementAction === 'BLOCK' ? 'BLOCK' : 'QUARANTINE';
    return buildResult(
      dec,
      'R4',
      primaryDisagreement.reasonCode,
      'MEDIUM',
      primaryDisagreement.confidence,
      score,
      'PASS',
      'SUSPICIOUS',
      'PASS',
      ['R1: PASS', 'R2: PASS', 'R3: PASS', `R4: TRIGGERED (${primaryDisagreement.reasonCode})`],
    );
  }

  // =========================================================================
  // Required CDR Behavior:
  // If policy mandates CDR disarm/reconstruction, verify a passing CDR finding is present.
  // If missing or un-disarmed, fail closed via policy.onSuspicious (default QUARANTINE).
  // =========================================================================
  if (policy.cdrRequired) {
    const hasPassedCdr = normalizedFindings.some(
      (f) =>
        (checkMatches('cdr', f.checkId) || checkMatches('cdr.disarm', f.checkId)) &&
        f.outcome === 'PASS',
    );
    if (!hasPassedCdr) {
      const dec = policy.onSuspicious ?? 'QUARANTINE';
      const score = Math.max(25, calculateRiskScore(rawFindings));
      return buildResult(
        dec,
        'R6',
        'CDR_REQUIRED',
        'MEDIUM',
        'CONFIRMED',
        score,
        'PASS',
        'SUSPICIOUS',
        'PASS',
        [
          'R1: PASS',
          'R2: PASS',
          'R3: PASS',
          'R4: PASS',
          'R5: PASS',
          `R6: TRIGGERED_CDR (${dec} due to cdrRequired without sanitized CDR artifact)`,
        ],
      );
    }
  }

  // =========================================================================
  // RULE R6: Risk Score Threshold & Medium / Suspicious Findings
  // Weighted sum of medium/low findings must remain below policy threshold.
  // =========================================================================
  const computedRiskScore = calculateRiskScore(rawFindings);
  const suspiciousAction = policy.onSuspicious ?? 'QUARANTINE';

  // 1. Hard risk score block
  if (computedRiskScore >= riskThreshold) {
    const primaryFinding = sortedFindings[0]!;
    return buildResult(
      'BLOCK',
      'R6',
      primaryFinding.reasonCode,
      primaryFinding.severity,
      'CONFIRMED',
      computedRiskScore,
      'PASS',
      'FAIL',
      'PASS',
      [
        'R1: PASS',
        'R2: PASS',
        'R3: PASS',
        'R4: PASS',
        'R5: PASS',
        `R6: TRIGGERED_BLOCK (${computedRiskScore} >= ${riskThreshold})`,
      ],
    );
  }

  // 2. Risk score reaches or exceeds manual review threshold
  if (computedRiskScore >= manualReviewThreshold && policy.manualReviewThreshold !== undefined) {
    const primaryFinding = sortedFindings[0]!;
    return buildResult(
      suspiciousAction,
      'R6',
      primaryFinding.reasonCode,
      primaryFinding.severity,
      'HIGH',
      computedRiskScore,
      'PASS',
      'SUSPICIOUS',
      'PASS',
      [
        'R1: PASS',
        'R2: PASS',
        'R3: PASS',
        'R4: PASS',
        'R5: PASS',
        `R6: TRIGGERED_MANUAL_REVIEW (${suspiciousAction} because ${computedRiskScore} >= ${manualReviewThreshold})`,
      ],
    );
  }

  // 3. Explicit suspicious findings or medium-severity warning
  const suspiciousFindings = sortedFindings.filter(
    (f) =>
      f.outcome === 'SUSPICIOUS' ||
      ((f.outcome as string) === 'WARN' && f.severity === 'MEDIUM') ||
      (f.outcome === 'FAIL' && f.severity === 'MEDIUM'),
  );
  if (suspiciousFindings.length > 0) {
    const primarySuspicious = suspiciousFindings[0]!;
    return buildResult(
      suspiciousAction,
      'R6',
      primarySuspicious.reasonCode,
      primarySuspicious.severity,
      primarySuspicious.confidence,
      Math.max(25, computedRiskScore),
      'PASS',
      'SUSPICIOUS',
      'PASS',
      [
        'R1: PASS',
        'R2: PASS',
        'R3: PASS',
        'R4: PASS',
        'R5: PASS',
        `R6: TRIGGERED_SUSPICIOUS (${suspiciousAction} due to ${primarySuspicious.reasonCode})`,
      ],
    );
  }

  // =========================================================================
  // RULE R7: Clean Verification
  // Only if all checks pass cleanly without error or failure is ALLOW emitted.
  // =========================================================================
  return buildResult(
    'ALLOW',
    'R7',
    'ALL_CHECKS_PASSED',
    'INFO',
    'CONFIRMED',
    computedRiskScore,
    'PASS',
    'PASS',
    'PASS',
    ['R1: PASS', 'R2: PASS', 'R3: PASS', 'R4: PASS', 'R5: PASS', 'R6: PASS', 'R7: CLEAN_ALLOW'],
  );
}
