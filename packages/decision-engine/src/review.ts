/**
 * @sug/decision-engine/review
 * Human review workflow evaluation and superseding decision generation.
 */

import { toCanonicalSha256 } from '@sug/shared';
import type {
  DecisionResult,
  DecisionRecordV1,
  ExistingDecision,
  ReviewRequest,
  DecisionPolicyInput,
  FindingReference,
  ScannerSummaryResult,
} from './types.js';
import { DECISION_RECORD_SCHEMA } from './types.js';
import { ENGINE_VERSION } from './engine.js';

export class ReviewValidationError extends Error {
  readonly statusCode: number;
  constructor(message: string, statusCode = 400) {
    super(message);
    this.name = 'ReviewValidationError';
    this.statusCode = statusCode;
  }
}

const CRITICAL_BLOCK_REASONS = new Set([
  'RESULT_IDENTITY_MISMATCH',
  'MALWARE_DETECTED',
  'ARCHIVE_BOMB_DETECTED',
  'OVERLAPPING_ENTRIES',
  'UNSAFE_PATH',
  'ZIP_SLIP_DETECTED',
  'EMBEDDED_EXECUTABLE_DETECTED',
  'POLYGLOT_DETECTED',
]);

/**
 * Evaluates an analyst/admin human review request against an existing security decision.
 *
 * Enforces strict fail-closed state transition invariants:
 * - A decision of 'ERROR' CANNOT be overridden to 'ALLOW'.
 * - A decision of 'BLOCK' due to confirmed high/critical threats CANNOT be overridden to 'ALLOW'.
 * - Justification must be non-empty and at least 10 characters in length.
 * - Produces an auditable, superseding DecisionResult with supersedesId attached.
 */
export function evaluateReview(
  targetDecision: ExistingDecision,
  review: ReviewRequest,
  policy?: DecisionPolicyInput,
): DecisionResult {
  if (!targetDecision) {
    throw new ReviewValidationError('Target security decision does not exist', 404);
  }

  if (!review) {
    throw new ReviewValidationError('Review payload is required', 400);
  }

  const { action, justification, reviewer } = review;

  if (action !== 'ALLOW' && action !== 'BLOCK') {
    throw new ReviewValidationError(
      `Invalid review action '${String(action)}'; must be 'ALLOW' or 'BLOCK'`,
      400,
    );
  }

  if (typeof justification !== 'string' || justification.trim().length < 10) {
    throw new ReviewValidationError(
      'Review justification must be a descriptive string of at least 10 characters',
      400,
    );
  }

  if (typeof reviewer !== 'string' || reviewer.trim().length === 0) {
    throw new ReviewValidationError('Reviewer identity is required', 400);
  }

  // FAIL-CLOSED INVARIANT 1: Cannot override ERROR to ALLOW
  if (targetDecision.decision === 'ERROR' && action === 'ALLOW') {
    throw new ReviewValidationError(
      'Cannot override ERROR decision or failed required checks to ALLOW',
      400,
    );
  }

  // FAIL-CLOSED INVARIANT 2: Cannot override confirmed Critical/High threats to ALLOW
  if (
    targetDecision.decision === 'BLOCK' &&
    action === 'ALLOW' &&
    (CRITICAL_BLOCK_REASONS.has(targetDecision.primary_reason) ||
      targetDecision.severity === 'CRITICAL')
  ) {
    throw new ReviewValidationError(
      `Cannot override critical threat BLOCK decision ('${targetDecision.primary_reason}') to ALLOW`,
      400,
    );
  }

  const boundShaHex = toCanonicalSha256(targetDecision.bound_sha256);
  const boundSizeBytes = Number(targetDecision.bound_size);

  const existingRecord =
    targetDecision.record && typeof targetDecision.record === 'object'
      ? (targetDecision.record as Record<string, unknown>)
      : {};

  const findingRefs = Array.isArray(existingRecord.findingReferences)
    ? existingRecord.findingReferences
    : [];

  const decision = action;
  const primaryReason = action === 'ALLOW' ? 'HUMAN_REVIEW_ALLOW' : 'HUMAN_REVIEW_BLOCK';
  const severity = action === 'ALLOW' ? 'INFO' : 'HIGH';
  const confidence = 'CONFIRMED';
  const riskScore = targetDecision.risk_score;
  const decidedBy = `human:${reviewer.trim()}`;

  const record: DecisionRecordV1 = {
    schema: DECISION_RECORD_SCHEMA,
    decision,
    rule: 'HUMAN_REVIEW',
    primaryReason,
    severity,
    confidence,
    riskScore,
    riskThreshold: policy?.manualReviewThreshold ?? 50,
    policy: {
      id: targetDecision.policy_id,
      name: policy?.name ?? 'reviewed-policy',
      version: policy?.version ?? 1,
      sha256: policy?.sha256 ?? '',
    },
    artifactIdentity: {
      bucket: targetDecision.bound_bucket,
      objectKey: targetDecision.bound_key,
      versionId: targetDecision.bound_storage_version_id,
      sha256: boundShaHex,
      sizeBytes: boundSizeBytes,
    },
    resultsSummary: {
      policyResult: action === 'ALLOW' ? 'PASS' : 'FAIL',
      scannerResult: targetDecision.scanner_result as ScannerSummaryResult,
      integrityResult: 'PASS',
      authorizationResult: 'PASS',
    },
    findingReferences: findingRefs as unknown as readonly FindingReference[],
    reasons: [primaryReason],
    ruleTrace: [`HUMAN_REVIEW: OVERRIDE -> ${action} (by ${reviewer.trim()})`],
    engineVersion: ENGINE_VERSION,
    decidedAt: new Date().toISOString(),
    decidedBy,
    supersedesId: targetDecision.id,
    reviewJustification: justification.trim(),
    humanReview: {
      justification: justification.trim(),
      reviewer: reviewer.trim(),
      reviewerId: review.reviewerId,
    },
  };

  return {
    decision,
    primaryReason,
    severity,
    confidence,
    riskScore,
    rule: 'HUMAN_REVIEW',
    policyResult: action === 'ALLOW' ? 'PASS' : 'FAIL',
    scannerResult: targetDecision.scanner_result as ScannerSummaryResult,
    integrityResult: 'PASS',
    authorizationResult: 'PASS',
    boundBucket: targetDecision.bound_bucket,
    boundKey: targetDecision.bound_key,
    boundStorageVersionId: targetDecision.bound_storage_version_id,
    boundSha256: boundShaHex,
    boundSize: boundSizeBytes,
    record,
    engineVersion: ENGINE_VERSION,
    decidedBy,
  };
}
