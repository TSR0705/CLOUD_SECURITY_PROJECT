/**
 * @sug/decision-engine/types
 * Canonical types and interfaces for the Deterministic Decision Engine (P18).
 */

import type { Buffer } from 'node:buffer';
import type {
  DecisionType,
  FindingOutcome,
  SeverityLevel,
  ConfidenceLevel,
  CanonicalReasonCode,
  CheckId,
} from '@sug/shared';

export type {
  DecisionType,
  FindingOutcome,
  SeverityLevel,
  ConfidenceLevel,
  CanonicalReasonCode,
  CheckId,
};

export type DecisionRule =
  | 'R1' // Result Identity Verification
  | 'R2' // Required Check Completeness & Scanner Failures
  | 'R3' // Critical Finding Check (Malware / Exploit / Bomb)
  | 'R4' // Detector Disagreement / Type Undetermined
  | 'R5' // Archive Integrity & Structural Violations
  | 'R6' // Risk Score Threshold
  | 'R7' // Clean Verification
  | 'HUMAN_REVIEW';

export const DECISION_RECORD_SCHEMA = 'sug.decision/v1' as const;

export interface DecisionPolicyInput {
  readonly id?: string | undefined;
  readonly name?: string | undefined;
  readonly version?: number | undefined;
  readonly sha256?: string | undefined;
  readonly requiredChecks?: readonly string[] | undefined;
  readonly scanRequired?: boolean | undefined;
  readonly onSuspicious?: 'QUARANTINE' | 'BLOCK' | undefined;
  readonly manualReviewThreshold?: number | undefined;
  readonly archiveAllowed?: boolean | undefined;
  readonly riskThreshold?: number | undefined;
  readonly disagreementAction?: 'QUARANTINE' | 'BLOCK' | 'FLAG' | undefined;
}

export interface FileVersionIdentityInput {
  readonly id?: string | undefined;
  readonly fileId?: string | undefined;
  readonly file_id?: string | undefined;
  readonly bucket: string;
  readonly objectKey?: string | undefined;
  readonly object_key?: string | undefined;
  readonly storageVersionId?: string | undefined;
  readonly storage_version_id?: string | undefined;
  readonly sha256?: string | undefined;
  readonly sha256_ingest?: Buffer | string | undefined;
  readonly sizeBytes?: number | bigint | string | undefined;
  readonly size_bytes?: number | bigint | string | undefined;
}

export interface FindingInput {
  readonly id?: string | undefined;
  readonly checkId?: string | undefined;
  readonly check_id?: string | undefined;
  readonly engine: string;
  readonly engineVersion?: string | null | undefined;
  readonly engine_version?: string | null | undefined;
  readonly signatureVersion?: string | null | undefined;
  readonly signature_version?: string | null | undefined;
  readonly outcome: FindingOutcome;
  readonly reasonCode?: string | null | undefined;
  readonly reason_code?: string | null | undefined;
  readonly severity?: SeverityLevel | undefined;
  readonly confidence?: ConfidenceLevel | undefined;
  readonly evidence?: Record<string, unknown> | null | undefined;
  readonly details?: Record<string, unknown> | null | undefined;
  readonly scannedStorageVersionId?: string | undefined;
  readonly scanned_storage_version_id?: string | undefined;
  readonly scannedSha256?: string | Buffer | undefined;
  readonly scanned_sha256?: string | Buffer | undefined;
  readonly scannedSizeBytes?: number | bigint | string | undefined;
  readonly scanned_size?: number | bigint | string | undefined;
  readonly durationMs?: number | null | undefined;
  readonly duration_ms?: number | null | undefined;
}

export interface FindingReference {
  readonly checkId: string;
  readonly engine: string;
  readonly outcome: FindingOutcome;
  readonly reasonCode: string;
  readonly severity: SeverityLevel;
  readonly confidence: ConfidenceLevel;
}

export type ScannerSummaryResult = 'PASS' | 'FAIL' | 'ERROR' | 'SKIPPED' | 'SUSPICIOUS';

export interface DecisionRecordV1 {
  readonly schema: typeof DECISION_RECORD_SCHEMA;
  readonly decision: DecisionType;
  readonly rule: DecisionRule;
  readonly primaryReason: string;
  readonly severity: SeverityLevel;
  readonly confidence: ConfidenceLevel;
  readonly riskScore: number;
  readonly riskThreshold: number;
  readonly policy: {
    readonly id: string;
    readonly name: string;
    readonly version: number;
    readonly sha256: string;
  };
  readonly artifactIdentity: {
    readonly bucket: string;
    readonly objectKey: string;
    readonly versionId: string;
    readonly sha256: string;
    readonly sizeBytes: number;
  };
  readonly resultsSummary: {
    readonly policyResult: 'PASS' | 'FAIL';
    readonly scannerResult: ScannerSummaryResult;
    readonly integrityResult: 'PASS' | 'FAIL';
    readonly authorizationResult: 'PASS' | 'FAIL';
  };
  readonly findingReferences: readonly FindingReference[];
  readonly reasons: readonly string[];
  readonly ruleTrace: readonly string[];
  readonly engineVersion: string;
  readonly decidedAt: string;
  readonly decidedBy: string;
  readonly supersedesId?: string | null | undefined;
  readonly reviewJustification?: string | undefined;
  readonly humanReview?:
    | {
        readonly justification: string;
        readonly reviewer: string;
        readonly reviewerId?: string | undefined;
      }
    | undefined;
}

export interface DecisionResult {
  readonly decision: DecisionType;
  readonly primaryReason: string;
  readonly severity: SeverityLevel;
  readonly confidence: ConfidenceLevel;
  readonly riskScore: number;
  readonly rule: DecisionRule;
  readonly policyResult: 'PASS' | 'FAIL';
  readonly scannerResult: ScannerSummaryResult;
  readonly integrityResult: 'PASS' | 'FAIL';
  readonly authorizationResult: 'PASS' | 'FAIL';
  readonly boundBucket: string;
  readonly boundKey: string;
  readonly boundStorageVersionId: string;
  readonly boundSha256: string;
  readonly boundSize: number;
  readonly record: DecisionRecordV1;
  readonly engineVersion: string;
  readonly decidedBy: string;
}

export type ReviewAction = 'ALLOW' | 'BLOCK';

export interface ReviewRequest {
  readonly action: ReviewAction;
  readonly justification: string;
  readonly reviewer: string;
  readonly reviewerId?: string | undefined;
}

export interface ExistingDecision {
  readonly id: string;
  readonly file_version_id: string;
  readonly scan_job_id: string | null;
  readonly policy_id: string;
  readonly decision: DecisionType;
  readonly primary_reason: string;
  readonly severity: SeverityLevel;
  readonly confidence: ConfidenceLevel;
  readonly risk_score: number;
  readonly policy_result: string;
  readonly scanner_result: string;
  readonly integrity_result: string;
  readonly authorization_result: string;
  readonly bound_bucket: string;
  readonly bound_key: string;
  readonly bound_storage_version_id: string;
  readonly bound_sha256: Buffer | string;
  readonly bound_size: number | bigint | string;
  readonly record: DecisionRecordV1 | Record<string, unknown>;
  readonly engine_version: string;
  readonly decided_by: string;
  readonly supersedes_id: string | null;
  readonly created_at?: Date | string | undefined;
}
