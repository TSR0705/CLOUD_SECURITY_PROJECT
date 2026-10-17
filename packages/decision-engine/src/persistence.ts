/**
 * @sug/decision-engine/persistence
 * Database persistence helpers for security decisions.
 */

import { Buffer } from 'node:buffer';
import type { DatabaseExecutor, SecurityDecisions } from '@sug/shared';
import type { DecisionResult } from './types.js';

export interface PersistDecisionParams {
  fileVersionId: string;
  policyId: string;
  scanJobId?: string | null | undefined;
  supersedesId?: string | null | undefined;
}

/**
 * Persists a DecisionResult into the PostgreSQL security_decisions table.
 */
export async function persistDecision(
  db: DatabaseExecutor,
  result: DecisionResult,
  params: PersistDecisionParams,
): Promise<SecurityDecisions> {
  const { fileVersionId, policyId, scanJobId, supersedesId } = params;

  const boundShaBuffer = Buffer.from(result.boundSha256, 'hex');

  const query = `
    INSERT INTO security_decisions (
      file_version_id,
      scan_job_id,
      policy_id,
      decision,
      primary_reason,
      severity,
      confidence,
      risk_score,
      policy_result,
      scanner_result,
      integrity_result,
      authorization_result,
      bound_bucket,
      bound_key,
      bound_storage_version_id,
      bound_sha256,
      bound_size,
      record,
      engine_version,
      decided_by,
      supersedes_id
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
      $11, $12, $13, $14, $15, $16, $17, $18::jsonb, $19, $20, $21
    )
    RETURNING *;
  `;

  const values = [
    fileVersionId,
    scanJobId ?? null,
    policyId,
    result.decision,
    result.primaryReason,
    result.severity,
    result.confidence,
    result.riskScore,
    result.policyResult,
    result.scannerResult,
    result.integrityResult,
    result.authorizationResult,
    result.boundBucket,
    result.boundKey,
    result.boundStorageVersionId,
    boundShaBuffer,
    result.boundSize,
    JSON.stringify(result.record),
    result.engineVersion,
    result.decidedBy,
    supersedesId ?? result.record.supersedesId ?? null,
  ];

  const res = await db.query<SecurityDecisions>(query, values);
  return res.rows[0]!;
}
