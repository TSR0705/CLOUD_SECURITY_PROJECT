import crypto from 'node:crypto';
import os from 'node:os';

import type { JobStatus } from './db.js';
export type { JobStatus };

/**
 * Minimal database interface required by job queue operations.
 * Compatible with pg.Pool and pg.PoolClient.
 */
export interface DatabaseExecutor {
  query<T = unknown>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[]; rowCount?: number | null }>;
}

export interface ScanJobRecord {
  id: string;
  fileVersionId: string;
  status: JobStatus;
  attempts: number;
  maxAttempts: number;
  runAfter: Date;
  lockedBy: string | null;
  lockedAt: Date | null;
  lastError: string | null;
  createdAt: Date;
  finishedAt: Date | null;
}

export interface ClaimedJobArtifact {
  bucket: string;
  objectKey: string;
  storageVersionId: string;
  sizeBytes: number;
  sha256Ingest: string;
}

export interface ClaimedScanJob {
  id: string;
  fileVersionId: string;
  status: 'RUNNING';
  attempts: number;
  maxAttempts: number;
  runAfter: Date;
  lockedBy: string;
  lockedAt: Date;
  artifact: ClaimedJobArtifact;
}

export interface ClaimOptions {
  workerId: string;
  leaseTimeoutMs?: number;
  now?: () => Date;
}

export interface CompleteOptions {
  workerId?: string;
  now?: () => Date;
}

export interface FailOptions {
  workerId?: string;
  error: Error | string;
  retryable?: boolean;
  backoffMs?: number;
  now?: () => Date;
}

export interface ReaperOptions {
  leaseTimeoutMs?: number;
  batchSize?: number;
  now?: () => Date;
  baseBackoffMs?: number;
  maxBackoffMs?: number;
}

export interface ReaperResult {
  reapedCount: number;
  requeuedCount: number;
  deadCount: number;
  reapedJobIds: string[];
}

/**
 * Generates an informative, unique worker identifier for auditing and lease tracking.
 */
export function generateWorkerId(prefix = 'scanner-worker'): string {
  const host =
    os
      .hostname()
      .replace(/[^a-zA-Z0-9_-]/g, '')
      .slice(0, 16) || 'localhost';
  const pid = process.pid;
  const rand = crypto.randomUUID().slice(0, 8);
  return `${prefix}-${host}-${pid}-${rand}`;
}

/**
 * Deterministic exponential backoff calculation:
 * delay = min(baseMs * 2^(attempt - 1), maxMs)
 */
export function calculateBackoff(
  attempt: number,
  baseMs: number = 1000,
  maxMs: number = 60_000,
): number {
  if (attempt <= 0) return 0;
  const exp = Math.min(attempt - 1, 10);
  const delay = baseMs * Math.pow(2, exp);
  return Math.min(delay, maxMs);
}

/**
 * Atomically claims the next eligible QUEUED scan job using PostgreSQL `FOR UPDATE SKIP LOCKED`.
 *
 * Requirements:
 * - Checks status = 'QUEUED' AND run_after <= now
 * - Transitions row to status = 'RUNNING'
 * - Records workerId in locked_by and timestamp in locked_at
 * - Increments attempts counter
 * - Retrieves bound artifact metadata from file_versions
 * - Returns null if no eligible job is available
 */
export async function claimScanJob(
  db: DatabaseExecutor,
  options: ClaimOptions,
): Promise<ClaimedScanJob | null> {
  const now = options.now ? options.now() : new Date();
  const workerId = options.workerId;

  if (!workerId || !workerId.trim()) {
    throw new Error('Worker ID is required to claim a job');
  }

  const queryText = `
    WITH next_job AS (
      SELECT sj.id, sj.file_version_id
      FROM scan_jobs sj
      WHERE sj.status = 'QUEUED'
        AND sj.run_after <= $1
      ORDER BY sj.run_after ASC, sj.created_at ASC
      LIMIT 1
      FOR UPDATE SKIP LOCKED
    )
    UPDATE scan_jobs
    SET status = 'RUNNING',
        locked_by = $2,
        locked_at = $1,
        attempts = scan_jobs.attempts + 1
    FROM next_job, file_versions fv
    WHERE scan_jobs.id = next_job.id
      AND fv.id = next_job.file_version_id
    RETURNING
      scan_jobs.id,
      scan_jobs.file_version_id,
      scan_jobs.status,
      scan_jobs.attempts,
      scan_jobs.max_attempts,
      scan_jobs.run_after,
      scan_jobs.locked_by,
      scan_jobs.locked_at,
      fv.bucket,
      fv.object_key,
      fv.storage_version_id,
      fv.size_bytes,
      fv.sha256_ingest;
  `;

  const res = await db.query<{
    id: string;
    file_version_id: string;
    status: JobStatus;
    attempts: number;
    max_attempts: number;
    run_after: Date | string;
    locked_by: string;
    locked_at: Date | string;
    bucket: string;
    object_key: string;
    storage_version_id: string;
    size_bytes: string | number;
    sha256_ingest: Buffer | string;
  }>(queryText, [now, workerId]);

  if (res.rows.length === 0) {
    return null;
  }

  const row = res.rows[0]!;

  const sha256Hex = Buffer.isBuffer(row.sha256_ingest)
    ? row.sha256_ingest.toString('hex').toLowerCase()
    : typeof row.sha256_ingest === 'string'
      ? row.sha256_ingest.replace(/^(?:0x|\\x)/i, '').toLowerCase()
      : '';

  return {
    id: row.id,
    fileVersionId: row.file_version_id,
    status: 'RUNNING',
    attempts: Number(row.attempts),
    maxAttempts: Number(row.max_attempts),
    runAfter: new Date(row.run_after),
    lockedBy: row.locked_by,
    lockedAt: new Date(row.locked_at),
    artifact: {
      bucket: row.bucket,
      objectKey: row.object_key,
      storageVersionId: row.storage_version_id,
      sizeBytes: Number(row.size_bytes),
      sha256Ingest: sha256Hex,
    },
  };
}

/**
 * Marks a RUNNING scan job as SUCCEEDED upon successful processing and identity verification.
 */
export async function completeScanJob(
  db: DatabaseExecutor,
  jobId: string,
  options: CompleteOptions = {},
): Promise<boolean> {
  const now = options.now ? options.now() : new Date();

  let sql = `
    UPDATE scan_jobs
    SET status = 'SUCCEEDED',
        finished_at = $2,
        locked_by = NULL,
        locked_at = NULL
    WHERE id = $1 AND status = 'RUNNING'
  `;
  const params: unknown[] = [jobId, now];

  if (options.workerId) {
    sql += ` AND locked_by = $3`;
    params.push(options.workerId);
  }

  const res = await db.query(sql, params);
  return (res.rowCount ?? 0) > 0;
}

/**
 * Fails a RUNNING scan job, transitioning it to:
 * - DEAD: if attempts >= max_attempts or options.retryable is false
 * - QUEUED: with exponential backoff if attempts < max_attempts and retryable is true
 */
export async function failScanJob(
  db: DatabaseExecutor,
  jobId: string,
  options: FailOptions,
): Promise<{ status: 'QUEUED' | 'DEAD'; attempts: number } | null> {
  const now = options.now ? options.now() : new Date();
  const errorMessage =
    options.error instanceof Error ? options.error.message : String(options.error);
  const isRetryable = options.retryable !== false;

  // Retrieve current attempts and max_attempts to compute backoff if retryable
  const checkRes = await db.query<{ attempts: number; max_attempts: number }>(
    `SELECT attempts, max_attempts FROM scan_jobs WHERE id = $1 AND status = 'RUNNING'`,
    [jobId],
  );

  if (checkRes.rows.length === 0) {
    return null;
  }

  const { attempts, max_attempts } = checkRes.rows[0]!;
  const willBeDead = !isRetryable || attempts >= max_attempts;

  let nextRunAfter: Date = now;
  if (!willBeDead) {
    const backoffMs =
      options.backoffMs !== undefined ? options.backoffMs : calculateBackoff(attempts);
    nextRunAfter = new Date(now.getTime() + backoffMs);
  }

  const updateSql = `
    UPDATE scan_jobs
    SET status = $2::job_status,
        finished_at = CASE WHEN $2::job_status = 'DEAD' THEN $3::timestamptz ELSE NULL END,
        run_after = CASE WHEN $2::job_status = 'QUEUED' THEN $4::timestamptz ELSE run_after END,
        locked_by = NULL,
        locked_at = NULL,
        last_error = $5
    WHERE id = $1 AND status = 'RUNNING'
    RETURNING id, status, attempts;
  `;

  const newStatus: JobStatus = willBeDead ? 'DEAD' : 'QUEUED';
  const updateRes = await db.query<{ id: string; status: 'QUEUED' | 'DEAD'; attempts: number }>(
    updateSql,
    [jobId, newStatus, now, nextRunAfter, errorMessage],
  );

  if (updateRes.rows.length === 0) {
    return null;
  }

  return {
    status: updateRes.rows[0]!.status,
    attempts: Number(updateRes.rows[0]!.attempts),
  };
}

/**
 * Scans for abandoned/orphaned RUNNING jobs whose leases have expired (e.g. worker crashed).
 *
 * For each expired job:
 * - If attempts >= max_attempts -> marks as DEAD
 * - If attempts < max_attempts -> requeues as QUEUED with backoff
 *
 * Atomic and concurrent-safe using `FOR UPDATE SKIP LOCKED`.
 */
export async function reapExpiredJobs(
  db: DatabaseExecutor,
  options: ReaperOptions = {},
): Promise<ReaperResult> {
  const now = options.now ? options.now() : new Date();
  const leaseTimeoutMs = options.leaseTimeoutMs ?? 240_000; // 240 seconds (4 minutes) default
  const batchSize = options.batchSize ?? 100;
  const baseBackoffMs = options.baseBackoffMs ?? 1000;
  const maxBackoffMs = options.maxBackoffMs ?? 60_000;

  const cutoff = new Date(now.getTime() - leaseTimeoutMs);

  // Lock up to batchSize expired running jobs
  const selectQuery = `
    SELECT id, attempts, max_attempts
    FROM scan_jobs
    WHERE status = 'RUNNING'
      AND locked_at <= $1
    ORDER BY locked_at ASC
    LIMIT $2
    FOR UPDATE SKIP LOCKED
  `;

  const expiredCandidates = await db.query<{
    id: string;
    attempts: number;
    max_attempts: number;
  }>(selectQuery, [cutoff, batchSize]);

  if (expiredCandidates.rows.length === 0) {
    return {
      reapedCount: 0,
      requeuedCount: 0,
      deadCount: 0,
      reapedJobIds: [],
    };
  }

  const reapedJobIds: string[] = [];
  let requeuedCount = 0;
  let deadCount = 0;

  for (const job of expiredCandidates.rows) {
    const attempts = Number(job.attempts);
    const maxAttempts = Number(job.max_attempts);

    if (attempts >= maxAttempts) {
      await db.query(
        `UPDATE scan_jobs
         SET status = 'DEAD',
             finished_at = $2,
             locked_by = NULL,
             locked_at = NULL,
             last_error = 'Lease expired; max attempts reached'
         WHERE id = $1`,
        [job.id, now],
      );
      deadCount++;
    } else {
      const backoffMs = calculateBackoff(attempts, baseBackoffMs, maxBackoffMs);
      const nextRunAfter = new Date(now.getTime() + backoffMs);

      await db.query(
        `UPDATE scan_jobs
         SET status = 'QUEUED',
             run_after = $2,
             finished_at = NULL,
             locked_by = NULL,
             locked_at = NULL,
             last_error = 'Lease expired; recovered by reaper'
         WHERE id = $1`,
        [job.id, nextRunAfter],
      );
      requeuedCount++;
    }
    reapedJobIds.push(job.id);
  }

  return {
    reapedCount: reapedJobIds.length,
    requeuedCount,
    deadCount,
    reapedJobIds,
  };
}
