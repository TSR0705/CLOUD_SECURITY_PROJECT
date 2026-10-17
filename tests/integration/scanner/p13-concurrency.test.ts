import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import type pg from 'pg';
import { createPool, createBaseFixtures, type FixtureContext } from '../db/helpers.js';
import {
  claimScanJob,
  completeScanJob,
  failScanJob,
  reapExpiredJobs,
  generateWorkerId,
  type ClaimedScanJob,
} from '@sug/shared/jobs';

describe('Phase P13: Job Queue Concurrency, Locking, and Lifecycle (DoD Suite)', () => {
  let adminPool: pg.Pool;
  let scannerPool: pg.Pool;
  let fixtures: FixtureContext;

  beforeAll(async () => {
    adminPool = createPool('sug_admin', 'sug_dev_password');
    scannerPool = createPool('sug_scanner', 'sug_scanner_dev_password', 20);

    fixtures = await createBaseFixtures(adminPool);
  });

  beforeEach(async () => {
    await adminPool.query(
      `DELETE FROM scan_jobs WHERE id NOT IN (SELECT scan_job_id FROM scan_results WHERE scan_job_id IS NOT NULL)`,
    );
    await adminPool.query(
      `UPDATE scan_jobs SET status = 'SUCCEEDED' WHERE status IN ('QUEUED', 'RUNNING')`,
    );
  });

  afterAll(async () => {
    if (scannerPool) await scannerPool.end();
    if (adminPool) await adminPool.end();
  });

  // Helper to create a single file_version and queued scan_job
  async function createScanJobFixture(
    params: {
      maxAttempts?: number;
      runAfter?: Date;
    } = {},
  ): Promise<{ jobId: string; fileVersionId: string }> {
    const fileVersionId = crypto.randomUUID();
    const jobId = crypto.randomUUID();
    const ingestSha = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest();
    const uniqueKey = `incoming/${fixtures.appId}/${crypto.randomUUID()}`;
    const uniqueVersion = `v-${crypto.randomUUID()}`;

    // Insert file_version using admin pool
    await adminPool.query(
      `INSERT INTO file_versions (
         id, file_id, version_no, provider, bucket, object_key, storage_version_id, size_bytes, sha256_ingest
       ) VALUES ($1, $2, (SELECT COALESCE(MAX(version_no), 0) + 1 FROM file_versions WHERE file_id = $2), 'aws', 'sug-quarantine-local', $3, $4, 1024, $5)`,
      [fileVersionId, fixtures.fileId, uniqueKey, uniqueVersion, ingestSha],
    );

    // Insert scan_jobs using admin pool (default run_after in the past so any now() sees it)
    await adminPool.query(
      `INSERT INTO scan_jobs (id, file_version_id, status, max_attempts, run_after)
       VALUES ($1, $2, 'QUEUED', $3, $4)`,
      [
        jobId,
        fileVersionId,
        params.maxAttempts ?? 3,
        params.runAfter ?? new Date('2020-01-01T00:00:00.000Z'),
      ],
    );

    return { jobId, fileVersionId };
  }

  // ============================================================
  // P13-01: 50 Jobs + 4 Concurrent Workers (Canonical DoD)
  // ============================================================
  it('P13-01: 50 jobs claimed concurrently by 4 workers -> 50 unique claims, 0 duplicates', async () => {
    const JOB_COUNT = 50;
    const WORKER_COUNT = 4;

    const createdJobIds: string[] = [];
    for (let i = 0; i < JOB_COUNT; i++) {
      const { jobId } = await createScanJobFixture();
      createdJobIds.push(jobId);
    }

    const createdJobSet = new Set(createdJobIds);

    interface ClaimEvent {
      workerId: string;
      jobId: string;
      timestamp: Date;
    }
    const claims: ClaimEvent[] = [];

    // Worker runners
    const workers = Array.from({ length: WORKER_COUNT }, (_, idx) => {
      const workerId = generateWorkerId(`concurrency-worker-${idx}`);
      return (async () => {
        while (true) {
          const claimed = await claimScanJob(scannerPool, {
            workerId,
            now: () => new Date(),
          });

          if (!claimed) {
            // No more available jobs
            break;
          }

          // If claimed job is one of ours, record it
          if (createdJobSet.has(claimed.id)) {
            claims.push({
              workerId,
              jobId: claimed.id,
              timestamp: claimed.lockedAt,
            });
          }
        }
      })();
    });

    await Promise.all(workers);

    // Verify all 50 jobs were claimed
    expect(claims.length).toBe(JOB_COUNT);

    // Verify ZERO duplicate claims across all jobs
    const claimCounts = new Map<string, number>();
    for (const c of claims) {
      claimCounts.set(c.jobId, (claimCounts.get(c.jobId) ?? 0) + 1);
    }

    for (const jobId of createdJobIds) {
      expect(claimCounts.get(jobId)).toBe(1);
    }

    // Verify every job in database is RUNNING with locked_by set
    const dbRes = await adminPool.query<{
      id: string;
      status: string;
      locked_by: string;
      attempts: number;
    }>(`SELECT id, status, locked_by, attempts FROM scan_jobs WHERE id = ANY($1)`, [createdJobIds]);
    expect(dbRes.rows.length).toBe(JOB_COUNT);
    for (const row of dbRes.rows) {
      expect(row.status).toBe('RUNNING');
      expect(row.locked_by).not.toBeNull();
      expect(row.attempts).toBe(1);
    }
  });

  // ============================================================
  // P13-02: Two workers race for one job -> exactly one winner
  // ============================================================
  it('P13-02: two workers racing for one job -> exactly one winner, one null', async () => {
    const { jobId } = await createScanJobFixture();

    const worker1 = generateWorkerId('race-worker-1');
    const worker2 = generateWorkerId('race-worker-2');

    const [claim1, claim2] = await Promise.all([
      claimScanJob(scannerPool, { workerId: worker1 }),
      claimScanJob(scannerPool, { workerId: worker2 }),
    ]);

    const claimedJobs = [claim1, claim2].filter(
      (c): c is ClaimedScanJob => c !== null && c.id === jobId,
    );

    expect(claimedJobs.length).toBe(1);
    const winner = claimedJobs[0]!;
    expect(winner.id).toBe(jobId);
    expect([worker1, worker2]).toContain(winner.lockedBy);
  });

  // ============================================================
  // P13-03: Worker claims job -> job becomes RUNNING
  // ============================================================
  it('P13-03: worker claims job -> status is RUNNING with locked_by and locked_at', async () => {
    const { jobId } = await createScanJobFixture();
    const workerId = generateWorkerId('test-worker-03');

    const claim = await claimScanJob(scannerPool, { workerId });
    expect(claim).not.toBeNull();
    expect(claim!.id).toBe(jobId);
    expect(claim!.status).toBe('RUNNING');
    expect(claim!.lockedBy).toBe(workerId);
    expect(claim!.attempts).toBe(1);
    expect(claim!.artifact.bucket).toBe('sug-quarantine-local');
    expect(claim!.artifact.storageVersionId).toBeDefined();

    const dbRow = await adminPool.query(
      `SELECT status, locked_by, locked_at, attempts FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(dbRow.rows[0].status).toBe('RUNNING');
    expect(dbRow.rows[0].locked_by).toBe(workerId);
    expect(dbRow.rows[0].attempts).toBe(1);
  });

  // ============================================================
  // P13-04: Worker finishes successfully -> status becomes SUCCEEDED
  // ============================================================
  it('P13-04: completeScanJob transitions job to terminal SUCCEEDED state', async () => {
    const { jobId } = await createScanJobFixture();
    const workerId = generateWorkerId('test-worker-04');

    await claimScanJob(scannerPool, { workerId });
    const completed = await completeScanJob(scannerPool, jobId, { workerId });
    expect(completed).toBe(true);

    const dbRow = await adminPool.query(
      `SELECT status, finished_at, locked_by, locked_at FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(dbRow.rows[0].status).toBe('SUCCEEDED');
    expect(dbRow.rows[0].finished_at).not.toBeNull();
    expect(dbRow.rows[0].locked_by).toBeNull();
    expect(dbRow.rows[0].locked_at).toBeNull();
  });

  // ============================================================
  // P13-05: Worker fails retryable -> job becomes QUEUED with backoff
  // ============================================================
  it('P13-05: failScanJob with retryable=true re-queues job with backoff', async () => {
    const { jobId } = await createScanJobFixture({ maxAttempts: 3 });
    const workerId = generateWorkerId('test-worker-05');

    const claim = await claimScanJob(scannerPool, { workerId });
    expect(claim).not.toBeNull();

    const fakeNow = new Date('2026-09-29T12:00:00.000Z');
    const result = await failScanJob(scannerPool, jobId, {
      workerId,
      error: new Error('Temporary network glitch'),
      retryable: true,
      backoffMs: 5000,
      now: () => fakeNow,
    });

    expect(result).not.toBeNull();
    expect(result!.status).toBe('QUEUED');
    expect(result!.attempts).toBe(1);

    const dbRow = await adminPool.query(
      `SELECT status, run_after, locked_by, locked_at, last_error FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(dbRow.rows[0].status).toBe('QUEUED');
    expect(new Date(dbRow.rows[0].run_after).getTime()).toBe(fakeNow.getTime() + 5000);
    expect(dbRow.rows[0].locked_by).toBeNull();
    expect(dbRow.rows[0].last_error).toBe('Temporary network glitch');
  });

  // ============================================================
  // P13-06: Worker exceeds max attempts -> status becomes DEAD
  // ============================================================
  it('P13-06: exhausting max_attempts transitions job to DEAD', async () => {
    // maxAttempts: 1
    const { jobId } = await createScanJobFixture({ maxAttempts: 1 });
    const workerId = generateWorkerId('test-worker-06');

    await claimScanJob(scannerPool, { workerId });

    const result = await failScanJob(scannerPool, jobId, {
      workerId,
      error: new Error('Exhausted error'),
      retryable: true,
    });

    expect(result).not.toBeNull();
    expect(result!.status).toBe('DEAD');

    const dbRow = await adminPool.query(
      `SELECT status, finished_at, locked_by FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(dbRow.rows[0].status).toBe('DEAD');
    expect(dbRow.rows[0].finished_at).not.toBeNull();
  });

  // ============================================================
  // P13-07 & P13-08: Killed worker -> reaper requeues within 5-minute bound -> second worker claims
  // ============================================================
  it('P13-07 & P13-08: killed worker orphaned job is recovered by reaper within 5-minute canonical bound and claimed by worker B', async () => {
    const { jobId } = await createScanJobFixture({ maxAttempts: 3 });
    const workerA = generateWorkerId('worker-A-killed');
    const workerB = generateWorkerId('worker-B-survivor');
    const TEST_LEASE_MS = 200; // Test lease duration: 200 ms (Production default: 300,000 ms / 5 minutes)

    // T1: Worker A claims the job
    const t1 = new Date();
    const claimA = await claimScanJob(scannerPool, {
      workerId: workerA,
      leaseTimeoutMs: TEST_LEASE_MS,
    });
    expect(claimA).not.toBeNull();
    expect(claimA!.id).toBe(jobId);
    expect(claimA!.status).toBe('RUNNING');
    expect(claimA!.lockedBy).toBe(workerA);

    // T2: Worker A abruptly terminates (simulated crash / SIGKILL - no release, no complete)
    const t2 = new Date();

    // Verify before lease expiry: reaper does NOT touch the job
    const earlyReap = await reapExpiredJobs(scannerPool, {
      leaseTimeoutMs: TEST_LEASE_MS,
    });
    expect(earlyReap.reapedJobIds).not.toContain(jobId);

    // Wait for lease to expire (> TEST_LEASE_MS)
    await new Promise((resolve) => setTimeout(resolve, TEST_LEASE_MS + 50));
    const t3 = new Date(claimA!.lockedAt.getTime() + TEST_LEASE_MS);

    // T4: Reaper runs and detects/requeues the expired job
    const reapResult = await reapExpiredJobs(scannerPool, {
      leaseTimeoutMs: TEST_LEASE_MS,
      baseBackoffMs: 0, // ready immediately for secondary worker
    });
    const t4 = new Date();
    expect(reapResult.reapedJobIds).toContain(jobId);
    expect(reapResult.requeuedCount).toBeGreaterThanOrEqual(1);

    // Calculate requeue latency
    const requeueTimeMs = t4.getTime() - t2.getTime();

    // Verify DB state
    const dbRow = await adminPool.query(
      `SELECT status, locked_by, last_error FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(dbRow.rows[0].status).toBe('QUEUED');
    expect(dbRow.rows[0].locked_by).toBeNull();
    expect(dbRow.rows[0].last_error).toContain('Lease expired');

    // T5: Worker B claims the recovered job
    const claimB = await claimScanJob(scannerPool, {
      workerId: workerB,
    });
    const t5 = new Date();
    expect(claimB).not.toBeNull();
    expect(claimB!.id).toBe(jobId);
    expect(claimB!.lockedBy).toBe(workerB);
    expect(claimB!.attempts).toBe(2); // Attempt incremented

    const recoveryTimeMs = t5.getTime() - t2.getTime();

    // Assert canonical 5-minute requirement (300,000 ms)
    const CANONICAL_MAX_RECOVERY_MS = 300_000;
    expect(requeueTimeMs).toBeLessThan(CANONICAL_MAX_RECOVERY_MS);
    expect(recoveryTimeMs).toBeLessThan(CANONICAL_MAX_RECOVERY_MS);
    expect(requeueTimeMs).toBeGreaterThan(0);

    // Log actual measured timing evidence for documentation and report
    console.log(
      JSON.stringify(
        {
          metric: 'P13_KILLED_WORKER_RECOVERY_TIMING',
          t1_workerClaimed: t1.toISOString(),
          t2_workerTerminated: t2.toISOString(),
          t3_leaseExpired: t3.toISOString(),
          t4_reaperRequeued: t4.toISOString(),
          t5_workerBClaimed: t5.toISOString(),
          requeueTimeMs,
          recoveryTimeMs,
          canonicalMaxMs: CANONICAL_MAX_RECOVERY_MS,
          status: 'PASS',
        },
        null,
        2,
      ),
    );
  });

  // ============================================================
  // P13-09: Already completed job (SUCCEEDED) cannot be claimed
  // ============================================================
  it('P13-09: already completed job (SUCCEEDED) cannot be claimed', async () => {
    const { jobId } = await createScanJobFixture();
    const worker1 = generateWorkerId('worker-09a');
    const worker2 = generateWorkerId('worker-09b');

    const claimed1 = await claimScanJob(scannerPool, { workerId: worker1 });
    expect(claimed1).not.toBeNull();
    expect(claimed1!.id).toBe(jobId);

    const completed = await completeScanJob(scannerPool, jobId);
    expect(completed).toBe(true);

    const dbRow = await adminPool.query(`SELECT status FROM scan_jobs WHERE id = $1`, [jobId]);
    expect(dbRow.rows[0].status).toBe('SUCCEEDED');

    // Set run_after to past to ensure it's not time-blocked
    await adminPool.query(
      `UPDATE scan_jobs SET run_after = now() - interval '1 hour' WHERE id = $1`,
      [jobId],
    );

    const claimAgain = await claimScanJob(scannerPool, { workerId: worker2 });
    expect(claimAgain).toBeNull();
  });

  // ============================================================
  // P13-10: DEAD job cannot be claimed by normal workers
  // ============================================================
  it('P13-10: DEAD job cannot be claimed by normal workers', async () => {
    const { jobId } = await createScanJobFixture({ maxAttempts: 1 });
    const worker1 = generateWorkerId('worker-10a');
    const worker2 = generateWorkerId('worker-10b');

    const claimed1 = await claimScanJob(scannerPool, { workerId: worker1 });
    expect(claimed1).not.toBeNull();
    expect(claimed1!.id).toBe(jobId);

    const failResult = await failScanJob(scannerPool, jobId, {
      workerId: worker1,
      error: new Error('Terminal failure'),
      retryable: false,
    });
    expect(failResult).not.toBeNull();
    expect(failResult!.status).toBe('DEAD');

    const dbRow = await adminPool.query(`SELECT status FROM scan_jobs WHERE id = $1`, [jobId]);
    expect(dbRow.rows[0].status).toBe('DEAD');

    await adminPool.query(
      `UPDATE scan_jobs SET run_after = now() - interval '1 hour' WHERE id = $1`,
      [jobId],
    );

    const claimAgain = await claimScanJob(scannerPool, { workerId: worker2 });
    expect(claimAgain).toBeNull();
  });
});
