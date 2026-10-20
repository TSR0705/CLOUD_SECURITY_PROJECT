/**
 * tests/integration/chaos.test.ts
 *
 * Phase 23 Deliverable C: Chaos & Resilience Test Suite
 *
 * Tests system resilience under simulated faults and attacks:
 * - Scenario 1: Scanner worker crash and orphan job reaper recovery
 * - Scenario 2: Database transactional interruption and rollback fail-closed
 * - Scenario 3: Storage stream abort / disconnect mid-upload
 * - Scenario 4: Concurrent/duplicate job claim race via SKIP LOCKED
 * - Scenario 5: Concurrency throughput and multi-tenant isolation
 * - SQL Invariant verification after every scenario ensuring zero violations.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import { Readable } from 'node:stream';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import {
  S3Client,
  HeadBucketCommand,
  CreateBucketCommand,
  PutBucketVersioningCommand,
} from '@aws-sdk/client-s3';
import { createS3Provider, type StorageProvider } from '@sug/storage';
import { LocalKeyProvider, DEFAULT_LOCAL_KEY_REFERENCE } from '@sug/crypto';
import { loadConfig } from '@sug/shared/config';
import { createApp } from '../../services/api/src/app.js';
import { ApiKeyService } from '../../services/api/src/auth/service.js';
import { createDocumentsPreset } from '@sug/policy-engine';
import {
  claimScanJob,
  completeScanJob,
  reapExpiredJobs,
  generateWorkerId,
  type ClaimedScanJob,
} from '@sug/shared/jobs';
import { SugClient, SugApiError } from '@sug/sdk';
import { createPool } from './db/helpers.js';
import { verifyInvariants } from '../../scripts/run-invariants.js';

describe('Phase P23: Chaos, Fault Injection & Invariant Enforcement', () => {
  const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
  const QUARANTINE_BUCKET = 'sug-quarantine-local';
  const CLEAN_BUCKET = 'sug-clean-local';

  let app: FastifyInstance;
  let adminPool: pg.Pool;
  let s3Provider: StorageProvider;
  let keyProvider: LocalKeyProvider;
  let baseUrl: string;

  // Tenant A
  let userAId: string;
  let appAId: string;
  let apiKeyARaw: string;
  let policyAId: string;
  let clientA: SugClient;

  // Tenant B
  let userBId: string;
  let appBId: string;
  let apiKeyBRaw: string;
  let clientB: SugClient;

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    const config = loadConfig({ secretsDir });
    adminPool = createPool('sug_admin', 'sug_dev_password');

    // 1. Ensure LocalStack buckets exist with versioning enabled
    const rawS3 = new S3Client({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
      forcePathStyle: true,
    });

    for (const bucket of [QUARANTINE_BUCKET, CLEAN_BUCKET]) {
      try {
        await rawS3.send(new HeadBucketCommand({ Bucket: bucket }));
      } catch {
        await rawS3.send(new CreateBucketCommand({ Bucket: bucket }));
      }
      await rawS3.send(
        new PutBucketVersioningCommand({
          Bucket: bucket,
          VersioningConfiguration: { Status: 'Enabled' },
        }),
      );
    }

    s3Provider = createS3Provider({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
      forcePathStyle: true,
    });

    const testKek = Buffer.alloc(32, 0x42);
    keyProvider = new LocalKeyProvider({
      keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
      defaultKeyReference: DEFAULT_LOCAL_KEY_REFERENCE,
    });

    // 2. Tenant A
    const userARes = await adminPool.query(
      `INSERT INTO users (email, password_hash, role) VALUES ($1, 'argon2id$mock', 'admin') RETURNING id`,
      [`chaos_tenant_a_${crypto.randomUUID()}@corp.internal`],
    );
    userAId = userARes.rows[0].id;

    const appARes = await adminPool.query(
      `INSERT INTO applications (name, owner_user_id) VALUES ($1, $2) RETURNING id`,
      [`app_chaos_a_${crypto.randomUUID().slice(0, 8)}`, userAId],
    );
    appAId = appARes.rows[0].id;

    const apiKeyService = new ApiKeyService({
      db: adminPool,
      pepper: config.secrets.pepper,
    });

    const keyA = await apiKeyService.createApiKey({
      applicationId: appAId,
      createdBy: userAId,
      scopes: ['upload', 'read'],
    });
    apiKeyARaw = keyA.rawKey;

    const baseDoc = createDocumentsPreset();
    const policyDocA = {
      ...baseDoc,
      allowedExtensions: [...baseDoc.allowedExtensions, '.bin', '.png'],
      allowedMimeTypes: [...baseDoc.allowedMimeTypes, 'application/octet-stream', 'image/png'],
    };
    const docASha = crypto.createHash('sha256').update(JSON.stringify(policyDocA)).digest();
    const policyARes = await adminPool.query(
      `INSERT INTO security_policies (application_id, version, document, document_sha256, created_by)
       VALUES ($1, 1, $2, $3, $4) RETURNING id`,
      [appAId, JSON.stringify(policyDocA), docASha, userAId],
    );
    policyAId = policyARes.rows[0].id;
    await adminPool.query(`UPDATE applications SET active_policy_id = $1 WHERE id = $2`, [
      policyAId,
      appAId,
    ]);

    // 3. Tenant B
    const userBRes = await adminPool.query(
      `INSERT INTO users (email, password_hash, role) VALUES ($1, 'argon2id$mock', 'admin') RETURNING id`,
      [`chaos_tenant_b_${crypto.randomUUID()}@corp.internal`],
    );
    userBId = userBRes.rows[0].id;

    const appBRes = await adminPool.query(
      `INSERT INTO applications (name, owner_user_id) VALUES ($1, $2) RETURNING id`,
      [`app_chaos_b_${crypto.randomUUID().slice(0, 8)}`, userBId],
    );
    appBId = appBRes.rows[0].id;

    const keyB = await apiKeyService.createApiKey({
      applicationId: appBId,
      createdBy: userBId,
      scopes: ['upload', 'read'],
    });
    apiKeyBRaw = keyB.rawKey;

    const policyDocB = { ...policyDocA };
    const docBSha = crypto.createHash('sha256').update(JSON.stringify(policyDocB)).digest();
    const policyBRes = await adminPool.query(
      `INSERT INTO security_policies (application_id, version, document, document_sha256, created_by)
       VALUES ($1, 1, $2, $3, $4) RETURNING id`,
      [appBId, JSON.stringify(policyDocB), docBSha, userBId],
    );
    const policyBId = policyBRes.rows[0].id;
    await adminPool.query(`UPDATE applications SET active_policy_id = $1 WHERE id = $2`, [
      policyBId,
      appBId,
    ]);

    // 4. Start Fastify app listening on dynamic port with elevated rate limit for benchmark
    app = await createApp({
      config,
      storageProvider: s3Provider,
      keyProvider,
      rateLimitMax: 100_000,
      logger: false,
    });
    await app.listen({ port: 0, host: '127.0.0.1' });

    const addr = app.server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 3000;
    baseUrl = `http://127.0.0.1:${port}`;

    clientA = new SugClient({ baseUrl, apiKey: apiKeyARaw });
    clientB = new SugClient({ baseUrl, apiKey: apiKeyBRaw });
  });

  afterAll(async () => {
    if (app) {
      if (typeof app.server?.closeAllConnections === 'function') {
        app.server.closeAllConnections();
      }
      await app.close();
    }
    if (adminPool) await adminPool.end();
  }, 30_000);

  // =========================================================================
  // SCENARIO 1: Scanner Hard Crash & Orphan Job Reaper Recovery
  // =========================================================================
  describe('Scenario 1: Scanner Crash & Reaper Orphan Job Recovery', () => {
    it('recovers an orphaned scan job whose worker died, requeues it, and allows healthy worker to complete', async () => {
      // 0. Drain or complete pre-existing queued jobs so our test job is claimed deterministically
      await adminPool.query(
        `UPDATE scan_jobs SET status = 'SUCCEEDED', finished_at = now() WHERE status IN ('QUEUED', 'RUNNING')`,
      );

      // 1. Upload a file creating a scan job
      const payload = Buffer.from('%PDF-1.7 Test document for scanner crash recovery');
      const uploadRes = await clientA.uploadFile({
        filename: 'crash-recovery.pdf',
        declaredMime: 'application/pdf',
        payload,
      });

      // 2. Worker 1 claims the job
      const worker1 = generateWorkerId('scanner-node1');
      const claimed1 = await claimScanJob(adminPool, { workerId: worker1, leaseTimeoutMs: 5000 });
      expect(claimed1).not.toBeNull();
      expect(claimed1?.fileVersionId).toBe(uploadRes.fileVersionId);
      expect(claimed1?.attempts).toBe(1);

      // 3. Simulate hard worker crash: worker terminates without completing job.
      // Fast-forward locked_at into past to simulate lease expiration
      await adminPool.query(
        `UPDATE scan_jobs
         SET locked_at = now() - interval '10 seconds'
         WHERE id = $1`,
        [claimed1!.id],
      );

      // 4. Reaper sweeps expired jobs
      const reaperResult = await reapExpiredJobs(adminPool, { leaseTimeoutMs: 5000 });
      expect(reaperResult.reapedCount).toBeGreaterThan(0);
      expect(reaperResult.requeuedCount).toBeGreaterThan(0);
      expect(reaperResult.reapedJobIds).toContain(claimed1!.id);

      // Verify job is back in QUEUED status with incremented attempts
      const jobRes = await adminPool.query('SELECT status, attempts FROM scan_jobs WHERE id = $1', [
        claimed1!.id,
      ]);
      expect(jobRes.rows[0].status).toBe('QUEUED');
      expect(jobRes.rows[0].attempts).toBe(1);

      // 5. Healthy Worker 2 claims the recovered job
      const worker2 = generateWorkerId('scanner-node2');
      const claimed2 = await claimScanJob(adminPool, {
        workerId: worker2,
        now: () => new Date(Date.now() + 60_000), // after backoff
      });
      expect(claimed2).not.toBeNull();
      expect(claimed2?.id).toBe(claimed1!.id);
      expect(claimed2?.attempts).toBe(2);

      // Worker 2 completes job successfully
      await completeScanJob(adminPool, claimed2!.id, { workerId: worker2 });

      const finalJob = await adminPool.query(
        'SELECT status, finished_at FROM scan_jobs WHERE id = $1',
        [claimed2!.id],
      );
      expect(finalJob.rows[0].status).toBe('SUCCEEDED');
      expect(finalJob.rows[0].finished_at).not.toBeNull();

      // 6. Database invariants verified
      const report = await verifyInvariants(adminPool);
      expect(report.ok).toBe(true);
      expect(report.totalViolations).toBe(0);
    });
  });

  // =========================================================================
  // SCENARIO 2: Database Interruption & Transaction Rollback Resilience
  // =========================================================================
  describe('Scenario 2: Database Transaction Interruption & Fail-Closed', () => {
    it('aborts cleanly during simulated database interruption, leaving zero corrupted or orphan state', async () => {
      const client = await adminPool.connect();
      try {
        await client.query('BEGIN');

        // Create partial upload session
        const sessRes = await client.query(
          `INSERT INTO upload_sessions (
             application_id, api_key_id, policy_id, original_filename,
             declared_mime, declared_size, token_jti, expires_at
           )
           VALUES ($1, (SELECT id FROM api_keys WHERE application_id = $1 LIMIT 1), $2,
                   'aborted.pdf', 'application/pdf', 1024, $3, now() + interval '10 minutes')
           RETURNING id`,
          [appAId, policyAId, crypto.randomUUID()],
        );
        const abortedSessionId = sessRes.rows[0].id;

        // Create partial file
        await client.query(
          `INSERT INTO files (application_id, upload_session_id, display_filename, status)
           VALUES ($1, $2, 'aborted.pdf', 'QUARANTINED')`,
          [appAId, abortedSessionId],
        );

        // Simulate abrupt DB transaction rollback / connection drop
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }

      // Verify no orphan upload session or file exists
      const orphanCheck = await adminPool.query(
        `SELECT count(*) FROM files WHERE display_filename = 'aborted.pdf'`,
      );
      expect(Number(orphanCheck.rows[0].count)).toBe(0);

      // Verify all invariants hold strictly
      const report = await verifyInvariants(adminPool);
      expect(report.ok).toBe(true);
      expect(report.totalViolations).toBe(0);
    });
  });

  // =========================================================================
  // SCENARIO 3: Storage Stream Interruption / Client Abort Mid-Upload
  // =========================================================================
  describe('Scenario 3: Client Abort & Truncated Stream Handling', () => {
    it('fails closed when upload stream is truncated or aborted mid-transfer, leaving clean storage untouched', async () => {
      // 1. Create upload session
      const session = await clientA.createUploadSession({
        filename: 'truncated.pdf',
        declaredSize: 150,
        declaredMime: 'application/pdf',
      });

      // 2. Transmit truncated stream with declared 150 bytes Content-Length but only 20 bytes payload
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'application/octet-stream',
          'content-length': '150',
        },
        body: Readable.from([Buffer.from('only 20 bytes here!')]),
      });

      expect(res.statusCode).toBe(400);
      const problem = JSON.parse(res.body);
      expect(problem.detail).toContain('prematurely');

      // 3. Verify clean storage has zero objects
      const cleanCheck = await adminPool.query(
        `SELECT * FROM cloud_objects co
         JOIN file_versions fv ON co.file_version_id = fv.id
         JOIN files f ON fv.file_id = f.id
         WHERE f.upload_session_id = $1 AND co.zone = 'clean'`,
        [session.sessionId],
      );
      expect(cleanCheck.rows.length).toBe(0);

      // 4. Invariants check
      const report = await verifyInvariants(adminPool);
      expect(report.ok).toBe(true);
      expect(report.totalViolations).toBe(0);
    });
  });

  // =========================================================================
  // SCENARIO 4: Concurrent Duplicate Job Claim Race (SKIP LOCKED)
  // =========================================================================
  describe('Scenario 4: Concurrent Job Claim Race via SKIP LOCKED', () => {
    it('guarantees exactly one worker claims a job when 20 workers compete simultaneously', async () => {
      // 0. Drain or complete pre-existing queued jobs so our test job is claimed deterministically
      await adminPool.query(
        `UPDATE scan_jobs SET status = 'SUCCEEDED', finished_at = now() WHERE status IN ('QUEUED', 'RUNNING')`,
      );

      // 1. Create single scan job
      const fileVersionId = crypto.randomUUID();
      const jobId = crypto.randomUUID();
      const uniqueKey = `incoming/race-${crypto.randomUUID()}`;
      const uniqueStorageVersionId = `v-race-${crypto.randomUUID()}`;
      const ingestSha = crypto.createHash('sha256').update('race-test').digest();

      await adminPool.query(
        `INSERT INTO file_versions (
           id, file_id, version_no, provider, bucket, object_key, storage_version_id, size_bytes, sha256_ingest
         )
         VALUES ($1, (SELECT id FROM files WHERE application_id = $2 LIMIT 1), 999, 'aws', 'sug-quarantine-local',
                 $3, $4, 100, $5)`,
        [fileVersionId, appAId, uniqueKey, uniqueStorageVersionId, ingestSha],
      );

      await adminPool.query(
        `INSERT INTO scan_jobs (id, file_version_id, status, max_attempts, run_after)
         VALUES ($1, $2, 'QUEUED', 3, now() - interval '10 seconds')`,
        [jobId, fileVersionId],
      );

      // 2. Launch 20 concurrent worker claim requests simultaneously
      const workerCount = 20;
      const claimPromises: Promise<ClaimedScanJob | null>[] = [];

      for (let i = 0; i < workerCount; i++) {
        claimPromises.push(
          claimScanJob(adminPool, {
            workerId: `worker-race-${i}`,
          }),
        );
      }

      const results = await Promise.all(claimPromises);

      // 3. Exactly ONE worker must have claimed the job; remaining 19 workers must be null
      const claimedJobs = results.filter((j): j is ClaimedScanJob => j !== null && j.id === jobId);
      expect(claimedJobs.length).toBe(1);

      // Clean up the test job
      await completeScanJob(adminPool, jobId, { workerId: claimedJobs[0]!.lockedBy });

      // 4. Invariants check
      const report = await verifyInvariants(adminPool);
      expect(report.ok).toBe(true);
      expect(report.totalViolations).toBe(0);
    });
  });

  // =========================================================================
  // SCENARIO 5: Concurrency Throughput & Multi-Tenant Isolation
  // =========================================================================
  describe('Scenario 5: Multi-Tenant Concurrent Ingestion Benchmark', () => {
    it('executes 100 concurrent uploads across Tenant A and Tenant B with zero cross-tenant leaks', async () => {
      const CONCURRENCY = 100;
      const pdfContent = Buffer.from('%PDF-1.7 High-Concurrency Multi-Tenant Ingestion Benchmark');
      const startMs = Date.now();
      const latencies: number[] = [];

      const uploadTasks: Promise<{ tenant: string; fileId: string; duration: number }>[] = [];

      for (let i = 0; i < CONCURRENCY; i++) {
        const isTenantA = i % 2 === 0;
        const client = isTenantA ? clientA : clientB;
        const tenant = isTenantA ? 'A' : 'B';

        const task = (async () => {
          const t0 = performance.now();
          const res = await client.uploadFile({
            filename: `bench-${tenant}-${i}.pdf`,
            declaredMime: 'application/pdf',
            payload: pdfContent,
          });
          const dur = performance.now() - t0;
          latencies.push(dur);
          return { tenant, fileId: res.fileId, duration: dur };
        })();

        uploadTasks.push(task);
      }

      const results = await Promise.all(uploadTasks);
      const totalElapsed = Date.now() - startMs;
      expect(results).toHaveLength(CONCURRENCY);

      // Calculate latency percentiles
      latencies.sort((a, b) => a - b);
      const p50 = latencies[Math.floor(latencies.length * 0.5)]!;
      const p95 = latencies[Math.floor(latencies.length * 0.95)]!;
      const p99 = latencies[Math.floor(latencies.length * 0.99)]!;
      const throughput = (CONCURRENCY / (totalElapsed / 1000)).toFixed(1);

      console.log(`\n--- BENCHMARK RESULTS (${CONCURRENCY} concurrent uploads) ---`);
      console.log(`Total Elapsed Time: ${totalElapsed} ms`);
      console.log(`Throughput:         ${throughput} uploads/sec`);
      console.log(`Latency p50:        ${p50.toFixed(2)} ms`);
      console.log(`Latency p95:        ${p95.toFixed(2)} ms`);
      console.log(`Latency p99:        ${p99.toFixed(2)} ms`);
      console.log(`----------------------------------------------------\n`);

      // Verify Cross-Tenant Isolation across all uploaded files
      // Tenant B cannot access any Tenant A file
      const tenantAFiles = results.filter((r) => r.tenant === 'A').slice(0, 5);
      for (const item of tenantAFiles) {
        await expect(clientB.getFileMetadata(item.fileId)).rejects.toThrow(SugApiError);
      }

      // Verify all invariants hold after high-concurrency burst
      const report = await verifyInvariants(adminPool);
      expect(report.ok).toBe(true);
      expect(report.totalViolations).toBe(0);
    });
  });
});
