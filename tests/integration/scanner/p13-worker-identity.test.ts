import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type pg from 'pg';
import {
  S3Client,
  HeadBucketCommand,
  CreateBucketCommand,
  PutBucketVersioningCommand,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import { createS3Provider, type StorageProvider } from '@sug/storage';
import { createPool, createBaseFixtures, type FixtureContext } from '../db/helpers.js';
import { ScannerWorker } from '../../../services/scanner/src/worker.js';

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
const S3_QUARANTINE_BUCKET = 'sug-quarantine-local';

describe('Phase P13: Scanner Worker Identity Verification & Execution (DoD Suite)', () => {
  let adminPool: pg.Pool;
  let scannerPool: pg.Pool;
  let fixtures: FixtureContext;
  let rawS3: S3Client;
  let storageProvider: StorageProvider;
  const testTmpDir = path.join(os.tmpdir(), `sug-p13-test-${crypto.randomUUID().slice(0, 8)}`);

  beforeAll(async () => {
    adminPool = createPool('sug_admin', 'sug_dev_password');
    scannerPool = createPool('sug_scanner', 'sug_scanner_dev_password', 10);
    fixtures = await createBaseFixtures(adminPool);

    rawS3 = new S3Client({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'test',
        secretAccessKey: 'test',
      },
      forcePathStyle: true,
    });

    // Ensure S3 bucket exists with versioning enabled
    let s3Ready = false;
    for (let attempt = 0; attempt < 15; attempt++) {
      try {
        try {
          await rawS3.send(new HeadBucketCommand({ Bucket: S3_QUARANTINE_BUCKET }));
        } catch {
          await rawS3.send(new CreateBucketCommand({ Bucket: S3_QUARANTINE_BUCKET }));
        }
        await rawS3.send(
          new PutBucketVersioningCommand({
            Bucket: S3_QUARANTINE_BUCKET,
            VersioningConfiguration: { Status: 'Enabled' },
          }),
        );
        s3Ready = true;
        break;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    if (!s3Ready) {
      throw new Error(`Could not connect to LocalStack S3 emulator at ${S3_ENDPOINT}`);
    }

    storageProvider = createS3Provider({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'test',
        secretAccessKey: 'test',
      },
      forcePathStyle: true,
    });

    await fs.promises.mkdir(testTmpDir, { recursive: true });
  });

  beforeEach(async () => {
    // Clean up unreferenced scan_jobs and ensure any older jobs don't interfere
    await adminPool.query(
      `DELETE FROM scan_jobs WHERE id NOT IN (SELECT scan_job_id FROM scan_results WHERE scan_job_id IS NOT NULL)`,
    );
    await adminPool.query(
      `UPDATE scan_jobs SET status = 'SUCCEEDED', finished_at = now() WHERE status IN ('QUEUED', 'RUNNING')`,
    );
  });

  afterAll(async () => {
    try {
      await fs.promises.rm(testTmpDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
    if (scannerPool) await scannerPool.end();
    if (adminPool) await adminPool.end();
  });

  // Helper to put an object to S3 and return key, versionId, sha256, size
  async function putTestObject(content: Buffer | string, customKey?: string) {
    const key = customKey ?? `quarantine/${fixtures.appId}/${crypto.randomUUID()}/test-file.bin`;
    const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex').toLowerCase();
    const size = buffer.length;

    const putRes = await rawS3.send(
      new PutObjectCommand({
        Bucket: S3_QUARANTINE_BUCKET,
        Key: key,
        Body: buffer,
      }),
    );

    if (!putRes.VersionId) {
      throw new Error('S3 put did not return VersionId');
    }

    return {
      key,
      versionId: putRes.VersionId,
      sha256,
      size,
      buffer,
    };
  }

  // Helper to create file_version and scan_job in DB
  async function createScanJobFixture(params: {
    bucket?: string;
    objectKey: string;
    storageVersionId: string;
    sizeBytes: number;
    sha256Ingest: string;
  }): Promise<{ jobId: string; fileVersionId: string }> {
    const fileVersionId = crypto.randomUUID();
    const jobId = crypto.randomUUID();
    const ingestShaBuffer = Buffer.from(params.sha256Ingest, 'hex');

    await adminPool.query(
      `INSERT INTO file_versions (
         id, file_id, version_no, provider, bucket, object_key, storage_version_id, size_bytes, sha256_ingest
       ) VALUES ($1, $2, (SELECT COALESCE(MAX(version_no), 0) + 1 FROM file_versions WHERE file_id = $2),
                 'aws', $3, $4, $5, $6, $7)`,
      [
        fileVersionId,
        fixtures.fileId,
        params.bucket ?? S3_QUARANTINE_BUCKET,
        params.objectKey,
        params.storageVersionId,
        params.sizeBytes,
        ingestShaBuffer,
      ],
    );

    await adminPool.query(
      `INSERT INTO scan_jobs (id, file_version_id, status, max_attempts, run_after)
       VALUES ($1, $2, 'QUEUED', 3, now() - interval '1 minute')`,
      [jobId, fileVersionId],
    );

    return { jobId, fileVersionId };
  }

  // ============================================================
  // P13-ID-01: End-to-End Worker Processing & Identity Verification
  // ============================================================
  it('P13-ID-01: worker claims job, verifies cryptographic identity, writes finding, and cleans tmpfs', async () => {
    const artifactContent = Buffer.from('PAYLOAD_FOR_P13_IDENTITY_TEST_' + crypto.randomUUID());
    const obj = await putTestObject(artifactContent);

    const { jobId, fileVersionId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();

    expect(job).not.toBeNull();
    expect(job!.id).toBe(jobId);
    expect(result).toBeDefined();
    expect(result!.success).toBe(true);
    expect(result!.verified).toBe(true);
    expect(result!.sha256).toBe(obj.sha256);
    expect(result!.size).toBe(obj.size);

    // Verify DB scan_jobs state
    const jobRow = await adminPool.query(
      `SELECT status, finished_at, locked_by FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(jobRow.rows[0].status).toBe('SUCCEEDED');
    expect(jobRow.rows[0].finished_at).not.toBeNull();
    expect(jobRow.rows[0].locked_by).toBeNull();

    // Verify scan_results contains the canonical placeholder finding
    const resultRow = await adminPool.query(
      `SELECT scan_job_id, file_version_id, check_id, engine, outcome, reason_code,
              scanned_storage_version_id, scanned_sha256, scanned_size, evidence
       FROM scan_results WHERE scan_job_id = $1`,
      [jobId],
    );
    expect(resultRow.rows.length).toBe(1);
    const row = resultRow.rows[0];
    expect(row.file_version_id).toBe(fileVersionId);
    expect(row.engine).toBe('scanner.skeleton');
    expect(row.check_id).toBe('scanner.skeleton');
    expect(row.outcome).toBe('PASS');
    expect(row.reason_code).toBe('IDENTITY_VERIFIED');
    expect(row.scanned_storage_version_id).toBe(obj.versionId);
    expect(row.scanned_sha256.toString('hex').toLowerCase()).toBe(obj.sha256);
    expect(Number(row.scanned_size)).toBe(obj.size);

    // Verify tmpfs cleanup
    const jobDir = path.join(testTmpDir, jobId);
    expect(fs.existsSync(jobDir)).toBe(false);
  });

  // ============================================================
  // P13-ID-02: Overwrite in storage does NOT alter exact version fetch
  // ============================================================
  it('P13-ID-02: overwrite on same key does not affect exact VersionId retrieval', async () => {
    const sharedKey = `quarantine/${fixtures.appId}/${crypto.randomUUID()}/versioned-file.bin`;

    // 1. Put Version 1
    const v1Content = Buffer.from('CONTENT_V1_INITIAL_' + crypto.randomUUID());
    const objV1 = await putTestObject(v1Content, sharedKey);

    // 2. Overwrite with Version 2 on same key
    const v2Content = Buffer.from('CONTENT_V2_OVERWRITTEN_' + crypto.randomUUID());
    const objV2 = await putTestObject(v2Content, sharedKey);

    expect(objV1.versionId).not.toBe(objV2.versionId);
    expect(objV1.sha256).not.toBe(objV2.sha256);

    // 3. Scan job is explicitly bound to Version 1
    const { jobId } = await createScanJobFixture({
      objectKey: sharedKey,
      storageVersionId: objV1.versionId,
      sizeBytes: objV1.size,
      sha256Ingest: objV1.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();

    expect(job).not.toBeNull();
    expect(job!.id).toBe(jobId);
    expect(result!.success).toBe(true);
    expect(result!.verified).toBe(true);
    expect(result!.sha256).toBe(objV1.sha256); // Exactly V1, NOT V2!
    expect(result!.size).toBe(objV1.size);

    // Verify scan_results records V1
    const resultRow = await adminPool.query(
      `SELECT scanned_storage_version_id, scanned_sha256 FROM scan_results WHERE scan_job_id = $1`,
      [jobId],
    );
    expect(resultRow.rows[0].scanned_storage_version_id).toBe(objV1.versionId);
    expect(resultRow.rows[0].scanned_sha256.toString('hex').toLowerCase()).toBe(objV1.sha256);
  });

  // ============================================================
  // P13-ID-03: Cryptographic Identity Mismatch Fails Closed
  // ============================================================
  it('P13-ID-03: cryptographic identity mismatch records FAIL finding and marks job DEAD', async () => {
    const realContent = Buffer.from('REAL_CONTENT_' + crypto.randomUUID());
    const obj = await putTestObject(realContent);

    // Expect a completely different hash in ingest record (tampered/corrupted)
    const tamperedSha = crypto.createHash('sha256').update('DIFFERENT_CONTENT').digest('hex');

    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: tamperedSha,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();

    expect(job).not.toBeNull();
    expect(job!.id).toBe(jobId);
    expect(result!.success).toBe(false);
    expect(result!.verified).toBe(false);
    expect(result!.error).toContain('Cryptographic identity mismatch');

    // Verify job transitioned to DEAD (non-retryable terminal failure)
    const jobRow = await adminPool.query(
      `SELECT status, finished_at, last_error FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(jobRow.rows[0].status).toBe('DEAD');
    expect(jobRow.rows[0].finished_at).not.toBeNull();
    expect(jobRow.rows[0].last_error).toContain('Cryptographic identity mismatch');

    // Verify scan_results records IDENTITY_MISMATCH failure finding
    const resultRow = await adminPool.query(
      `SELECT outcome, reason_code, severity, confidence, scanned_storage_version_id
       FROM scan_results WHERE scan_job_id = $1`,
      [jobId],
    );
    expect(resultRow.rows.length).toBe(1);
    expect(resultRow.rows[0].outcome).toBe('FAIL');
    expect(resultRow.rows[0].reason_code).toBe('IDENTITY_MISMATCH');
    expect(resultRow.rows[0].severity).toBe('CRITICAL');
    expect(resultRow.rows[0].confidence).toBe('CONFIRMED');

    // Working directory cleaned up
    const jobDir = path.join(testTmpDir, jobId);
    expect(fs.existsSync(jobDir)).toBe(false);
  });

  // ============================================================
  // P13-ID-04: Size Mismatch Fails Closed
  // ============================================================
  it('P13-ID-04: artifact size mismatch fails closed and transitions job to DEAD', async () => {
    const realContent = Buffer.from('EXACT_CONTENT_FOR_SIZE_CHECK');
    const obj = await putTestObject(realContent);

    // Provide correct SHA-256 but incorrect size
    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size + 42, // Incorrect size
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();

    expect(job).not.toBeNull();
    expect(result!.success).toBe(false);
    expect(result!.verified).toBe(false);

    const jobRow = await adminPool.query(`SELECT status FROM scan_jobs WHERE id = $1`, [jobId]);
    expect(jobRow.rows[0].status).toBe('DEAD');

    const resultRow = await adminPool.query(
      `SELECT outcome, reason_code FROM scan_results WHERE scan_job_id = $1`,
      [jobId],
    );
    expect(resultRow.rows[0].outcome).toBe('FAIL');
    expect(resultRow.rows[0].reason_code).toBe('IDENTITY_MISMATCH');
  });

  // ============================================================
  // P13-ID-05: Non-existent VersionId in Storage Fails Closed
  // ============================================================
  it('P13-ID-05: non-existent VersionId fails closed without producing clean finding', async () => {
    const dummyKey = `quarantine/${fixtures.appId}/${crypto.randomUUID()}/missing.bin`;
    const dummySha = crypto.createHash('sha256').update('foo').digest('hex');

    const { jobId } = await createScanJobFixture({
      objectKey: dummyKey,
      storageVersionId: 'fake-non-existent-version-id-999',
      sizeBytes: 100,
      sha256Ingest: dummySha,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();

    expect(job).not.toBeNull();
    expect(result!.success).toBe(false);
    expect(result!.verified).toBe(false);

    // No PASS result should be written
    const resultRow = await adminPool.query(
      `SELECT outcome FROM scan_results WHERE scan_job_id = $1`,
      [jobId],
    );
    expect(resultRow.rows.length).toBe(0);

    // Job should be marked DEAD because VersionMissing is non-retryable
    const jobRow = await adminPool.query(`SELECT status, last_error FROM scan_jobs WHERE id = $1`, [
      jobId,
    ]);
    expect(jobRow.rows[0].status).toBe('DEAD');
  });

  // ============================================================
  // P13-ID-06: Graceful Worker Start and Stop
  // ============================================================
  it('P13-ID-06: worker background loop starts, processes, and stops gracefully', async () => {
    const obj = await putTestObject(Buffer.from('ASYNC_WORKER_TEST_' + crypto.randomUUID()));
    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      tempDir: testTmpDir,
      pollIntervalMs: 50,
    });

    worker.start();
    expect(worker.isRunning()).toBe(true);

    // Poll until job is SUCCEEDED (or timeout)
    const deadline = Date.now() + 5000;
    let finished = false;
    while (Date.now() < deadline) {
      const check = await adminPool.query(`SELECT status FROM scan_jobs WHERE id = $1`, [jobId]);
      if (check.rows[0]?.status === 'SUCCEEDED') {
        finished = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }

    expect(finished).toBe(true);

    await worker.stop();
    expect(worker.isRunning()).toBe(false);
  });
});
