/**
 * @sug/tests/integration/scanner/p16-archive.test.ts
 * End-to-end integration tests for Archive Inspection Engine & Scanner Worker (P16).
 *
 * Verifies that the scanner worker claims jobs from PostgreSQL, retrieves exact object
 * versions from S3 (LocalStack), performs two-phase safe archive inspection, and persists
 * deterministic findings in scan_results across canonical security test cases:
 * - arc-01: archive under no-archive policy (archiveAllowed: false -> ARCHIVE_FORBIDDEN)
 * - arc-02: high-ratio ZIP bomb (< 10s, worker RSS < 256 MB)
 * - arc-03: nested ZIP depth 5 (NESTED_ARCHIVE_DEPTH_EXCEEDED)
 * - arc-04: entry count ceiling (ENTRY_COUNT_EXCEEDED)
 * - arc-05: overlapping physical ranges / Fifield bomb (OVERLAPPING_ENTRIES)
 * - arc-06: lying central directory size (SIZE_MISMATCH / CORRUPT_ARCHIVE)
 * - arc-07: Zip Slip traversal (ZIP_SLIP_DETECTED)
 * - arc-08: encrypted archive (ENCRYPTED_ARCHIVE_FORBIDDEN)
 * - arc-09: symlink archive (SYMLINK_FORBIDDEN)
 * - Clean stored ZIP (PASS, CLEAN)
 * - Clean deflated ZIP (PASS, CLEAN)
 * - Clean OOXML container (PASS, CLEAN)
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import pg from 'pg';
import {
  S3Client,
  CreateBucketCommand,
  PutObjectCommand,
  HeadBucketCommand,
  PutBucketVersioningCommand,
} from '@aws-sdk/client-s3';
import { createPool, createBaseFixtures, type FixtureContext } from '../db/helpers.js';
import { createS3Provider, type StorageProvider } from '@sug/storage';
import { ScannerWorker } from '../../../services/scanner/src/worker.js';
import {
  buildZip,
  buildHighRatioZipBombFixture,
  buildOverlappingZipFixture,
  buildCleanDocxFixture,
} from '../../fixtures/archive-builder.js';

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
const S3_QUARANTINE_BUCKET = 'sug-quarantine-local';

describe('Phase P16: Safe ZIP & OOXML Container Inspection Integration', () => {
  let adminPool: pg.Pool;
  let scannerPool: pg.Pool;
  let fixtures: FixtureContext;
  let rawS3: S3Client;
  let storageProvider: StorageProvider;
  const testTmpDir = path.join(os.tmpdir(), `sug-p16-test-${crypto.randomUUID().slice(0, 8)}`);

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
  }, 30000);

  beforeEach(async () => {
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

  // Helper to create full end-to-end upload and scan job fixture
  async function createArchiveJobFixture(params: {
    filename: string;
    mime: string;
    content: Buffer;
    policyDoc?: Record<string, unknown>;
  }) {
    // Create upload session ID and use canonical quarantine key
    const sessionId = crypto.randomUUID();
    const key = `incoming/${fixtures.appId}/${sessionId}`;
    const buffer = params.content;
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

    const versionId = putRes.VersionId;

    // Create policy if custom document supplied
    let policyId = fixtures.policyId;
    if (params.policyDoc) {
      const docStr = JSON.stringify(params.policyDoc);
      const docSha = crypto.createHash('sha256').update(docStr).digest();
      const nextVerRes = await adminPool.query<{ next_ver: number }>(
        `SELECT COALESCE(MAX(version), 0) + 1 AS next_ver FROM security_policies WHERE application_id = $1`,
        [fixtures.appId],
      );
      const nextVer = nextVerRes.rows[0]!.next_ver;

      const polRes = await adminPool.query<{ id: string }>(
        `INSERT INTO security_policies (application_id, version, document, document_sha256, created_by)
         VALUES ($1, $2, $3::jsonb, $4, $5)
         RETURNING id`,
        [fixtures.appId, nextVer, docStr, docSha, fixtures.userId],
      );
      policyId = polRes.rows[0]!.id;
    }

    // Create upload session
    const jti = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 600000);
    await adminPool.query(
      `INSERT INTO upload_sessions (
         id, application_id, api_key_id, policy_id, original_filename, declared_mime,
         declared_size, token_jti, expires_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        sessionId,
        fixtures.appId,
        fixtures.apiKeyId,
        policyId,
        params.filename,
        params.mime,
        size,
        jti,
        expiresAt,
      ],
    );

    // Create file
    const fileId = crypto.randomUUID();
    await adminPool.query(
      `INSERT INTO files (id, application_id, upload_session_id, display_filename)
       VALUES ($1, $2, $3, $4)`,
      [fileId, fixtures.appId, sessionId, params.filename],
    );

    // Create file_version
    const fileVersionId = crypto.randomUUID();
    const ingestShaBuffer = Buffer.from(sha256, 'hex');
    await adminPool.query(
      `INSERT INTO file_versions (
         id, file_id, version_no, provider, bucket, object_key,
         storage_version_id, size_bytes, sha256_ingest
       ) VALUES ($1, $2, 1, 'aws', $3, $4, $5, $6, $7)`,
      [fileVersionId, fileId, S3_QUARANTINE_BUCKET, key, versionId, size, ingestShaBuffer],
    );

    // Create queued scan job ready immediately
    const jobId = crypto.randomUUID();
    await adminPool.query(
      `INSERT INTO scan_jobs (id, file_version_id, status, max_attempts, run_after)
       VALUES ($1, $2, 'QUEUED', 3, now() - interval '5 seconds')`,
      [jobId, fileVersionId],
    );

    return {
      jobId,
      fileVersionId,
      fileId,
      sessionId,
      policyId,
      storageVersionId: versionId,
      sha256,
      size,
    };
  }

  it('arc-01: archive rejected when policy has archiveAllowed: false', async () => {
    const zipBuf = buildZip([{ name: 'document.txt', content: 'Normal file', method: 0 }]);

    const fixture = await createArchiveJobFixture({
      filename: 'package.zip',
      mime: 'application/zip',
      content: zipBuf,
      policyDoc: {
        schema: 'sug.policy/v1',
        name: 'no-archive-policy',
        maxFileSize: 52428800,
        allowedExtensions: ['.pdf'],
        allowedMimeTypes: ['application/pdf'],
        archiveAllowed: false,
      },
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();
    expect(result.job!.id).toBe(fixture.jobId);
    expect(result.result?.success).toBe(true);

    // Verify finding in scan_results
    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
      severity: string;
      confidence: string;
      engine: string;
    }>(
      `SELECT outcome, reason_code, severity, confidence, engine
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    const row = dbRes.rows[0]!;
    expect(row.engine).toBe('yauzl');
    expect(row.outcome).toBe('FAIL');
    expect(row.reason_code).toBe('ARCHIVE_FORBIDDEN');
    expect(row.severity).toBe('HIGH');
    expect(row.confidence).toBe('CONFIRMED');
  });

  it('arc-02 PERFORMANCE GATE: high-ratio ZIP bomb completes in < 10s with worker RSS < 256 MB', async () => {
    const bombBuf = buildHighRatioZipBombFixture();

    const fixture = await createArchiveJobFixture({
      filename: 'ratio-bomb.zip',
      mime: 'application/zip',
      content: bombBuf,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const start = Date.now();
    const result = await worker.runOnce();
    const duration = Date.now() - start;

    expect(result.job).not.toBeNull();
    expect(result.result?.success).toBe(true);
    expect(duration).toBeLessThan(10_000);

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
      severity: string;
      evidence: Record<string, unknown>;
    }>(
      `SELECT outcome, reason_code, severity, evidence
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    const row = dbRes.rows[0]!;
    expect(row.outcome).toBe('FAIL');
    expect([
      'COMPRESSION_RATIO_EXCEEDED',
      'UNCOMPRESSED_SIZE_EXCEEDED',
      'ARCHIVE_BOMB_DETECTED',
    ]).toContain(row.reason_code);
    expect(['HIGH', 'CRITICAL']).toContain(row.severity);
    expect(row.evidence.workerRssBytes).toBeLessThan(268_435_456);
  });

  it('arc-03: nested archive depth > maxDepth is rejected (NESTED_ARCHIVE_DEPTH_EXCEEDED)', async () => {
    // 5 levels of nesting
    let innerZip = buildZip([{ name: 'core.txt', content: 'deep data', method: 8 }]);
    for (let level = 4; level >= 1; level--) {
      innerZip = buildZip([{ name: `level_${level + 1}.zip`, content: innerZip, method: 8 }]);
    }

    const fixture = await createArchiveJobFixture({
      filename: 'nested-depth-5.zip',
      mime: 'application/zip',
      content: innerZip,
      policyDoc: {
        schema: 'sug.policy/v1',
        name: 'archive-maxdepth-3',
        maxFileSize: 52428800,
        allowedExtensions: ['.zip'],
        allowedMimeTypes: ['application/zip'],
        archiveAllowed: true,
        archive: {
          maxCompressedSize: 52428800,
          maxUncompressedSize: 104857600,
          maxEntries: 1000,
          maxDepth: 3, // depth 5 exceeds 3
          maxRatio: 100,
          maxExtractionMs: 10000,
          maxMemoryBytes: 268435456,
        },
      },
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
    }>(
      `SELECT outcome, reason_code
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('FAIL');
    expect(dbRes.rows[0]!.reason_code).toBe('NESTED_ARCHIVE_DEPTH_EXCEEDED');
  });

  it('arc-04: archive exceeding entry count budget is rejected (ENTRY_COUNT_EXCEEDED)', async () => {
    const entries = Array.from({ length: 30 }, (_, i) => ({
      name: `item_${i}.txt`,
      content: `Content ${i}`,
      method: 0,
    }));
    const zipBuf = buildZip(entries);

    const fixture = await createArchiveJobFixture({
      filename: 'many-items.zip',
      mime: 'application/zip',
      content: zipBuf,
      policyDoc: {
        schema: 'sug.policy/v1',
        name: 'archive-maxentries-20',
        maxFileSize: 52428800,
        allowedExtensions: ['.zip'],
        allowedMimeTypes: ['application/zip'],
        archiveAllowed: true,
        archive: {
          maxCompressedSize: 52428800,
          maxUncompressedSize: 104857600,
          maxEntries: 20, // 30 entries exceeds 20
          maxDepth: 3,
          maxRatio: 100,
          maxExtractionMs: 10000,
          maxMemoryBytes: 268435456,
        },
      },
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
    }>(
      `SELECT outcome, reason_code
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('FAIL');
    expect(dbRes.rows[0]!.reason_code).toBe('ENTRY_COUNT_EXCEEDED');
  });

  it('arc-05: overlapping physical entry ranges rejected in Phase 1 (OVERLAPPING_ENTRIES)', async () => {
    const bombBuf = buildOverlappingZipFixture();

    const fixture = await createArchiveJobFixture({
      filename: 'fifield-overlap.zip',
      mime: 'application/zip',
      content: bombBuf,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
      severity: string;
    }>(
      `SELECT outcome, reason_code, severity
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('FAIL');
    expect(dbRes.rows[0]!.reason_code).toBe('OVERLAPPING_ENTRIES');
    expect(dbRes.rows[0]!.severity).toBe('CRITICAL');
  });

  it('arc-06: lying central directory size rejected (SIZE_MISMATCH / CORRUPT_ARCHIVE)', async () => {
    const zipBuf = buildZip([
      {
        name: 'lying.txt',
        content: Buffer.from('Real length is 50 bytes of text and not 5 bytes'),
        method: 8,
        customUncompressedSize: 5,
      },
    ]);

    const fixture = await createArchiveJobFixture({
      filename: 'lying-size.zip',
      mime: 'application/zip',
      content: zipBuf,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
    }>(
      `SELECT outcome, reason_code
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('FAIL');
    expect(['SIZE_MISMATCH', 'CORRUPT_ARCHIVE']).toContain(dbRes.rows[0]!.reason_code);
  });

  it('arc-07: Zip Slip path traversal rejected (ZIP_SLIP_DETECTED)', async () => {
    const zipBuf = buildZip([{ name: '../../etc/shadow', content: 'root:!:...', method: 0 }]);

    const fixture = await createArchiveJobFixture({
      filename: 'zip-slip.zip',
      mime: 'application/zip',
      content: zipBuf,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
      severity: string;
    }>(
      `SELECT outcome, reason_code, severity
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('FAIL');
    expect(dbRes.rows[0]!.reason_code).toBe('ZIP_SLIP_DETECTED');
    expect(dbRes.rows[0]!.severity).toBe('CRITICAL');
  });

  it('arc-08: password encrypted archive rejected (ENCRYPTED_ARCHIVE_FORBIDDEN)', async () => {
    const zipBuf = buildZip([
      { name: 'confidential.txt', content: 'Secret', method: 8, isEncrypted: true },
    ]);

    const fixture = await createArchiveJobFixture({
      filename: 'encrypted.zip',
      mime: 'application/zip',
      content: zipBuf,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
    }>(
      `SELECT outcome, reason_code
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('FAIL');
    expect(dbRes.rows[0]!.reason_code).toBe('ENCRYPTED_ARCHIVE_FORBIDDEN');
  });

  it('arc-09: symlink entry in archive rejected (SYMLINK_FORBIDDEN)', async () => {
    const zipBuf = buildZip([
      { name: 'symlink_to_etc', content: '/etc/passwd', method: 0, isSymlink: true },
    ]);

    const fixture = await createArchiveJobFixture({
      filename: 'symlink.zip',
      mime: 'application/zip',
      content: zipBuf,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
    }>(
      `SELECT outcome, reason_code
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('FAIL');
    expect(dbRes.rows[0]!.reason_code).toBe('SYMLINK_FORBIDDEN');
  });

  it('passes clean stored ZIP (PASS, CLEAN)', async () => {
    const zipBuf = buildZip([{ name: 'notes.txt', content: 'Meeting notes 2026', method: 0 }]);

    const fixture = await createArchiveJobFixture({
      filename: 'notes.zip',
      mime: 'application/zip',
      content: zipBuf,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();
    expect(result.result?.success).toBe(true);

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
      severity: string;
    }>(
      `SELECT outcome, reason_code, severity
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('PASS');
    expect(dbRes.rows[0]!.reason_code).toBe('CLEAN');
    expect(dbRes.rows[0]!.severity).toBe('INFO');
  });

  it('passes clean deflated ZIP (PASS, CLEAN)', async () => {
    const zipBuf = buildZip([
      { name: 'report.txt', content: 'Annual Security Audit Report', method: 8 },
    ]);

    const fixture = await createArchiveJobFixture({
      filename: 'report.zip',
      mime: 'application/zip',
      content: zipBuf,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();
    expect(result.result?.success).toBe(true);

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
    }>(
      `SELECT outcome, reason_code
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('PASS');
    expect(dbRes.rows[0]!.reason_code).toBe('CLEAN');
  });

  it('passes clean OOXML container structurally without P17 macro checks (PASS, CLEAN)', async () => {
    const docxBuf = buildCleanDocxFixture();

    const fixture = await createArchiveJobFixture({
      filename: 'specification.docx',
      mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      content: docxBuf,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: true,
      tempDir: testTmpDir,
    });

    const result = await worker.runOnce();
    expect(result.job).not.toBeNull();
    expect(result.result?.success).toBe(true);

    const dbRes = await adminPool.query<{
      outcome: string;
      reason_code: string;
    }>(
      `SELECT outcome, reason_code
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.archive'`,
      [fixture.jobId],
    );

    expect(dbRes.rows.length).toBe(1);
    expect(dbRes.rows[0]!.outcome).toBe('PASS');
    expect(dbRes.rows[0]!.reason_code).toBe('CLEAN');
  });
});
