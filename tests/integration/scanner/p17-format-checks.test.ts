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
  createEmbeddedMachoBuffer,
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

  it('detects embedded Mach-O executable header at non-zero offset', async () => {
    const machoBuffer = createEmbeddedMachoBuffer(64);
    const obj = await putTestObject(machoBuffer, 'document.bin');
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
      `SELECT check_id, outcome, reason_code, severity, confidence,
              scanned_storage_version_id, scanned_sha256, scanned_size, evidence
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.signature.embedded'`,
      [jobId],
    );
    expect(dbRes.rows).toHaveLength(1);
    const row = dbRes.rows[0]!;
    expect(row.outcome).toBe('FAIL');
    expect(row.reason_code).toBe('EMBEDDED_EXECUTABLE_DETECTED');
    expect(row.severity).toBe('CRITICAL');
    expect(row.scanned_storage_version_id).toBe(obj.versionId);
    expect(row.scanned_sha256.toString('hex')).toBe(obj.sha256);
    expect(Number(row.scanned_size)).toBe(obj.size);
    const evidence = row.evidence as { matches: Array<{ signatureType: string }> };
    expect(evidence.matches.some((m) => m.signatureType === 'MACHO')).toBe(true);
  });

  it('fails closed and marks job DEAD on cryptographic identity mismatch without invoking format checkers', async () => {
    const realBuffer = createCleanPdfBuffer();
    const obj = await putTestObject(realBuffer, 'tampered.pdf');

    // Supply a deliberately mismatched digest (tampered ingest record)
    const tamperedSha = crypto.createHash('sha256').update('FORGED_CONTENT_BYTES').digest('hex');

    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: tamperedSha,
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
    expect(result?.success).toBe(false);
    expect(result?.verified).toBe(false);

    // Scan job must have transitioned to DEAD
    const jobRes = await adminPool.query(
      `SELECT status, attempts, last_error FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(jobRes.rows[0].status).toBe('DEAD');
    expect(jobRes.rows[0].last_error).toContain('Cryptographic identity mismatch');

    // Finding recorded must be IDENTITY_MISMATCH, format checks must NOT have been executed
    const findingsRes = await scannerPool.query(
      `SELECT check_id, outcome, reason_code FROM scan_results WHERE scan_job_id = $1`,
      [jobId],
    );
    expect(findingsRes.rows).toHaveLength(1);
    expect(findingsRes.rows[0].check_id).toBe('scanner.skeleton');
    expect(findingsRes.rows[0].outcome).toBe('FAIL');
    expect(findingsRes.rows[0].reason_code).toBe('IDENTITY_MISMATCH');
  });

  it('binds exact storage_version_id and resists stale findings on storage overwrite and worker retries', async () => {
    const sharedKey = `quarantine/${fixtures.appId}/${crypto.randomUUID()}/versioned-file.pdf`;

    // 1. Put Version 1 in S3
    const v1Pdf = createCleanPdfBuffer();
    const putV1 = await rawS3.send(
      new PutObjectCommand({
        Bucket: S3_QUARANTINE_BUCKET,
        Key: sharedKey,
        Body: v1Pdf,
      }),
    );
    const ver1Id = putV1.VersionId!;
    const sha1 = crypto.createHash('sha256').update(v1Pdf).digest('hex').toLowerCase();

    // 2. Overwrite on same S3 key with Version 2
    const v2Pdf = createActiveContentPdfBuffer('javascript');
    const putV2 = await rawS3.send(
      new PutObjectCommand({
        Bucket: S3_QUARANTINE_BUCKET,
        Key: sharedKey,
        Body: v2Pdf,
      }),
    );
    const ver2Id = putV2.VersionId!;
    expect(ver1Id).not.toBe(ver2Id);

    // 3. Scan job is explicitly bound to Version 1
    const { jobId } = await createScanJobFixture({
      objectKey: sharedKey,
      storageVersionId: ver1Id,
      sizeBytes: v1Pdf.length,
      sha256Ingest: sha1,
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

    const run1 = await worker.runOnce();
    expect(run1.result?.success).toBe(true);
    expect(run1.result?.verified).toBe(true);
    expect(run1.result?.sha256).toBe(sha1);
    expect(run1.result?.pdf?.outcome).toBe('PASS');

    // Verify findings explicitly record Version 1
    const results1 = await scannerPool.query(
      `SELECT check_id, scanned_storage_version_id, scanned_sha256, outcome, reason_code
       FROM scan_results WHERE scan_job_id = $1`,
      [jobId],
    );
    expect(results1.rows.length).toBeGreaterThan(0);
    for (const r of results1.rows) {
      expect(r.scanned_storage_version_id).toBe(ver1Id);
      expect(r.scanned_sha256.toString('hex')).toBe(sha1);
    }

    // 4. Retry with exact same artifact identity is idempotent and preserves findings
    await expect(
      worker.recordFinding({
        jobId,
        fileVersionId: run1.job!.fileVersionId,
        checkId: 'scanner.pdf',
        engine: 'tampered-scanner',
        outcome: 'FAIL',
        reasonCode: 'ACTIVE_CONTENT_DETECTED',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        evidence: { tampered: true },
        storageVersionId: ver1Id, // Same verified storageVersionId
        sha256Hex: sha1, // Same verified digest
        sizeBytes: v1Pdf.length, // Same verified size
        durationMs: 1,
      }),
    ).resolves.not.toThrow();

    // 5. Retry with conflicting artifact identity fails closed and throws
    await expect(
      worker.recordFinding({
        jobId,
        fileVersionId: run1.job!.fileVersionId,
        checkId: 'scanner.pdf',
        engine: 'tampered-scanner',
        outcome: 'FAIL',
        reasonCode: 'ACTIVE_CONTENT_DETECTED',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        evidence: { tampered: true },
        storageVersionId: ver2Id, // Conflicting storageVersionId!
        sha256Hex: '0000000000000000000000000000000000000000000000000000000000000000',
        sizeBytes: 9999,
        durationMs: 1,
      }),
    ).rejects.toThrow(/Artifact identity conflict on scan job retry/);

    const results2 = await scannerPool.query(
      `SELECT check_id, scanned_storage_version_id, outcome, reason_code
       FROM scan_results WHERE scan_job_id = $1 AND check_id = 'scanner.pdf'`,
      [jobId],
    );
    expect(results2.rows).toHaveLength(1);
    expect(results2.rows[0].scanned_storage_version_id).toBe(ver1Id);
    expect(results2.rows[0].outcome).toBe('PASS');
    expect(results2.rows[0].reason_code).toBe('CLEAN');
  });

  it('fails closed on worker retry if pre-existing findings belong to a different artifact identity', async () => {
    const cleanPdf = createCleanPdfBuffer();
    const obj = await putTestObject(cleanPdf, 'retry-mismatch.pdf');
    const { jobId, fileVersionId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    // Plant a pre-existing finding with mismatched artifact identity under this scan_job_id
    await scannerPool.query(
      `INSERT INTO scan_results (
         scan_job_id, file_version_id, check_id, engine, engine_version,
         outcome, reason_code, severity, confidence, evidence,
         scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
       ) VALUES (
         $1, $2, 'scanner.poisoned', 'poison', '1.0.0',
         'PASS', 'CLEAN', 'INFO', 'CONFIRMED', '{}'::jsonb,
         'different-storage-version', decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
         999999, 10
       )`,
      [jobId, fileVersionId],
    );

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
    expect(result?.success).toBe(false);
    expect(result?.error).toContain('Artifact identity conflict on scan retry');

    // Scan job must have transitioned to DEAD due to finding conflict
    const jobRes = await adminPool.query(`SELECT status, last_error FROM scan_jobs WHERE id = $1`, [
      jobId,
    ]);
    expect(jobRes.rows[0].status).toBe('DEAD');
    expect(jobRes.rows[0].last_error).toContain('Artifact identity conflict on scan retry');
  });

  it('proves immutable foreign-key relationship and forbid_mutation trigger on file_versions, scan_jobs, and scan_results', async () => {
    const cleanPdf = createCleanPdfBuffer();
    const obj = await putTestObject(cleanPdf, 'immutable.pdf');
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

    await worker.runOnce();

    // 1. Foreign-key relationship: scan_results.file_version_id -> file_versions.id
    const joinedRes = await adminPool.query(
      `SELECT sr.id as finding_id, sr.check_id, sr.scanned_storage_version_id,
              fv.id as version_id, fv.bucket, fv.object_key, fv.storage_version_id,
              fv.size_bytes, fv.sha256_ingest
       FROM scan_results sr
       JOIN file_versions fv ON sr.file_version_id = fv.id
       WHERE sr.scan_job_id = $1`,
      [jobId],
    );

    expect(joinedRes.rows.length).toBeGreaterThan(0);
    const firstRow = joinedRes.rows[0]!;
    expect(firstRow.version_id).toBe(fileVersionId);
    expect(firstRow.bucket).toBe(S3_QUARANTINE_BUCKET);
    expect(firstRow.object_key).toBe(obj.key);
    expect(firstRow.scanned_storage_version_id).toBe(obj.versionId);
    expect(firstRow.storage_version_id).toBe(obj.versionId);
    expect(firstRow.sha256_ingest.toString('hex')).toBe(obj.sha256);
    expect(Number(firstRow.size_bytes)).toBe(obj.size);

    // 2. Verify file_versions is append-only: UPDATE or DELETE must fail closed
    await expect(
      adminPool.query(`UPDATE file_versions SET size_bytes = 9999 WHERE id = $1`, [fileVersionId]),
    ).rejects.toThrow(/append-only/i);

    await expect(
      adminPool.query(`DELETE FROM file_versions WHERE id = $1`, [fileVersionId]),
    ).rejects.toThrow(/append-only/i);

    // 3. Verify scan_jobs.file_version_id is immutable: UPDATE must fail closed
    const otherFvId = crypto.randomUUID();
    await expect(
      adminPool.query(`UPDATE scan_jobs SET file_version_id = $1 WHERE id = $2`, [
        otherFvId,
        jobId,
      ]),
    ).rejects.toThrow(/scan_jobs.file_version_id is immutable/i);

    // 4. Verify scan_results.file_version_id cannot be switched to a mismatched file_version_id
    await expect(
      scannerPool.query(
        `INSERT INTO scan_results (
           scan_job_id, file_version_id, check_id, engine, engine_version,
           outcome, reason_code, severity, confidence, evidence,
           scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
         ) VALUES (
           $1, $2, 'scanner.fake_fv', 'fake', '1.0.0',
           'PASS', 'CLEAN', 'INFO', 'CONFIRMED', '{}'::jsonb,
           $3, decode($4, 'hex'), $5, 10
         )`,
        [jobId, fixtures.fileVersionId, obj.versionId, obj.sha256, obj.size], // using fixtures.fileVersionId != jobId's fileVersionId
      ),
    ).rejects.toThrow(/scan_results.file_version_id does not match scan_jobs.file_version_id/i);

    // 5. Verify scan_results is append-only: UPDATE or DELETE must fail closed
    await expect(
      adminPool.query(`UPDATE scan_results SET outcome = 'FAIL' WHERE scan_job_id = $1`, [jobId]),
    ).rejects.toThrow(/append-only/i);

    await expect(
      adminPool.query(`DELETE FROM scan_results WHERE scan_job_id = $1`, [jobId]),
    ).rejects.toThrow(/append-only/i);
  });
});
