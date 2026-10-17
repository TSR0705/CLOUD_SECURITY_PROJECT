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
import { execSync, spawnSync } from 'node:child_process';
import { createPool, createBaseFixtures, type FixtureContext } from '../db/helpers.js';
import { createS3Provider, type StorageProvider } from '@sug/storage';
import { YARA_ENGINE, YARA_ENGINE_VERSION, YARA_CHECK_ID, YaraScanner } from '@sug/scanner';
import { ScannerWorker } from '../../../services/scanner/src/worker.js';
import { validateRulesDirectory } from '../../../scripts/validate-yara-rules.mjs';

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
const S3_QUARANTINE_BUCKET = 'sug-quarantine-local';
const RULES_DIR = path.resolve(process.cwd(), 'packages/scanner/rules');
const BENIGN_CORPUS_DIR = path.resolve(process.cwd(), 'tests/fixtures/corpus/benign');
const INVALID_RULES_DIR = path.resolve(process.cwd(), 'tests/fixtures/yara/invalid');

describe('Phase P15: YARA-X Integration & Rules DoD Test Suite', () => {
  let adminPool: pg.Pool;
  let scannerPool: pg.Pool;
  let fixtures: FixtureContext;
  let rawS3: S3Client;
  let storageProvider: StorageProvider;
  let yaraScanner: YaraScanner;
  const testTmpDir = path.join(os.tmpdir(), `sug-p15-test-${crypto.randomUUID().slice(0, 8)}`);

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

    yaraScanner = new YaraScanner({
      rulesPath: RULES_DIR,
      timeoutSeconds: 30,
    });

    // Verify YARA-X 1.20.0 CLI is installed and responsive
    const pingOk = await yaraScanner.ping();
    if (!pingOk) {
      throw new Error(
        `YARA-X 1.20.0 CLI 'yr' is not reachable or did not report 1.20.0. Ensure 'yr' is on PATH.`,
      );
    }
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

  // Helper to put an object to S3 and return metadata
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

  // Helper to insert a file_version and scan_job
  async function createScanJobFixture(params: {
    objectKey: string;
    storageVersionId: string;
    sizeBytes: number;
    sha256Ingest: string;
    bucket?: string;
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
  // 1. YARA-X Version Verification
  // ============================================================
  it('verifies YARA-X CLI is exactly version 1.20.0', () => {
    const versionOutput = execSync('yr --version', { encoding: 'utf8' }).trim();
    expect(versionOutput).toMatch(/yara-x(-cli)?\s+1\.20\.0/i);
    expect(YARA_ENGINE).toBe('yara-x');
    expect(YARA_ENGINE_VERSION).toBe('1.20.0');
  });

  // ============================================================
  // 2. scan-03: Canonical YARA-X Threat Detection
  // ============================================================
  it('scan-03: detects canonical P15 test malware pattern with severity and confidence', async () => {
    const malwareContent =
      'BEGIN_PAYLOAD\n' +
      'Header-Data: Normal\n' +
      'SUG_MALWARE_TEST_PATTERN_P15_THREAT\n' +
      'END_PAYLOAD';

    const testFile = path.join(testTmpDir, `scan-03-${crypto.randomUUID()}.bin`);
    await fs.promises.writeFile(testFile, malwareContent);

    try {
      const result = await yaraScanner.scanFile(testFile);

      expect(result.status).toBe('MATCH');
      expect(result.status).not.toBe('CLEAN');
      expect(result.status).not.toBe('ERROR');
      expect(result.matches.length).toBeGreaterThanOrEqual(1);

      const threatMatch = result.matches.find((m) => m.identifier === 'P15_Test_Malware_Signature');
      expect(threatMatch).toBeDefined();
      expect(threatMatch!.meta.severity).toBe('CRITICAL');
      expect(threatMatch!.meta.confidence).toBe('HIGH');
      expect(threatMatch!.meta.description).toMatch(/canonical p15 test malware pattern/i);

      // Verify signature_version is attached and non-empty
      expect(result.signatureVersion).toBeDefined();
      expect(result.signatureVersion.length).toBeGreaterThanOrEqual(16);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    } finally {
      await fs.promises.rm(testFile, { force: true });
    }
  });

  // ============================================================
  // 3. Clean File Test (no false positives)
  // ============================================================
  it('returns CLEAN with 0 rule matches for benign payload', async () => {
    const cleanPayload = 'SECURE_UPLOAD_GATEWAY_BENIGN_DOCUMENT_NO_MALWARE_' + crypto.randomUUID();
    const testFile = path.join(testTmpDir, `clean-${crypto.randomUUID()}.txt`);
    await fs.promises.writeFile(testFile, cleanPayload);

    try {
      const result = await yaraScanner.scanFile(testFile);

      expect(result.status).toBe('CLEAN');
      expect(result.matches).toHaveLength(0);
      expect(result.error).toBeNull();
      expect(result.engine).toBe('yara-x');
      expect(result.engineVersion).toBe('1.20.0');
      expect(result.signatureVersion).toBeDefined();
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    } finally {
      await fs.promises.rm(testFile, { force: true });
    }
  });

  // ============================================================
  // 4. Multiple Rule Matches Test
  // ============================================================
  it('preserves all matching findings when multiple rules match simultaneously', async () => {
    // Contains patterns for both P15_Test_Malware_Signature and P15_Secondary_Test_Signature
    const multiMatchPayload = [
      'SAMPLE_CONTAINER_START',
      'SUG_MALWARE_TEST_PATTERN_P15_THREAT',
      'INTERMEDIATE_BENIGN_DATA',
      'SUG_SECONDARY_TEST_PATTERN_P15_THREAT',
      'SAMPLE_CONTAINER_END',
    ].join('\n');

    const testFile = path.join(testTmpDir, `multi-${crypto.randomUUID()}.bin`);
    await fs.promises.writeFile(testFile, multiMatchPayload);

    try {
      const result = await yaraScanner.scanFile(testFile);

      expect(result.status).toBe('MATCH');
      expect(result.matches).toHaveLength(2);

      const identifiers = result.matches.map((m) => m.identifier);
      expect(identifiers).toContain('P15_Test_Malware_Signature');
      expect(identifiers).toContain('P15_Secondary_Test_Signature');

      const primary = result.matches.find((m) => m.identifier === 'P15_Test_Malware_Signature')!;
      expect(primary.meta.severity).toBe('CRITICAL');
      expect(primary.meta.confidence).toBe('HIGH');

      const secondary = result.matches.find(
        (m) => m.identifier === 'P15_Secondary_Test_Signature',
      )!;
      expect(secondary.meta.severity).toBe('HIGH');
      expect(secondary.meta.confidence).toBe('MEDIUM');
    } finally {
      await fs.promises.rm(testFile, { force: true });
    }
  });

  // ============================================================
  // 5. fp-01: Benign Corpus False-Positive Gate
  // ============================================================
  it('fp-01: produces 0 false positives across all files in the curated benign corpus', async () => {
    const files = await fs.promises.readdir(BENIGN_CORPUS_DIR);
    expect(files.length).toBeGreaterThanOrEqual(4);

    for (const file of files) {
      const fullPath = path.join(BENIGN_CORPUS_DIR, file);
      const stat = await fs.promises.stat(fullPath);
      if (stat.isFile() && !file.startsWith('.')) {
        const result = await yaraScanner.scanFile(fullPath);
        expect(
          result.status,
          `Expected benign file '${file}' to be CLEAN, but got '${result.status}' with matches: ${JSON.stringify(
            result.matches,
          )}`,
        ).toBe('CLEAN');
        expect(result.matches).toHaveLength(0);
      }
    }
  });

  // ============================================================
  // 6. Syntax Error Build / Validation Gate (Definition of Done)
  // ============================================================
  it('DoD: invalid YARA rule syntax causes build/validation gate to fail with non-zero exit', () => {
    // 1. Direct validation function check
    expect(() => validateRulesDirectory(INVALID_RULES_DIR)).toThrow(/YARA-X compilation failed/i);

    // 2. Subprocess execution check asserting non-zero exit code
    const valScript = path.resolve(process.cwd(), 'scripts/validate-yara-rules.mjs');
    const child = spawnSync('node', [valScript, INVALID_RULES_DIR], {
      encoding: 'utf8',
    });

    expect(child.status).not.toBe(0);
    expect(child.status).toBe(1);
    expect(child.stderr).toMatch(/YARA-X Rule Validation Failed/i);
    expect(child.stderr).toMatch(/syntax error/i);
  });

  it('DoD: canonical production rules directory passes validation gate cleanly', () => {
    const valScript = path.resolve(process.cwd(), 'scripts/validate-yara-rules.mjs');
    const child = spawnSync('node', [valScript, RULES_DIR], {
      encoding: 'utf8',
    });

    expect(child.status).toBe(0);
    expect(child.stdout).toMatch(
      /All YARA-X rules in '.*' compiled and passed metadata validation/i,
    );
  });

  it('DoD: invalid YARA rule causes normal pnpm build to fail with non-zero exit', () => {
    const tempBadRule = path.join(RULES_DIR, 'temp_gate_test_invalid.yar');
    fs.writeFileSync(tempBadRule, 'rule bad_syntax { condition: INVALID SYNTAX !!! }', 'utf8');

    const runBuild = () =>
      process.platform === 'win32'
        ? spawnSync('cmd.exe', ['/c', 'pnpm build'], { encoding: 'utf8' })
        : spawnSync('pnpm', ['build'], { encoding: 'utf8' });

    try {
      const child = runBuild();

      expect(child.status).not.toBe(0);
      expect(child.stderr).toMatch(/YARA-X Rule Validation Failed/i);
    } finally {
      if (fs.existsSync(tempBadRule)) {
        fs.unlinkSync(tempBadRule);
      }
    }

    // Build must pass once invalid rule is removed
    const recovery = runBuild();
    expect(recovery.status).toBe(0);
  });

  // ============================================================
  // 7. ScannerWorker End-to-End Integration & scan_results Persistence
  // ============================================================
  it('records YARA threat finding in scan_results with exact artifact identity', async () => {
    const threatPayload =
      'HEADER: ARCHIVE_DATA\n' + 'SUG_MALWARE_TEST_PATTERN_P15_THREAT\n' + 'FOOTER: CHECKSUM';

    const testObject = await putTestObject(threatPayload);
    const { jobId } = await createScanJobFixture({
      objectKey: testObject.key,
      storageVersionId: testObject.versionId,
      sizeBytes: testObject.size,
      sha256Ingest: testObject.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableYara: true,
      enableClamAv: false,
      yaraScanner,
      tempDir: testTmpDir,
    });

    const runRes = await worker.runOnce();
    expect(runRes.job?.id).toBe(jobId);
    expect(runRes.result?.success).toBe(true);
    expect(runRes.result?.verified).toBe(true);
    expect(runRes.result?.yara?.status).toBe('MATCH');

    // Verify job transitioned to SUCCEEDED
    const jobRow = await adminPool.query('SELECT status FROM scan_jobs WHERE id = $1', [jobId]);
    expect(jobRow.rows[0].status).toBe('SUCCEEDED');

    // Verify scan_results contains exact check_id: 'scanner.yara'
    const scanResultQuery = await adminPool.query(
      `SELECT check_id, engine, engine_version, signature_version, outcome,
              reason_code, severity, confidence, evidence,
              scanned_storage_version_id, scanned_sha256, scanned_size
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.yara'`,
      [jobId],
    );

    expect(scanResultQuery.rows).toHaveLength(1);
    const row = scanResultQuery.rows[0];

    expect(row.check_id).toBe(YARA_CHECK_ID);
    expect(row.engine).toBe('yara-x');
    expect(row.engine_version).toBe('1.20.0');
    expect(row.signature_version).toBe(yaraScanner.getSignatureVersion());
    expect(row.outcome).toBe('FAIL');
    expect(row.reason_code).toBe('MALWARE_DETECTED');
    expect(row.severity).toBe('CRITICAL');
    expect(row.confidence).toBe('HIGH');
    expect(row.scanned_storage_version_id).toBe(testObject.versionId);
    expect(row.scanned_sha256.toString('hex')).toBe(testObject.sha256);
    expect(Number(row.scanned_size)).toBe(testObject.size);

    const evidence = row.evidence;
    expect(evidence.status).toBe('MATCH');
    expect(evidence.matchedRules).toContain('P15_Test_Malware_Signature');
  });

  it('records YARA clean scan in scan_results with PASS and INFO severity', async () => {
    const cleanPayload = 'SECURE_UPLOAD_GATEWAY_CLEAN_DOCUMENT_' + crypto.randomUUID();

    const testObject = await putTestObject(cleanPayload);
    const { jobId } = await createScanJobFixture({
      objectKey: testObject.key,
      storageVersionId: testObject.versionId,
      sizeBytes: testObject.size,
      sha256Ingest: testObject.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableYara: true,
      enableClamAv: false,
      yaraScanner,
      tempDir: testTmpDir,
    });

    const runRes = await worker.runOnce();
    expect(runRes.job?.id).toBe(jobId);
    expect(runRes.result?.success).toBe(true);
    expect(runRes.result?.verified).toBe(true);
    expect(runRes.result?.yara?.status).toBe('CLEAN');

    const scanResultQuery = await adminPool.query(
      `SELECT check_id, engine, engine_version, signature_version, outcome,
              reason_code, severity, confidence, evidence,
              scanned_storage_version_id, scanned_sha256, scanned_size
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = 'scanner.yara'`,
      [jobId],
    );

    expect(scanResultQuery.rows).toHaveLength(1);
    const row = scanResultQuery.rows[0];

    expect(row.check_id).toBe('scanner.yara');
    expect(row.engine).toBe('yara-x');
    expect(row.engine_version).toBe('1.20.0');
    expect(row.signature_version).toBe(yaraScanner.getSignatureVersion());
    expect(row.outcome).toBe('PASS');
    expect(row.reason_code).toBe('CLEAN');
    expect(row.severity).toBe('INFO');
    expect(row.confidence).toBe('CONFIRMED');
    expect(row.scanned_storage_version_id).toBe(testObject.versionId);
    expect(row.scanned_sha256.toString('hex')).toBe(testObject.sha256);
    expect(Number(row.scanned_size)).toBe(testObject.size);
    expect(row.evidence.status).toBe('CLEAN');
  });

  // ============================================================
  // 8. Fail-Closed Behavior on Scanner Error
  // ============================================================
  it('fails closed when YARA scanner encounters an execution error', async () => {
    const cleanPayload = 'SAMPLE_DATA_FOR_FAIL_CLOSED_TEST';
    const testObject = await putTestObject(cleanPayload);
    const { jobId } = await createScanJobFixture({
      objectKey: testObject.key,
      storageVersionId: testObject.versionId,
      sizeBytes: testObject.size,
      sha256Ingest: testObject.sha256,
    });

    // Scanner configured with non-existent binary to trigger execution error
    const faultyScanner = new YaraScanner({
      binaryPath: 'non_existent_yr_binary_trigger_error',
      rulesPath: RULES_DIR,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableYara: true,
      enableClamAv: false,
      yaraScanner: faultyScanner,
      tempDir: testTmpDir,
    });

    const runRes = await worker.runOnce();
    expect(runRes.result?.success).toBe(false);
    expect(runRes.result?.yara?.status).toBe('ERROR');

    // Verify job transitioned to QUEUED (retryable with backoff)
    const jobRow = await adminPool.query(
      'SELECT status, attempts, last_error FROM scan_jobs WHERE id = $1',
      [jobId],
    );
    expect(jobRow.rows[0].status).toBe('QUEUED');
    expect(jobRow.rows[0].attempts).toBe(1);
    expect(jobRow.rows[0].last_error).toMatch(/non_existent_yr_binary/i);

    // Verify ERROR result recorded in scan_results
    const scanResultQuery = await adminPool.query(
      `SELECT check_id, outcome, reason_code, severity FROM scan_results WHERE scan_job_id = $1 AND check_id = 'scanner.yara'`,
      [jobId],
    );
    expect(scanResultQuery.rows).toHaveLength(1);
    expect(scanResultQuery.rows[0].outcome).toBe('ERROR');
    expect(scanResultQuery.rows[0].reason_code).toBe('SCANNER_ERROR');
  });

  // ============================================================
  // 9. P18 Scope Boundary Audit (Zero ALLOW/BLOCK Decision Contamination)
  // ============================================================
  it('strictly persists findings to scan_results and never creates security decisions or ALLOW/BLOCK verdicts', async () => {
    const threatPayload = 'SAMPLE_DATA_CONTAINING_SUG_MALWARE_TEST_PATTERN_P15_THREAT';
    const testObject = await putTestObject(threatPayload);
    const { jobId, fileVersionId } = await createScanJobFixture({
      objectKey: testObject.key,
      storageVersionId: testObject.versionId,
      sizeBytes: testObject.size,
      sha256Ingest: testObject.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      enableYara: true,
      enableClamAv: false,
      yaraScanner,
      tempDir: testTmpDir,
    });

    const runRes = await worker.runOnce();
    expect(runRes.result?.success).toBe(true);
    expect(runRes.result?.yara?.status).toBe('MATCH');

    // 1. Worker marks scan_job as SUCCEEDED (job execution succeeded)
    const jobRes = await adminPool.query('SELECT status FROM scan_jobs WHERE id = $1', [jobId]);
    expect(jobRes.rows[0].status).toBe('SUCCEEDED');

    // 2. Worker inserted telemetry row into scan_results
    const scanRes = await adminPool.query(
      'SELECT check_id, outcome, reason_code FROM scan_results WHERE scan_job_id = $1',
      [jobId],
    );
    expect(scanRes.rows.some((r) => r.check_id === 'scanner.yara' && r.outcome === 'FAIL')).toBe(
      true,
    );

    // 3. ZERO security_decisions exist for this file version (P18 responsibility)
    const decRes = await adminPool.query(
      'SELECT COUNT(*)::int as count FROM security_decisions WHERE file_version_id = $1',
      [fileVersionId],
    );
    expect(decRes.rows[0].count).toBe(0);
  });
});
