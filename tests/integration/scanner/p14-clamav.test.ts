import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import pg from 'pg';
import {
  S3Client,
  CreateBucketCommand,
  PutObjectCommand,
  HeadBucketCommand,
  PutBucketVersioningCommand,
} from '@aws-sdk/client-s3';
import { execSync } from 'node:child_process';
import { createPool, createBaseFixtures, type FixtureContext } from '../db/helpers.js';
import { createS3Provider, type StorageProvider } from '@sug/storage';
import { ClamAvScanner, createClamAvSignatureAgeGauge, Registry } from '@sug/scanner';
import { ScannerWorker } from '../../../services/scanner/src/worker.js';

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
const S3_QUARANTINE_BUCKET = 'sug-quarantine-local';

describe('Phase P14: ClamAV Integration & EICAR Scanning (DoD Test Suite)', () => {
  let adminPool: pg.Pool;
  let scannerPool: pg.Pool;
  let fixtures: FixtureContext;
  let rawS3: S3Client;
  let storageProvider: StorageProvider;
  let clamavScanner: ClamAvScanner;
  const testTmpDir = path.join(os.tmpdir(), `sug-p14-test-${crypto.randomUUID().slice(0, 8)}`);

  // Runtime assembly of canonical EICAR string without static repository signature
  const assembleEicarString = (): string => {
    const part1 = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}';
    const dollar = String.fromCharCode(36);
    const part2 = dollar + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!';
    const part3 = dollar + 'H+H*';
    return part1 + part2 + part3;
  };

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

    // Initialize ClamAV scanner client targeting the Docker Compose ClamAV container
    clamavScanner = new ClamAvScanner({
      host: process.env.CLAMAV_HOST || '127.0.0.1',
      port: Number(process.env.CLAMAV_PORT) || 3310,
      connectTimeoutMs: 5000,
      scanTimeoutMs: 60_000,
    });

    // Verify clamd container is reachable and healthy
    const pingOk = await clamavScanner.ping();
    if (!pingOk) {
      throw new Error(
        `ClamAV daemon is not reachable at ${clamavScanner.config.host}:${clamavScanner.config.port}. Ensure sug-clamav container is running.`,
      );
    }
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
  // scan-01: Canonical EICAR Detection
  // ============================================================
  it('scan-01: detects runtime-assembled EICAR test signature as FOUND', async () => {
    const eicar = assembleEicarString();
    expect(eicar.length).toBe(68);

    const stream = Readable.from([Buffer.from(eicar)]);
    const result = await clamavScanner.scanStream(stream);

    expect(result.status).toBe('FOUND');
    expect(result.signature).toBe('Eicar-Test-Signature');
    expect(result.status).not.toBe('CLEAN');
    expect(result.rawResponse).toMatch(/Eicar-Test-Signature FOUND/);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  // ============================================================
  // scan-02: Benign Clean File
  // ============================================================
  it('scan-02: returns CLEAN and stream: OK for benign clean payload', async () => {
    const cleanPayload = Buffer.from(
      'SECURE_UPLOAD_GATEWAY_BENIGN_TEXT_PAYLOAD_' + crypto.randomUUID(),
    );
    const stream = Readable.from([cleanPayload]);

    const result = await clamavScanner.scanStream(stream);

    expect(result.status).toBe('CLEAN');
    expect(result.signature).toBeNull();
    expect(result.error).toBeNull();
    expect(result.rawResponse).toBe('stream: OK');
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  // ============================================================
  // scan-07: clamd Failure During Active Scan
  // ============================================================
  it('scan-07: fails closed with ERROR when clamd connection is aborted mid-scan', async () => {
    // Spin up an ephemeral mock server that accepts the connection and forcibly resets
    let mockPort = 0;
    const server = net.createServer((socket) => {
      socket.on('data', () => {
        // Abruptly destroy connection mid-stream to simulate worker crash or network drop
        socket.destroy();
      });
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        mockPort = (server.address() as net.AddressInfo).port;
        resolve();
      });
    });

    try {
      const failingScanner = new ClamAvScanner({
        host: '127.0.0.1',
        port: mockPort,
        connectTimeoutMs: 1000,
        scanTimeoutMs: 2000,
      });

      // Stream that produces multiple chunks
      const stream = Readable.from([
        Buffer.from('Chunk 1 that begins transfer'),
        Buffer.from('Chunk 2 that arrives right before reset'),
      ]);

      const result = await failingScanner.scanStream(stream);

      expect(result.status).toBe('ERROR');
      expect(result.status).not.toBe('CLEAN');
      expect(result.error).toBeDefined();
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  // ============================================================
  // scan-07-real-clamd-kill: Real sug-clamav Container Termination Mid-Scan
  // ============================================================
  it('scan-07-real-clamd-kill: fails closed (ERROR / not CLEAN) when real sug-clamav container is killed during active scan', async () => {
    // 1. Verify that real sug-clamav is initially healthy
    const initialHealth = await clamavScanner.ping();
    expect(initialHealth).toBe(true);

    let chunksSent = 0;
    let containerKilled = false;
    let signalScanActive!: () => void;
    const scanActivePromise = new Promise<void>((resolve) => {
      signalScanActive = resolve;
    });

    // Paced stream that actively sends 64KB slices with controlled pacing
    const slowStream = new Readable({
      async read() {
        if (containerKilled) {
          this.push(null);
          return;
        }
        if (chunksSent < 100) {
          chunksSent++;
          this.push(Buffer.alloc(64 * 1024, 0x41));
          // Once 5 chunks (320 KB) have actively entered the clamd INSTREAM session, signal active scan
          if (chunksSent === 5) {
            signalScanActive();
          }
          await new Promise((r) => setTimeout(r, 40));
        } else {
          this.push(null);
        }
      },
    });

    try {
      // 2. Start the scan against the real ClamAV daemon
      const scanPromise = clamavScanner.scanStream(slowStream, { scanTimeoutMs: 15_000 });

      // 3. Guarantee that the scan is actively transmitting into real clamd
      await scanActivePromise;
      expect(chunksSent).toBeGreaterThanOrEqual(5);

      // 4. Abruptly kill the real sug-clamav Docker container mid-scan
      containerKilled = true;
      execSync('docker kill sug-clamav', { stdio: 'ignore' });

      // 5. Await scanner result
      const result = await scanPromise;

      // 6. Assert fail-closed contract: result is ERROR and never CLEAN
      expect(result.status).toBe('ERROR');
      expect(result.status).not.toBe('CLEAN');
      expect(result.error).toBeDefined();
    } finally {
      // 7. Robust cleanup: restart sug-clamav and wait until fully healthy
      try {
        execSync('docker start sug-clamav', { stdio: 'ignore' });
      } catch {
        // ignore if already running
      }

      let recovered = false;
      for (let attempt = 0; attempt < 45; attempt++) {
        await new Promise((r) => setTimeout(r, 1000));
        try {
          if (await clamavScanner.ping()) {
            recovered = true;
            break;
          }
        } catch {
          // continue waiting
        }
      }

      if (!recovered) {
        throw new Error('Failed to restore sug-clamav container to healthy state after test');
      }
    }
  }, 90_000);

  // ============================================================
  // scan-09: Configured Scan / Resource Limits Behavior
  // ============================================================
  it('scan-09: fails closed (ERROR / non-clean) when stream exceeds configured StreamMaxLength (55M)', async () => {
    // ClamAV configuration in docker-compose: StreamMaxLength = 55M (57,671,680 bytes)
    // We stream 56 MB of data to trigger ClamAV's StreamMaxLength limit
    const totalBytes = 56 * 1024 * 1024;
    const chunkSizeBytes = 1024 * 1024; // 1 MB chunks
    let sent = 0;

    const oversizedStream = new Readable({
      read() {
        if (sent < totalBytes) {
          const toSend = Math.min(chunkSizeBytes, totalBytes - sent);
          sent += toSend;
          this.push(Buffer.alloc(toSend, 0x41));
        } else {
          this.push(null);
        }
      },
    });

    const result = await clamavScanner.scanStream(oversizedStream, {
      scanTimeoutMs: 30_000,
    });

    // In ClamAV 1.4.6, exceeding StreamMaxLength returns: "INSTREAM size limit exceeded. ERROR"
    expect(result.status).toBe('ERROR');
    expect(result.status).not.toBe('CLEAN');
    expect(result.error).toMatch(/limit exceeded/i);
    expect(result.rawResponse).toMatch(/INSTREAM size limit exceeded/i);
  });

  // ============================================================
  // scan-10: ClamAV Service Health / Unavailability Path
  // ============================================================
  it('scan-10: fails closed with ERROR when clamd is unavailable or port is unreachable', async () => {
    const unavailableScanner = new ClamAvScanner({
      host: '127.0.0.1',
      port: 65430, // Unused port
      connectTimeoutMs: 500,
    });

    const pingResult = await unavailableScanner.ping();
    expect(pingResult).toBe(false);

    const stream = Readable.from([Buffer.from('Test content for unreachable clamd')]);
    const result = await unavailableScanner.scanStream(stream);

    expect(result.status).toBe('ERROR');
    expect(result.status).not.toBe('CLEAN');
    expect(result.error).toMatch(/ECONNREFUSED|connect/i);
  });

  // ============================================================
  // Signature Age Gauge Verification
  // ============================================================
  it('scan-sig-age: retrieves signature database version and computes age in seconds', async () => {
    const sigInfo = await clamavScanner.getSignatureAge();

    expect(sigInfo.available).toBe(true);
    expect(sigInfo.version).toBe('1.4.6');
    expect(typeof sigInfo.dbVersion).toBe('number');
    expect(sigInfo.dbVersion).toBeGreaterThan(0);
    expect(sigInfo.dbDate).toBeInstanceOf(Date);
    expect(typeof sigInfo.ageSeconds).toBe('number');
    expect(sigInfo.ageSeconds).toBeGreaterThanOrEqual(0);
  });

  it('scan-sig-age-gauge: exposes clamav_signature_age_seconds Prometheus gauge reflecting actual ClamAV database publication timestamp', async () => {
    const registry = new Registry();
    const gauge = createClamAvSignatureAgeGauge(clamavScanner, { registry });

    expect(gauge).toBeDefined();

    // Trigger metrics collection from registry
    const metricsOutput = await registry.metrics();

    expect(metricsOutput).toContain(
      '# HELP clamav_signature_age_seconds Age of ClamAV virus signature database in seconds',
    );
    expect(metricsOutput).toContain('# TYPE clamav_signature_age_seconds gauge');

    const match = metricsOutput.match(/clamav_signature_age_seconds\s+(\d+)/);
    expect(match).not.toBeNull();
    const metricAge = Number(match![1]);
    expect(metricAge).toBeGreaterThanOrEqual(0);

    // Verify it matches getSignatureAge within a few seconds margin
    const sigInfo = await clamavScanner.getSignatureAge();
    expect(sigInfo.available).toBe(true);
    expect(Math.abs(metricAge - sigInfo.ageSeconds!)).toBeLessThanOrEqual(5);
  });

  // ============================================================
  // End-to-End Worker Integration: Benign Clean File
  // ============================================================
  it('scan-worker-clean: worker scans benign artifact, writes PASS finding, and completes job', async () => {
    const benignContent = Buffer.from(
      'CLEAN_BENIGN_PROJECT_DOCUMENT_FOR_P14_' + crypto.randomUUID(),
    );
    const obj = await putTestObject(benignContent);

    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      clamavScanner,
      enableClamAv: true,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();

    expect(job).not.toBeNull();
    expect(job!.id).toBe(jobId);
    expect(result).toBeDefined();
    expect(result!.success).toBe(true);
    expect(result!.verified).toBe(true);
    expect(result!.clamav?.status).toBe('CLEAN');

    // Verify job transitioned to SUCCEEDED
    const jobRow = await adminPool.query(
      `SELECT status, finished_at, locked_by FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(jobRow.rows[0].status).toBe('SUCCEEDED');
    expect(jobRow.rows[0].finished_at).not.toBeNull();
    expect(jobRow.rows[0].locked_by).toBeNull();

    // Verify scan_results contains the ClamAV PASS finding
    const clamavResultRow = await adminPool.query(
      `SELECT check_id, engine, engine_version, outcome, reason_code, severity, confidence, evidence
       FROM scan_results WHERE scan_job_id = $1 AND check_id = 'scanner.clamav'`,
      [jobId],
    );
    expect(clamavResultRow.rows.length).toBe(1);
    const finding = clamavResultRow.rows[0];
    expect(finding.engine).toBe('clamav');
    expect(finding.engine_version).toBe('1.4.6');
    expect(finding.outcome).toBe('PASS');
    expect(finding.reason_code).toBe('CLEAN');
    expect(finding.severity).toBe('INFO');
    expect(finding.confidence).toBe('CONFIRMED');
    expect(finding.evidence.status).toBe('CLEAN');
  });

  // ============================================================
  // End-to-End Worker Integration: Malware / EICAR Detection
  // ============================================================
  it('scan-worker-eicar: worker scans EICAR artifact, writes MALWARE_DETECTED finding, and completes scan execution', async () => {
    const eicarPayload = Buffer.from(assembleEicarString());
    const obj = await putTestObject(eicarPayload);

    const { jobId } = await createScanJobFixture({
      objectKey: obj.key,
      storageVersionId: obj.versionId,
      sizeBytes: obj.size,
      sha256Ingest: obj.sha256,
    });

    const worker = new ScannerWorker({
      db: scannerPool,
      storageProvider,
      clamavScanner,
      enableClamAv: true,
      tempDir: testTmpDir,
    });

    const { job, result } = await worker.runOnce();

    expect(job).not.toBeNull();
    expect(job!.id).toBe(jobId);
    expect(result).toBeDefined();
    expect(result!.success).toBe(true);
    expect(result!.verified).toBe(true);
    expect(result!.clamav?.status).toBe('FOUND');
    expect(result!.clamav?.signature).toBe('Eicar-Test-Signature');

    // Verify job transitioned to SUCCEEDED (finding persisted for decision engine)
    const jobRow = await adminPool.query(
      `SELECT status, finished_at, locked_by FROM scan_jobs WHERE id = $1`,
      [jobId],
    );
    expect(jobRow.rows[0].status).toBe('SUCCEEDED');
    expect(jobRow.rows[0].finished_at).not.toBeNull();
    expect(jobRow.rows[0].locked_by).toBeNull();

    // Verify scan_results contains the ClamAV MALWARE_DETECTED FAIL finding
    const clamavResultRow = await adminPool.query(
      `SELECT check_id, engine, engine_version, outcome, reason_code, severity, confidence, evidence
       FROM scan_results WHERE scan_job_id = $1 AND check_id = 'scanner.clamav'`,
      [jobId],
    );
    expect(clamavResultRow.rows.length).toBe(1);
    const finding = clamavResultRow.rows[0];
    expect(finding.engine).toBe('clamav');
    expect(finding.engine_version).toBe('1.4.6');
    expect(finding.outcome).toBe('FAIL');
    expect(finding.reason_code).toBe('MALWARE_DETECTED');
    expect(finding.severity).toBe('CRITICAL');
    expect(finding.confidence).toBe('CONFIRMED');
    expect(finding.evidence.status).toBe('FOUND');
    expect(finding.evidence.signature).toBe('Eicar-Test-Signature');
  });
});
