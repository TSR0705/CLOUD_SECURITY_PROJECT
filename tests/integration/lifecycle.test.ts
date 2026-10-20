/**
 * tests/integration/lifecycle.test.ts
 *
 * Phase 23 Deliverable B: End-to-End Lifecycle & Multi-Tenant Isolation Suite
 *
 * Exercises the complete Secure Upload Gateway lifecycle via @sug/sdk:
 * - Path 1 (Upload -> Promoted): Clean PDF -> Scanned -> ALLOW -> Promoted -> Download -> Cross-tenant 403
 * - Path 2 (Upload -> Blocked): EICAR malware -> Scanned -> FAIL -> BLOCK -> Zero clean writes -> Download 400
 * - Path 3 (Upload -> Review -> Allow): Suspicious file -> REVIEW_REQUIRED -> Analyst override -> ALLOW -> Promoted -> Download 200
 * - Invariant verification: runs verifyInvariants() after every path ensuring zero violations.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
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
import { createDashboardToken } from '../../services/api/src/auth/jwt.js';
import { ScannerWorker } from '../../services/scanner/src/worker.js';
import { PromotionService } from '../../services/promotion/src/promoter.js';
import type { ClaimedPromotionJob } from '../../services/promotion/src/types.js';
import { ClamAvScanner, YaraScanner } from '@sug/scanner';
import { createDocumentsPreset } from '@sug/policy-engine';
import {
  decide,
  persistDecision,
  type DecisionPolicyInput,
  type FileVersionIdentityInput,
  type FindingInput,
} from '@sug/decision-engine';
import { SugClient, SugApiError } from '@sug/sdk';
import { createPool } from './db/helpers.js';
import { verifyInvariants } from '../../scripts/run-invariants.js';

describe('Phase P23: End-to-End Lifecycle & Multi-Tenant Isolation', () => {
  const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
  const QUARANTINE_BUCKET = 'sug-quarantine-local';
  const CLEAN_BUCKET = 'sug-clean-local';

  let app: FastifyInstance;
  let adminPool: pg.Pool;
  let s3Provider: StorageProvider;
  let keyProvider: LocalKeyProvider;
  let baseUrl: string;

  let scannerWorker: ScannerWorker;
  let promotionService: PromotionService;

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
  let policyBId: string;
  let clientB: SugClient;

  // Analyst Client
  let analystToken: string;
  let analystClient: SugClient;

  // Runtime assembled EICAR string
  const assembleEicarString = (): string => {
    const part1 = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}';
    const dollar = '$';
    const part2 = dollar + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!';
    const part3 = dollar + 'H+H*';
    return part1 + part2 + part3;
  };

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    const config = loadConfig({ secretsDir });
    adminPool = createPool('sug_admin', 'sug_dev_password');

    // Drain pre-existing queued scan jobs from prior test suites
    await adminPool.query(
      `UPDATE scan_jobs SET status = 'SUCCEEDED', finished_at = now() WHERE status IN ('QUEUED', 'RUNNING')`,
    );

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

    // 2. Provision Tenant A
    const userARes = await adminPool.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, 'argon2id$mock', 'admin')
       RETURNING id`,
      [`tenant_a_${crypto.randomUUID()}@corp.internal`],
    );
    userAId = userARes.rows[0].id;

    const appARes = await adminPool.query(
      `INSERT INTO applications (name, owner_user_id)
       VALUES ($1, $2)
       RETURNING id`,
      [`app_tenant_a_${crypto.randomUUID().slice(0, 8)}`, userAId],
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
       VALUES ($1, 1, $2, $3, $4)
       RETURNING id`,
      [appAId, JSON.stringify(policyDocA), docASha, userAId],
    );
    policyAId = policyARes.rows[0].id;
    await adminPool.query(`UPDATE applications SET active_policy_id = $1 WHERE id = $2`, [
      policyAId,
      appAId,
    ]);

    // 3. Provision Tenant B
    const userBRes = await adminPool.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, 'argon2id$mock', 'admin')
       RETURNING id`,
      [`tenant_b_${crypto.randomUUID()}@corp.internal`],
    );
    userBId = userBRes.rows[0].id;

    const appBRes = await adminPool.query(
      `INSERT INTO applications (name, owner_user_id)
       VALUES ($1, $2)
       RETURNING id`,
      [`app_tenant_b_${crypto.randomUUID().slice(0, 8)}`, userBId],
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
       VALUES ($1, 1, $2, $3, $4)
       RETURNING id`,
      [appBId, JSON.stringify(policyDocB), docBSha, userBId],
    );
    policyBId = policyBRes.rows[0].id;
    await adminPool.query(`UPDATE applications SET active_policy_id = $1 WHERE id = $2`, [
      policyBId,
      appBId,
    ]);

    // 4. Create Analyst Token
    analystToken = await createDashboardToken(
      { id: crypto.randomUUID(), email: 'analyst@sec.internal', role: 'analyst' },
      config.secrets.jwtPrivateKey,
    );

    // 5. Start Fastify app listening on dynamic port
    app = await createApp({
      config,
      authDb: adminPool,
      storageProvider: s3Provider,
      keyProvider,
      logger: false,
    });
    await app.listen({ port: 0, host: '127.0.0.1' });

    const addr = app.server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 3000;
    baseUrl = `http://127.0.0.1:${port}`;

    // 6. Initialize SDK Clients
    clientA = new SugClient({ baseUrl, apiKey: apiKeyARaw });
    clientB = new SugClient({ baseUrl, apiKey: apiKeyBRaw });
    analystClient = new SugClient({ baseUrl, userToken: analystToken });

    // 7. Initialize Workers
    const clamavScanner = new ClamAvScanner({
      host: process.env.CLAMAV_HOST || '127.0.0.1',
      port: 3310,
      timeoutMs: 15_000,
    });
    const yaraScanner = new YaraScanner();

    scannerWorker = new ScannerWorker({
      db: adminPool,
      storageProvider: s3Provider,
      clamavScanner,
      enableClamAv: true,
      yaraScanner,
      enableYara: true,
      enableArchive: true,
      enableFormatChecks: true,
    });

    promotionService = new PromotionService({
      db: adminPool,
      storageProvider: s3Provider,
      cleanBucket: CLEAN_BUCKET,
      keyProvider,
    });
  });

  afterAll(async () => {
    if (adminPool) {
      await adminPool
        .query(
          `UPDATE scan_jobs SET status = 'SUCCEEDED', finished_at = now() WHERE status IN ('QUEUED', 'RUNNING')`,
        )
        .catch(() => {});
      await adminPool.end();
    }
    if (app) await app.close();
  });

  /**
   * Helper to claim a specific promotion job for a decision
   */
  async function claimSpecificJob(
    pool: pg.Pool,
    decisionId: string,
    workerId: string,
  ): Promise<ClaimedPromotionJob | null> {
    const res = await pool.query(
      `UPDATE promotion_jobs
       SET status = 'RUNNING',
           locked_by = $2,
           locked_at = now(),
           attempts = promotion_jobs.attempts + 1
       FROM security_decisions sd, file_versions fv, files f
       WHERE promotion_jobs.decision_id = $1
         AND sd.id = promotion_jobs.decision_id
         AND fv.id = sd.file_version_id
         AND f.id = fv.file_id
       RETURNING
         promotion_jobs.id,
         promotion_jobs.decision_id,
         sd.file_version_id,
         fv.file_id,
         f.application_id,
         promotion_jobs.status,
         promotion_jobs.attempts,
         promotion_jobs.run_after,
         promotion_jobs.locked_by,
         promotion_jobs.locked_at,
         sd.decision,
         sd.bound_bucket,
         sd.bound_key,
         sd.bound_storage_version_id,
         sd.bound_sha256,
         sd.bound_size,
         f.display_filename`,
      [decisionId, workerId],
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    const sha256Hex = Buffer.isBuffer(row.bound_sha256)
      ? row.bound_sha256.toString('hex').toLowerCase()
      : typeof row.bound_sha256 === 'string'
        ? row.bound_sha256.replace(/^(?:0x|\\x)/i, '').toLowerCase()
        : '';
    return {
      id: row.id,
      decisionId: row.decision_id,
      fileVersionId: row.file_version_id,
      fileId: row.file_id,
      applicationId: row.application_id,
      status: 'RUNNING',
      attempts: row.attempts,
      runAfter: row.run_after,
      lockedBy: row.locked_by,
      lockedAt: row.locked_at,
      decision: row.decision,
      boundBucket: row.bound_bucket,
      boundKey: row.bound_key,
      boundStorageVersionId: row.bound_storage_version_id,
      boundSha256: sha256Hex,
      boundSize: Number(row.bound_size),
      displayFilename: row.display_filename,
    };
  }

  /**
   * Helper to promote a specific decision
   */
  async function promoteDecision(decisionId: string) {
    await adminPool.query(
      `INSERT INTO promotion_jobs (decision_id) VALUES ($1) ON CONFLICT (decision_id) DO NOTHING`,
      [decisionId],
    );

    const claimed = await claimSpecificJob(adminPool, decisionId, 'test-promoter');
    expect(claimed).not.toBeNull();

    const result = await promotionService.promote(claimed!);
    expect(result.success).toBe(true);
    expect(result.outcome).toBe('PROMOTED');
    return result;
  }

  /**
   * Helper to evaluate pure decision engine and persist decision row
   */
  async function evaluateAndPersistDecision(fileVersionId: string) {
    const fvRes = await adminPool.query(
      `SELECT fv.*, f.id as file_id, f.application_id, us.policy_id, sp.document as policy_doc
       FROM file_versions fv
       JOIN files f ON fv.file_id = f.id
       JOIN upload_sessions us ON f.upload_session_id = us.id
       JOIN security_policies sp ON us.policy_id = sp.id
       WHERE fv.id = $1`,
      [fileVersionId],
    );
    expect(fvRes.rows.length).toBeGreaterThan(0);
    const row = fvRes.rows[0];

    const srRes = await adminPool.query(
      `SELECT * FROM scan_results WHERE file_version_id = $1 ORDER BY created_at ASC`,
      [fileVersionId],
    );

    const findings: FindingInput[] = srRes.rows.map(
      (r: {
        check_id: string;
        engine: string;
        engine_version: string | null;
        signature_version: string | null;
        outcome: 'PASS' | 'FAIL' | 'SUSPICIOUS' | 'ERROR' | 'SKIPPED';
        reason_code: string | null;
        severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
        confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
        evidence: Record<string, unknown>;
        scanned_storage_version_id: string;
        scanned_sha256: Buffer | string;
        scanned_size: number | string;
      }) => ({
        checkId: r.check_id,
        engine: r.engine,
        engineVersion: r.engine_version ?? undefined,
        signatureVersion: r.signature_version ?? undefined,
        outcome: r.outcome,
        reasonCode: r.reason_code ?? undefined,
        severity: r.severity,
        confidence: r.confidence,
        evidence: r.evidence,
        scannedStorageVersionId: r.scanned_storage_version_id,
        scannedSha256: Buffer.isBuffer(r.scanned_sha256)
          ? r.scanned_sha256.toString('hex')
          : String(r.scanned_sha256),
        scannedSizeBytes: Number(r.scanned_size),
      }),
    );

    const sha256Hex = Buffer.isBuffer(row.sha256_ingest)
      ? row.sha256_ingest.toString('hex')
      : String(row.sha256_ingest);

    const artifactIdentity: FileVersionIdentityInput = {
      bucket: row.bucket,
      objectKey: row.object_key,
      storageVersionId: row.storage_version_id,
      sha256: sha256Hex,
      sizeBytes: Number(row.size_bytes),
    };

    const policyDoc = row.policy_doc;
    const policyInput: DecisionPolicyInput = {
      id: row.policy_id,
      name: 'policy-eval',
      version: 1,
      sha256: sha256Hex,
      requiredChecks: ['scanner.clamav'],
      riskThreshold: policyDoc.riskThreshold ?? 60,
      manualReviewThreshold: policyDoc.manualReviewThreshold ?? 20,
      disagreementAction: policyDoc.disagreementAction ?? 'QUARANTINE',
      allowedMimes: policyDoc.allowedMimeTypes ?? policyDoc.allowedMimes,
      allowedExtensions: policyDoc.allowedExtensions,
    };

    const decisionResult = decide(policyInput, artifactIdentity, findings);

    const persisted = await persistDecision(adminPool, decisionResult, {
      fileVersionId,
      policyId: row.policy_id,
      scanJobId: srRes.rows[0]?.scan_job_id ?? null,
    });

    const nextStatus =
      decisionResult.decision === 'ALLOW'
        ? 'SCANNED'
        : decisionResult.decision === 'BLOCK'
          ? 'BLOCKED'
          : 'IN_REVIEW';

    await adminPool.query('UPDATE files SET status = $1 WHERE id = $2', [nextStatus, row.file_id]);

    await adminPool.query(
      `SELECT audit_append('service', 'decision-engine', 'decision.created', $1::jsonb, $2::jsonb)`,
      [
        JSON.stringify({
          application_id: row.application_id,
          file_id: row.file_id,
          file_version_id: fileVersionId,
          decision_id: persisted.id,
        }),
        JSON.stringify({
          decision: decisionResult.decision,
          primaryReason: decisionResult.primaryReason,
          riskScore: decisionResult.riskScore,
        }),
      ],
    );

    return persisted;
  }

  // =========================================================================
  // PATH 1: Upload -> Promoted & Multi-Tenant Isolation
  // =========================================================================
  describe('Path 1: Upload -> Promoted & Cross-Tenant Isolation Enforcement', () => {
    it('executes clean upload, promotion, download verification, and enforces cross-tenant 403', async () => {
      const cleanPdfContent = Buffer.from(
        '%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000056 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n111\n%%EOF',
      );
      const cleanSha = crypto.createHash('sha256').update(cleanPdfContent).digest('hex');

      // 1. Tenant A uploads clean PDF via SDK
      const uploadRes = await clientA.uploadFile({
        filename: 'corporate-policy.pdf',
        declaredMime: 'application/pdf',
        payload: cleanPdfContent,
      });

      expect(uploadRes.fileId).toBeTruthy();
      expect(uploadRes.fileVersionId).toBeTruthy();
      expect(uploadRes.scanJobId).toBeTruthy();
      expect(uploadRes.sha256).toBe(cleanSha);

      // 2. Scanner worker processes the scan job
      let scanOutcome = await scannerWorker.runOnce();
      while (scanOutcome.job && scanOutcome.job.id !== uploadRes.scanJobId) {
        scanOutcome = await scannerWorker.runOnce();
      }
      expect(scanOutcome.job).not.toBeNull();
      expect(scanOutcome.result?.success).toBe(true);

      // Verify scan result via SDK
      const scanData = await clientA.getScan(uploadRes.scanJobId);
      expect(scanData.scanStatus).toBe('SUCCEEDED');
      expect(scanData.findings.length).toBeGreaterThan(0);
      expect(scanData.findings.every((f) => f.outcome === 'PASS')).toBe(true);

      // 3. Evaluate deterministic decision (ALLOW)
      const decision = await evaluateAndPersistDecision(uploadRes.fileVersionId);
      expect(decision.decision).toBe('ALLOW');

      // Verify decision via SDK
      const decisionData = await clientA.getDecision(decision.id);
      expect(decisionData.decision).toBe('ALLOW');

      // 4. Promotion service executes promotion
      await promoteDecision(decision.id);

      // 5. Tenant A downloads clean file via SDK
      const downloadRes = await clientA.downloadFile(uploadRes.fileId);
      expect(downloadRes.contentType).toBe('application/octet-stream');
      expect(downloadRes.sha256).toBe(cleanSha);
      expect(downloadRes.data.equals(cleanPdfContent)).toBe(true);
      expect(downloadRes.contentDisposition).toContain('attachment');

      // 6. Cross-Tenant Isolation Attack: Tenant B attempts to access Tenant A's file
      // Attack A: Cross-tenant download attempt -> 403 Forbidden
      await expect(clientB.downloadFile(uploadRes.fileId)).rejects.toThrow(SugApiError);
      try {
        await clientB.downloadFile(uploadRes.fileId);
      } catch (err) {
        expect((err as SugApiError).status).toBe(403);
        expect((err as SugApiError).detail).toContain('another application');
      }

      // Attack B: Cross-tenant metadata inspection -> 403 or 404 (non-disclosing)
      await expect(clientB.getFileMetadata(uploadRes.fileId)).rejects.toThrow(SugApiError);
      try {
        await clientB.getFileMetadata(uploadRes.fileId);
      } catch (err) {
        expect([403, 404]).toContain((err as SugApiError).status);
      }

      // Attack C: Cross-tenant file deletion -> 403 Forbidden
      await expect(clientB.deleteFile(uploadRes.fileId)).rejects.toThrow(SugApiError);
      try {
        await clientB.deleteFile(uploadRes.fileId);
      } catch (err) {
        expect((err as SugApiError).status).toBe(403);
      }

      // 7. Verify all canonical database invariants hold strictly
      const invReport = await verifyInvariants(adminPool);
      expect(invReport.ok).toBe(true);
      expect(invReport.totalViolations).toBe(0);
    });
  });

  // =========================================================================
  // PATH 2: Upload -> Blocked (EICAR Malware)
  // =========================================================================
  describe('Path 2: Upload -> Blocked (Zero Clean Writes)', () => {
    it('detects malware, records BLOCK decision, and leaves clean storage untouched', async () => {
      const eicarString = assembleEicarString();
      const eicarPayload = Buffer.from(eicarString);

      // 1. Tenant A uploads EICAR test string
      const uploadRes = await clientA.uploadFile({
        filename: 'malware-sample.bin',
        declaredMime: 'application/octet-stream',
        payload: eicarPayload,
      });

      // 2. Scanner worker processes the scan job
      let scanOutcome = await scannerWorker.runOnce();
      while (scanOutcome.job && scanOutcome.job.id !== uploadRes.scanJobId) {
        scanOutcome = await scannerWorker.runOnce();
      }
      expect(scanOutcome.job).not.toBeNull();
      expect(scanOutcome.result?.clamav?.signature).toBe('Eicar-Test-Signature');

      // Verify scan result via SDK indicates FAIL finding
      const scanData = await clientA.getScan(uploadRes.scanJobId);
      expect(scanData.scanStatus).toBe('SUCCEEDED');
      const clamavFinding = scanData.findings.find((f) => f.checkId === 'scanner.clamav');
      expect(clamavFinding?.outcome).toBe('FAIL');
      expect(clamavFinding?.reasonCode).toBe('MALWARE_DETECTED');

      // 3. Evaluate deterministic decision (BLOCK)
      const decision = await evaluateAndPersistDecision(uploadRes.fileVersionId);
      expect(decision.decision).toBe('BLOCK');

      // File status is BLOCKED
      const fileStatusRes = await adminPool.query('SELECT status FROM files WHERE id = $1', [
        uploadRes.fileId,
      ]);
      expect(fileStatusRes.rows[0].status).toBe('BLOCKED');

      // 4. Verify no promotion job exists for this blocked decision
      const pjRes = await adminPool.query(`SELECT * FROM promotion_jobs WHERE decision_id = $1`, [
        decision.id,
      ]);
      expect(pjRes.rows.length).toBe(0);

      // 5. Verify clean storage has zero objects for this file version
      const cleanObjRes = await adminPool.query(
        `SELECT * FROM cloud_objects WHERE file_version_id = $1 AND zone = 'clean'`,
        [uploadRes.fileVersionId],
      );
      expect(cleanObjRes.rows.length).toBe(0);

      // 6. Download attempt by Tenant A fails (file not promoted)
      await expect(clientA.downloadFile(uploadRes.fileId)).rejects.toThrow(SugApiError);
      try {
        await clientA.downloadFile(uploadRes.fileId);
      } catch (err) {
        expect((err as SugApiError).status).toBe(400);
        expect((err as SugApiError).detail).toContain('has not been promoted');
      }

      // 7. Invariants check
      const invReport = await verifyInvariants(adminPool);
      expect(invReport.ok).toBe(true);
      expect(invReport.totalViolations).toBe(0);
    });
  });

  // =========================================================================
  // PATH 3: Upload -> Review -> Allow
  // =========================================================================
  describe('Path 3: Upload -> Review -> Allow (Human Review Override)', () => {
    it('quarantines suspicious artifact, blocks premature download, and promotes upon analyst override', async () => {
      // 1. Upload text document with suspicious keywords
      const docPayload = Buffer.from('CONFIDENTIAL INTERNAL REPORT: REVIEW REQUIRED');
      const uploadRes = await clientA.uploadFile({
        filename: 'internal-audit.txt',
        declaredMime: 'text/plain',
        payload: docPayload,
      });

      // 2. Scanner worker completes scan
      let scanOutcome = await scannerWorker.runOnce();
      while (scanOutcome.job && scanOutcome.job.id !== uploadRes.scanJobId) {
        scanOutcome = await scannerWorker.runOnce();
      }

      // 3. Insert a SUSPICIOUS finding representing heuristic policy alert
      await adminPool.query(
        `INSERT INTO scan_results (
           scan_job_id, file_version_id, check_id, engine, outcome, reason_code,
           severity, confidence, scanned_storage_version_id, scanned_sha256, scanned_size
         )
         VALUES ($1, $2, 'policy.keyword', 'rule-engine', 'SUSPICIOUS', 'SUSPICIOUS_KEYWORD',
                 'MEDIUM', 'HIGH', $3, $4, $5)`,
        [
          uploadRes.scanJobId,
          uploadRes.fileVersionId,
          uploadRes.versionId,
          Buffer.from(uploadRes.sha256, 'hex'),
          uploadRes.size,
        ],
      );

      // 4. Decision evaluates to QUARANTINE / REVIEW_REQUIRED
      const decision = await evaluateAndPersistDecision(uploadRes.fileVersionId);
      expect(decision.decision).toBe('QUARANTINE');

      // Verify file status is IN_REVIEW
      const fRes = await adminPool.query('SELECT status FROM files WHERE id = $1', [
        uploadRes.fileId,
      ]);
      expect(fRes.rows[0].status).toBe('IN_REVIEW');

      // Clean storage has zero objects
      const cleanObjBefore = await adminPool.query(
        `SELECT * FROM cloud_objects WHERE file_version_id = $1 AND zone = 'clean'`,
        [uploadRes.fileVersionId],
      );
      expect(cleanObjBefore.rows.length).toBe(0);

      // Download attempt is rejected
      await expect(clientA.downloadFile(uploadRes.fileId)).rejects.toThrow(SugApiError);

      // 5. Analyst submits review decision override (ALLOW) via SDK
      const reviewRes = await analystClient.reviewDecision(decision.id, {
        action: 'ALLOW',
        justification: 'Audited and approved by senior security team: false positive keyword alert',
      });

      expect(reviewRes.decision).toBe('ALLOW');
      expect(reviewRes.supersedesId).toBe(decision.id);

      // 6. Promote the approved decision
      await promoteDecision(reviewRes.id);

      // 7. Verify file status transitioned to PROMOTED
      const fResAfter = await adminPool.query('SELECT status FROM files WHERE id = $1', [
        uploadRes.fileId,
      ]);
      expect(fResAfter.rows[0].status).toBe('PROMOTED');

      // 8. Download now succeeds for Tenant A
      const downloadRes = await clientA.downloadFile(uploadRes.fileId);
      expect(downloadRes.data.equals(docPayload)).toBe(true);

      // Cross-tenant attack still strictly blocked
      await expect(clientB.downloadFile(uploadRes.fileId)).rejects.toThrow(SugApiError);

      // 9. Invariants check
      const invReport = await verifyInvariants(adminPool);
      expect(invReport.ok).toBe(true);
      expect(invReport.totalViolations).toBe(0);
    });
  });
});
