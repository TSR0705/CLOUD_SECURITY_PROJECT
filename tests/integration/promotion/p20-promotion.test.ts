/**
 * @sug/test/integration/promotion/p20-promotion.test.ts
 *
 * Comprehensive Adversarial Integration Test Suite for Phase P20:
 * - toctou-01: Legitimate clean artifact promotion end-to-end
 * - toctou-02: Source version replaced in quarantine (exact version binding; no latest fallback)
 * - toctou-03: Content mutated under same version (SHA-256 mismatch rejection, zero clean writes)
 * - toctou-04: Size mismatch / truncated payload rejection
 * - Priority 1: Safe orphan reconciliation when clean storage write succeeds but DB fails, and retry
 * - Encryption/KEK failure with zero clean storage publication
 * - Verify-before-release download API and tampered ciphertext/AAD rejection (zero plaintext bytes released)
 * - Strict safe download headers (nosniff, sandbox, attachment, no-store)
 * - authz-07: Tenant application isolation, route aliases, and RBAC (admin delete, analyst/auditor 403)
 * - Invariant int-01 verification against real PostgreSQL and LocalStack S3
 */

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import {
  S3Client,
  HeadBucketCommand,
  CreateBucketCommand,
  PutBucketVersioningCommand,
  PutObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { createS3Provider, type StorageProvider } from '@sug/storage';
import { LocalKeyProvider, DEFAULT_LOCAL_KEY_REFERENCE, decryptBuffer } from '@sug/crypto';
import { loadConfig } from '@sug/shared/config';
import { createApp } from '../../../services/api/src/app.js';
import { generateRawKey, computeKeyHmac } from '../../../services/api/src/auth/keys.js';
import { createDashboardToken } from '../../../services/api/src/auth/jwt.js';
import { PromotionService } from '../../../services/promotion/src/index.js';
import { createPool } from '../db/helpers.js';

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
const QUARANTINE_BUCKET = 'sug-quarantine-local';
const CLEAN_BUCKET = 'sug-clean-local';

interface FixtureResult {
  userId: string;
  appId: string;
  apiKeyId: string;
  rawApiKey: string;
  policyId: string;
  fileId: string;
  fileVersionId: string;
  storageVersionId: string;
  decisionId: string;
  jobId: string;
  plaintext: Buffer;
  sha256Hex: string;
  sizeBytes: number;
  objectKey: string;
}

describe('Phase P20 Adversarial Integration — Trusted Storage & Bound Promotion', () => {
  let adminPool: pg.Pool;
  let rawS3: S3Client;
  let s3Provider: StorageProvider;
  let keyProvider: LocalKeyProvider;
  let app: FastifyInstance;
  let jwtPrivateKeyPem: string;
  let pepper: string;
  const testKek = crypto.randomBytes(32);

  beforeAll(async () => {
    adminPool = createPool('sug_admin', 'sug_dev_password');

    rawS3 = new S3Client({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'test',
        secretAccessKey: 'test',
      },
      forcePathStyle: true,
    });

    // Ensure LocalStack quarantine and clean buckets exist with versioning enabled
    for (const b of [QUARANTINE_BUCKET, CLEAN_BUCKET]) {
      try {
        await rawS3.send(new HeadBucketCommand({ Bucket: b }));
      } catch {
        await rawS3.send(new CreateBucketCommand({ Bucket: b }));
      }
      await rawS3.send(
        new PutBucketVersioningCommand({
          Bucket: b,
          VersioningConfiguration: { Status: 'Enabled' },
        }),
      );
    }

    s3Provider = createS3Provider({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'test',
        secretAccessKey: 'test',
      },
      forcePathStyle: true,
    });

    keyProvider = new LocalKeyProvider({
      keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
      defaultKeyReference: DEFAULT_LOCAL_KEY_REFERENCE,
    });

    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');
    const baseConfig = loadConfig({ secretsDir });
    pepper = baseConfig.secrets.pepper;
    jwtPrivateKeyPem = baseConfig.secrets.jwtPrivateKey;

    // Clean up old queued promotion jobs from prior runs
    await adminPool.query("DELETE FROM promotion_jobs WHERE status = 'QUEUED'");

    app = await createApp({
      config: baseConfig,
      storageProvider: s3Provider,
      keyProvider,
      logger: false,
    });
    await app.ready();
  });

  async function claimSpecificJob(pool: pg.Pool, jobId: string, workerId: string) {
    const res = await pool.query(
      `UPDATE promotion_jobs
       SET status = 'RUNNING',
           locked_by = $2,
           locked_at = now(),
           attempts = promotion_jobs.attempts + 1
       FROM security_decisions sd, file_versions fv, files f
       WHERE promotion_jobs.id = $1
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
      [jobId, workerId],
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
      status: 'RUNNING' as const,
      attempts: Number(row.attempts),
      maxAttempts: 3,
      runAfter: new Date(row.run_after),
      lockedBy: row.locked_by,
      lockedAt: new Date(row.locked_at),
      decision: row.decision,
      boundBucket: row.bound_bucket,
      boundKey: row.bound_key,
      boundStorageVersionId: row.bound_storage_version_id,
      boundSha256: sha256Hex,
      boundSize: Number(row.bound_size),
      displayFilename: row.display_filename,
    };
  }

  afterAll(async () => {
    if (app) await app.close();
    if (adminPool) await adminPool.end();
  });

  /**
   * Evaluates the canonical int-01 security invariant:
   * Every clean cloud_object MUST reference a file with status 'PROMOTED'
   * and an active (un-superseded) ALLOW security decision.
   * Returns 0 rows if invariant is maintained.
   */
  async function assertInt01Invariant(fileVersionId?: string): Promise<void> {
    const params: unknown[] = [CLEAN_BUCKET];
    let query = `
      SELECT co.id, co.file_version_id, co.bucket, co.object_key
      FROM cloud_objects co
      JOIN file_versions fv ON fv.id = co.file_version_id
      JOIN files f ON f.id = fv.file_id
      LEFT JOIN security_decisions sd ON sd.file_version_id = fv.id
        AND sd.decision = 'ALLOW'
        AND NOT EXISTS (SELECT 1 FROM security_decisions sub WHERE sub.supersedes_id = sd.id)
      WHERE co.zone = 'clean'
        AND co.bucket = $1
        AND (f.status NOT IN ('PROMOTED', 'DELETED') OR sd.id IS NULL)
    `;
    if (fileVersionId) {
      params.push(fileVersionId);
      query += ` AND co.file_version_id = $2`;
    }
    const res = await adminPool.query(query, params);
    expect(res.rows).toEqual([]);
  }

  /**
   * Creates an end-to-end fixture:
   * - Uploads real payload to LocalStack S3 quarantine
   * - Inserts DB user, application, API key, policy, file, file_version, ALLOW decision, and promotion_job
   */
  async function createFixture(
    options: {
      plaintext?: Buffer;
      decision?: 'ALLOW' | 'BLOCK';
      tamperBoundSha?: boolean;
      tamperBoundSize?: boolean;
      appOwnerUserId?: string;
    } = {},
  ): Promise<FixtureResult> {
    const plaintext = options.plaintext ?? Buffer.from('Confidential payroll report 2026', 'utf8');
    const actualSha = crypto.createHash('sha256').update(plaintext).digest('hex');
    const actualSize = plaintext.length;

    const boundShaHex = options.tamperBoundSha ? crypto.randomBytes(32).toString('hex') : actualSha;
    const boundSize = options.tamperBoundSize ? actualSize + 999 : actualSize;

    const client = await adminPool.connect();
    try {
      await client.query('BEGIN');

      // 1. User
      let userId = options.appOwnerUserId;
      if (!userId) {
        const userRes = await client.query(
          `INSERT INTO users (email, password_hash, role)
           VALUES ($1, 'argon2id$placeholder', 'admin')
           RETURNING id`,
          [`admin_${crypto.randomUUID()}@gateway.internal`],
        );
        userId = userRes.rows[0].id;
      }

      // 2. Application
      const appRes = await client.query(
        `INSERT INTO applications (name, owner_user_id)
         VALUES ($1, $2)
         RETURNING id`,
        [`app_${crypto.randomUUID().slice(0, 16)}`, userId],
      );
      const appId = appRes.rows[0].id;

      // 3. API Key
      const { rawKey, keyPrefix, secret } = generateRawKey();
      const keyHmac = computeKeyHmac(secret, pepper);
      const keyRes = await client.query(
        `INSERT INTO api_keys (application_id, key_prefix, key_hmac, scopes, created_by)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [appId, keyPrefix, keyHmac, ['read', 'upload', 'files:delete'], userId],
      );
      const apiKeyId = keyRes.rows[0].id;
      const rawApiKey = rawKey;

      // 4. Security Policy
      const policyDoc = { allowedExtensions: ['.pdf'], maxFileSize: 10485760 };
      const policyDocSha = crypto.createHash('sha256').update(JSON.stringify(policyDoc)).digest();
      const polRes = await client.query(
        `INSERT INTO security_policies (application_id, version, document, document_sha256, created_by)
         VALUES ($1, 1, $2, $3, $4)
         RETURNING id`,
        [appId, JSON.stringify(policyDoc), policyDocSha, userId],
      );
      const policyId = polRes.rows[0].id;

      // 5. Upload Session & File
      const sessionRes = await client.query(
        `INSERT INTO upload_sessions (
           application_id, api_key_id, policy_id, original_filename, declared_mime,
           declared_size, token_jti, expires_at
         )
         VALUES ($1, $2, $3, 'payroll.pdf', 'application/pdf', $4, $5, now() + interval '10 minutes')
         RETURNING id`,
        [appId, apiKeyId, policyId, actualSize, crypto.randomUUID()],
      );
      const sessionId = sessionRes.rows[0].id;

      const fileRes = await client.query(
        `INSERT INTO files (application_id, upload_session_id, display_filename, status)
         VALUES ($1, $2, 'payroll.pdf', 'QUARANTINED')
         RETURNING id`,
        [appId, sessionId],
      );
      const fileId = fileRes.rows[0].id;

      // 6. Upload real object to LocalStack S3 quarantine to obtain real versionId
      const objectKey = `quarantine/${appId}/${fileId}`;
      const putS3Res = await rawS3.send(
        new PutObjectCommand({
          Bucket: QUARANTINE_BUCKET,
          Key: objectKey,
          Body: plaintext,
          ContentType: 'application/pdf',
        }),
      );
      const storageVersionId = putS3Res.VersionId;
      if (!storageVersionId) {
        throw new Error(
          'S3 quarantine bucket versioning is not active or did not return VersionId',
        );
      }

      // 7. File Version
      const fvRes = await client.query(
        `INSERT INTO file_versions (
           file_id, version_no, provider, bucket, object_key, storage_version_id, size_bytes, sha256_ingest
         )
         VALUES ($1, 1, 'aws', $2, $3, $4, $5, $6)
         RETURNING id`,
        [
          fileId,
          QUARANTINE_BUCKET,
          objectKey,
          storageVersionId,
          actualSize,
          Buffer.from(actualSha, 'hex'),
        ],
      );
      const fileVersionId = fvRes.rows[0].id;

      await client.query(`UPDATE files SET current_version_id = $1 WHERE id = $2`, [
        fileVersionId,
        fileId,
      ]);

      // 8. Security Decision
      const decisionType = options.decision ?? 'ALLOW';
      const decRes = await client.query(
        `INSERT INTO security_decisions (
           file_version_id, policy_id, decision, primary_reason,
           severity, confidence, risk_score, policy_result, scanner_result,
           integrity_result, authorization_result, bound_bucket, bound_key,
           bound_storage_version_id, bound_sha256, bound_size, record,
           engine_version, decided_by
         )
         VALUES (
           $1, $2, $3, 'EVAL_PASSED',
           'INFO', 'CONFIRMED', 0, 'PASS', 'CLEAN',
           'MATCH', 'AUTHORIZED', $4, $5,
           $6, $7, $8, '{}',
           '1.0.0', 'evaluator-service'
         )
         RETURNING id`,
        [
          fileVersionId,
          policyId,
          decisionType,
          QUARANTINE_BUCKET,
          objectKey,
          storageVersionId,
          Buffer.from(boundShaHex, 'hex'),
          boundSize,
        ],
      );
      const decisionId = decRes.rows[0].id;

      // 9. Promotion Job
      const jobRes = await client.query(
        `INSERT INTO promotion_jobs (decision_id, status)
         VALUES ($1, 'QUEUED')
         RETURNING id`,
        [decisionId],
      );
      const jobId = jobRes.rows[0].id;

      await client.query('COMMIT');

      return {
        userId,
        appId,
        apiKeyId,
        rawApiKey,
        policyId,
        fileId,
        fileVersionId,
        storageVersionId,
        decisionId,
        jobId,
        plaintext,
        sha256Hex: actualSha,
        sizeBytes: actualSize,
        objectKey,
      };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  describe('1. toctou-01: Legitimate Clean Artifact Promotion End-to-End', () => {
    it('promotes clean artifact from real quarantine to real clean storage and records database entities', async () => {
      const fix = await createFixture();

      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      // Claim job
      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-01');
      expect(claimed).not.toBeNull();
      expect(claimed!.id).toBe(fix.jobId);

      const result = await promoter.promote(claimed!);

      expect(result.success).toBe(true);
      expect(result.outcome).toBe('PROMOTED');
      expect(result.cleanBucket).toBe(CLEAN_BUCKET);
      expect(result.cleanObjectKey).toBe(`objects/${fix.appId}/${fix.fileId}`);

      // 1. Verify clean storage contains valid SUG1 envelope
      const cleanObj = await s3Provider.getByVersion({
        bucket: CLEAN_BUCKET,
        key: result.cleanObjectKey!,
        versionId: result.cleanStorageVersionId!,
      });
      const chunks: Buffer[] = [];
      for await (const chunk of cleanObj.body) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      const envelope = Buffer.concat(chunks);
      expect(envelope.subarray(0, 4).toString('utf8')).toBe('SUG1');

      // 2. Decrypt envelope with bound AAD and verify plaintext match
      const decrypted = await decryptBuffer(envelope, {
        keyProvider,
        aad: {
          appId: fix.appId,
          fileId: fix.fileId,
          storageVersionId: fix.storageVersionId,
          sha256Plaintext: fix.sha256Hex,
        },
      });
      expect(decrypted.toString('utf8')).toBe(fix.plaintext.toString('utf8'));

      // 3. Verify database records
      const coRes = await adminPool.query(
        `SELECT * FROM cloud_objects WHERE file_version_id = $1 AND zone = 'clean'`,
        [fix.fileVersionId],
      );
      expect(coRes.rows).toHaveLength(1);
      const co = coRes.rows[0];
      expect(co.bucket).toBe(CLEAN_BUCKET);
      expect(co.object_key).toBe(`objects/${fix.appId}/${fix.fileId}`);
      expect(co.enc_alg).toBe('AES-256-GCM');
      expect(co.sha256_plain.toString('hex')).toBe(fix.sha256Hex);

      const fRes = await adminPool.query(`SELECT status FROM files WHERE id = $1`, [fix.fileId]);
      expect(fRes.rows[0].status).toBe('PROMOTED');

      const pjRes = await adminPool.query(
        `SELECT status, outcome FROM promotion_jobs WHERE id = $1`,
        [fix.jobId],
      );
      expect(pjRes.rows[0].status).toBe('SUCCEEDED');
      expect(pjRes.rows[0].outcome).toBe('PROMOTED');

      // 4. Verify int-01 invariant
      await assertInt01Invariant();
    });
  });

  describe('2. toctou-02: Source Version Replaced in Quarantine (Exact Version Binding)', () => {
    it('promotes bound source version even if malicious version is uploaded under same key', async () => {
      const fix = await createFixture();

      // Attacker uploads a mutated payload under the same quarantine key, creating version v2 in S3
      const maliciousPayload = Buffer.from('MALICIOUS CONTENT INJECTED AFTER SCAN', 'utf8');
      const putMaliciousRes = await rawS3.send(
        new PutObjectCommand({
          Bucket: QUARANTINE_BUCKET,
          Key: fix.objectKey,
          Body: maliciousPayload,
        }),
      );
      const v2VersionId = putMaliciousRes.VersionId;
      expect(v2VersionId).not.toBe(fix.storageVersionId);

      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-02');
      expect(claimed).not.toBeNull();

      // Promoter must fetch fix.storageVersionId (v1) rather than the latest version (v2)
      const result = await promoter.promote(claimed!);

      expect(result.success).toBe(true);
      expect(result.outcome).toBe('PROMOTED');

      // Verify clean storage decrypts to original v1 content, NOT v2
      const cleanObj = await s3Provider.getByVersion({
        bucket: CLEAN_BUCKET,
        key: result.cleanObjectKey!,
        versionId: result.cleanStorageVersionId!,
      });
      const chunks: Buffer[] = [];
      for await (const chunk of cleanObj.body) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      const decrypted = await decryptBuffer(Buffer.concat(chunks), {
        keyProvider,
        aad: {
          appId: fix.appId,
          fileId: fix.fileId,
          storageVersionId: fix.storageVersionId,
          sha256Plaintext: fix.sha256Hex,
        },
      });
      expect(decrypted.toString('utf8')).toBe(fix.plaintext.toString('utf8'));
      expect(decrypted.toString('utf8')).not.toContain('MALICIOUS');

      await assertInt01Invariant();
    });

    it('aborts and leaves clean storage empty if bound source version is deleted or missing', async () => {
      const fix = await createFixture();

      // Delete the bound version v1 from S3 quarantine
      await rawS3.send(
        new DeleteObjectCommand({
          Bucket: QUARANTINE_BUCKET,
          Key: fix.objectKey,
          VersionId: fix.storageVersionId,
        }),
      );

      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-02-missing');
      expect(claimed).not.toBeNull();

      const result = await promoter.promote(claimed!);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('STORAGE_FAILED');

      // Zero clean storage objects created
      const cleanKey = `objects/${fix.appId}/${fix.fileId}`;
      await expect(s3Provider.head({ bucket: CLEAN_BUCKET, key: cleanKey })).rejects.toThrow();

      // File status transitions to ERROR when bound version is missing
      const fRes = await adminPool.query(`SELECT status FROM files WHERE id = $1`, [fix.fileId]);
      expect(fRes.rows[0].status).toBe('ERROR');

      await assertInt01Invariant();
    });
  });

  describe('3. toctou-03: Content Mutated Under Same Version (SHA-256 Mismatch Rejection)', () => {
    it('rejects promotion immediately with HASH_MISMATCH and zero clean storage writes', async () => {
      // Fixture with tampered bound SHA-256
      const fix = await createFixture({ tamperBoundSha: true });

      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-03');
      expect(claimed).not.toBeNull();

      const result = await promoter.promote(claimed!);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('HASH_MISMATCH');
      expect(result.error).toContain('does not match bound SHA-256');

      // Zero clean storage objects created
      const cleanKey = `objects/${fix.appId}/${fix.fileId}`;
      await expect(s3Provider.head({ bucket: CLEAN_BUCKET, key: cleanKey })).rejects.toThrow();

      // File transitioned to BLOCKED
      const fRes = await adminPool.query(`SELECT status FROM files WHERE id = $1`, [fix.fileId]);
      expect(fRes.rows[0].status).toBe('BLOCKED');

      // Job marked FAILED
      const jRes = await adminPool.query(
        `SELECT status, outcome FROM promotion_jobs WHERE id = $1`,
        [fix.jobId],
      );
      expect(jRes.rows[0].status).toBe('FAILED');
      expect(jRes.rows[0].outcome).toBe('HASH_MISMATCH');

      // Audit event PROMOTION_REJECTED recorded
      const auditRes = await adminPool.query(
        `SELECT * FROM audit_events WHERE action = 'PROMOTION_REJECTED' AND file_id = $1`,
        [fix.fileId],
      );
      expect(auditRes.rows).toHaveLength(1);

      await assertInt01Invariant();
    });
  });

  describe('4. toctou-04: Size Mismatch or Truncated Payload Rejection', () => {
    it('rejects promotion immediately with SIZE_MISMATCH when payload length differs from bound size', async () => {
      // Fixture with tampered bound size
      const fix = await createFixture({ tamperBoundSize: true });

      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-04');
      expect(claimed).not.toBeNull();

      const result = await promoter.promote(claimed!);

      expect(result.success).toBe(false);
      expect(['SIZE_MISMATCH', 'HASH_MISMATCH']).toContain(result.outcome);

      // Zero clean storage objects created
      const cleanKey = `objects/${fix.appId}/${fix.fileId}`;
      await expect(s3Provider.head({ bucket: CLEAN_BUCKET, key: cleanKey })).rejects.toThrow();

      // File transitioned to BLOCKED
      const fRes = await adminPool.query(`SELECT status FROM files WHERE id = $1`, [fix.fileId]);
      expect(fRes.rows[0].status).toBe('BLOCKED');

      await assertInt01Invariant();
    });
  });

  describe('5. Priority 1: Storage/Database Consistency and Safe Orphan Reconciliation', () => {
    it('demonstrates clean storage write success followed by DB transaction failure, and safe orphan reconciliation on retry', async () => {
      const fix = await createFixture();

      const cleanKey = `objects/${fix.appId}/${fix.fileId}`;

      // PART A: Simulated failure where S3 putIfAbsent succeeds, but DB commit rolls back
      const realQuery = adminPool.query.bind(adminPool);
      // Wrap db query to inject an error on COMMIT inside promoter
      const failingDb = {
        query: async <T = unknown>(
          sql: string,
          params?: unknown[],
        ): Promise<{ rows: T[]; rowCount?: number | null }> => {
          if (typeof sql === 'string' && sql.trim() === 'COMMIT') {
            throw new Error('Injected database transaction abort right after storage write');
          }
          return realQuery(sql, params) as Promise<{ rows: T[]; rowCount?: number | null }>;
        },
      };

      const promoterA = new PromotionService({
        db: failingDb,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      const claimedA = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-fail');
      expect(claimedA).not.toBeNull();

      const resultA = await promoterA.promote(claimedA!);
      expect(resultA.success).toBe(false);

      // Verify: The S3 object in clean storage WAS written (S3 is WORM, not rolled back by Postgres)
      const headAfterFail = await s3Provider.head({ bucket: CLEAN_BUCKET, key: cleanKey });
      expect(headAfterFail.versionId).toBeDefined();

      // Verify: In Postgres, cloud_objects has NO record! files.status is still QUARANTINED!
      const coAfterFail = await adminPool.query(
        `SELECT * FROM cloud_objects WHERE file_version_id = $1 AND zone = 'clean'`,
        [fix.fileVersionId],
      );
      expect(coAfterFail.rows).toHaveLength(0);

      const fAfterFail = await adminPool.query(`SELECT status FROM files WHERE id = $1`, [
        fix.fileId,
      ]);
      expect(fAfterFail.rows[0].status).toBe('QUARANTINED');

      // Verify int-01 invariant holds (0 rows)
      await assertInt01Invariant();

      // PART B: Job retry with Safe Orphan Reconciliation
      // Reset promotion job to QUEUED so worker can claim it
      await adminPool.query(
        `UPDATE promotion_jobs SET status = 'QUEUED', locked_by = null, locked_at = null WHERE id = $1`,
        [fix.jobId],
      );

      const promoterB = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      const claimedB = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-retry');
      expect(claimedB).not.toBeNull();

      // putIfAbsent will throw AlreadyExists.
      // Safe Orphan Reconciliation inspects the existing S3 object, verifies AAD & SHA-256 cryptographically,
      // and safely adopts it into cloud_objects!
      const resultB = await promoterB.promote(claimedB!);

      expect(resultB.success).toBe(true);
      expect(resultB.outcome).toBe('PROMOTED');

      // Verify: cloud_objects now has the clean record
      const coAfterRetry = await adminPool.query(
        `SELECT * FROM cloud_objects WHERE file_version_id = $1 AND zone = 'clean'`,
        [fix.fileVersionId],
      );
      expect(coAfterRetry.rows).toHaveLength(1);
      expect(coAfterRetry.rows[0].object_key).toBe(cleanKey);

      // Verify: file is now PROMOTED
      const fAfterRetry = await adminPool.query(`SELECT status FROM files WHERE id = $1`, [
        fix.fileId,
      ]);
      expect(fAfterRetry.rows[0].status).toBe('PROMOTED');

      // Verify: promotion_job is SUCCEEDED
      const pjAfterRetry = await adminPool.query(
        `SELECT status, outcome FROM promotion_jobs WHERE id = $1`,
        [fix.jobId],
      );
      expect(pjAfterRetry.rows[0].status).toBe('SUCCEEDED');
      expect(pjAfterRetry.rows[0].outcome).toBe('PROMOTED');

      // Verify int-01 invariant holds
      await assertInt01Invariant();
    });

    it('rejects adoption if pre-existing clean storage object has conflicting or unverified payload', async () => {
      const fix = await createFixture();
      const cleanKey = `objects/${fix.appId}/${fix.fileId}`;

      // Attacker or unverified rogue process uploaded an unverified object under cleanKey
      await rawS3.send(
        new PutObjectCommand({
          Bucket: CLEAN_BUCKET,
          Key: cleanKey,
          Body: Buffer.from('ROGUE CONTENT NOT ENCRYPTED WITH SUG1', 'utf8'),
        }),
      );

      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-conflict');
      expect(claimed).not.toBeNull();

      // Must fail closed with ALREADY_EXISTS and transition file status to ERROR
      const result = await promoter.promote(claimed!);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('ALREADY_EXISTS');

      const fRes = await adminPool.query(`SELECT status FROM files WHERE id = $1`, [fix.fileId]);
      expect(fRes.rows[0].status).toBe('ERROR');

      // cloud_objects must not record this unverified object
      const coRes = await adminPool.query(
        `SELECT * FROM cloud_objects WHERE file_version_id = $1 AND zone = 'clean'`,
        [fix.fileVersionId],
      );
      expect(coRes.rows).toHaveLength(0);

      await assertInt01Invariant();
    });
  });

  describe('6. Encryption / KEK Failure — Fail-Closed with Zero Plaintext Publication', () => {
    it('fails closed when KEK is missing or invalid, setting file to QUARANTINED with zero clean storage writes', async () => {
      const fix = await createFixture();

      // Configure an empty key provider with no matching KEK
      const emptyKeyProvider = new LocalKeyProvider({
        keys: {},
      });

      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider: emptyKeyProvider,
      });

      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-kek-fail');
      expect(claimed).not.toBeNull();

      const result = await promoter.promote(claimed!);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('ENCRYPTION_FAILED');

      // Zero clean storage objects created
      const cleanKey = `objects/${fix.appId}/${fix.fileId}`;
      await expect(s3Provider.head({ bucket: CLEAN_BUCKET, key: cleanKey })).rejects.toThrow();

      // File remains in QUARANTINED status for retry
      const fRes = await adminPool.query(`SELECT status FROM files WHERE id = $1`, [fix.fileId]);
      expect(fRes.rows[0].status).toBe('QUARANTINED');

      await assertInt01Invariant();
    });
  });

  describe('7. Verify-Before-Release Download API & Tampered Ciphertext/AAD', () => {
    it('serves promoted file over both route aliases (/api/v1/files/:id and /files/:id) with strict security headers', async () => {
      const fix = await createFixture();

      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-dl');
      await promoter.promote(claimed!);

      // Test route alias 1: /api/v1/files/:id
      const res1 = await app.inject({
        method: 'GET',
        url: `/api/v1/files/${fix.fileId}`,
        headers: {
          authorization: `Bearer ${fix.rawApiKey}`,
        },
      });

      expect(res1.statusCode).toBe(200);
      expect(res1.headers['content-type']).toBe('application/octet-stream');
      expect(res1.headers['content-disposition']).toContain('attachment; filename="payroll.pdf"');
      expect(res1.headers['x-content-type-options']).toBe('nosniff');
      expect(res1.headers['content-security-policy']).toBe("default-src 'none'; sandbox");
      expect(res1.headers['cache-control']).toBe('no-store, private');
      expect(res1.headers['x-payload-sha256']).toBe(fix.sha256Hex);
      expect(res1.body).toBe(fix.plaintext.toString('utf8'));

      // Test route alias 2: /files/:id
      const res2 = await app.inject({
        method: 'GET',
        url: `/files/${fix.fileId}`,
        headers: {
          authorization: `Bearer ${fix.rawApiKey}`,
        },
      });
      expect(res2.statusCode).toBe(200);
      expect(res2.body).toBe(fix.plaintext.toString('utf8'));

      // Audit event FILE_DOWNLOADED recorded
      const auditRes = await adminPool.query(
        `SELECT * FROM audit_events WHERE action = 'FILE_DOWNLOADED' AND file_id = $1`,
        [fix.fileId],
      );
      expect(auditRes.rows.length).toBeGreaterThanOrEqual(1);
    });

    it('returns HTTP 500 and releases ZERO plaintext bytes when ciphertext in clean storage is tampered', async () => {
      const fix = await createFixture();

      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });

      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-tamper');
      const promoResult = await promoter.promote(claimed!);
      expect(promoResult.success).toBe(true);

      const cleanKey = `objects/${fix.appId}/${fix.fileId}`;

      // Tamper: Fetch clean envelope from S3, corrupt 1 byte of ciphertext, and write back to S3 under the same key
      const cleanObj = await s3Provider.getByVersion({
        bucket: CLEAN_BUCKET,
        key: cleanKey,
        versionId: promoResult.cleanStorageVersionId!,
      });
      const chunks: Buffer[] = [];
      for await (const chunk of cleanObj.body) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      const tamperedEnvelope = Buffer.concat(chunks);
      // Flip a bit in the ciphertext / auth tag area
      tamperedEnvelope[tamperedEnvelope.length - 5] ^= 0xff;

      const putTamperRes = await rawS3.send(
        new PutObjectCommand({
          Bucket: CLEAN_BUCKET,
          Key: cleanKey,
          Body: tamperedEnvelope,
        }),
      );

      // Update cloud_objects to point to the tampered version
      await adminPool.query(
        `UPDATE cloud_objects SET storage_version_id = $1 WHERE file_version_id = $2 AND zone = 'clean'`,
        [putTamperRes.VersionId, fix.fileVersionId],
      );

      // Attempt download: verify-before-release MUST catch AES-GCM tag mismatch, return 500, and release zero plaintext
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/files/${fix.fileId}`,
        headers: {
          authorization: `Bearer ${fix.rawApiKey}`,
        },
      });

      expect(res.statusCode).toBe(500);
      const problem = res.json();
      expect(problem.title).toBe('Decryption Failed');
      expect(problem.detail).toContain('plaintext rejected before release');
      expect(res.body).not.toContain(fix.plaintext.toString('utf8'));
    });
  });

  describe('8. authz-07: Cross-Tenant Isolation, RBAC, and Deletion Lifecycle', () => {
    it('enforces strict tenant application isolation (Application B cannot download or delete Application A file)', async () => {
      const fixA = await createFixture();
      const fixB = await createFixture();

      // Promote file A
      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });
      const claimedA = await claimSpecificJob(adminPool, fixA.jobId, 'test-promoter-authz-a');
      await promoter.promote(claimedA!);

      // Tenant B attempts to download Tenant A file
      const dlRes = await app.inject({
        method: 'GET',
        url: `/api/v1/files/${fixA.fileId}`,
        headers: {
          authorization: `Bearer ${fixB.rawApiKey}`,
        },
      });
      expect(dlRes.statusCode).toBe(403);
      expect(dlRes.json().detail).toContain('file belongs to another application');

      // Tenant B attempts to delete Tenant A file
      const delRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/files/${fixA.fileId}`,
        headers: {
          authorization: `Bearer ${fixB.rawApiKey}`,
        },
      });
      expect(delRes.statusCode).toBe(403);
      expect(delRes.json().detail).toContain('another application');
    });

    it('enforces RBAC on deletion (analyst/auditor 403, admin 204) and handles download after deletion', async () => {
      const fix = await createFixture();

      // Promote file
      const promoter = new PromotionService({
        db: adminPool,
        storageProvider: s3Provider,
        cleanBucket: CLEAN_BUCKET,
        keyProvider,
      });
      const claimed = await claimSpecificJob(adminPool, fix.jobId, 'test-promoter-rbac');
      await promoter.promote(claimed!);

      // Create dashboard user tokens
      const analystToken = await createDashboardToken(
        { id: crypto.randomUUID(), email: 'analyst@sec.internal', role: 'analyst' },
        jwtPrivateKeyPem,
      );
      const auditorToken = await createDashboardToken(
        { id: crypto.randomUUID(), email: 'auditor@sec.internal', role: 'auditor' },
        jwtPrivateKeyPem,
      );
      const adminToken = await createDashboardToken(
        { id: fix.userId, email: 'admin@sec.internal', role: 'admin' },
        jwtPrivateKeyPem,
      );

      // Analyst deletion attempt -> 403
      const analystDelRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/files/${fix.fileId}`,
        headers: { authorization: `Bearer ${analystToken}` },
      });
      expect(analystDelRes.statusCode).toBe(403);
      expect(analystDelRes.json().detail).toContain(
        "Role 'analyst' is not authorized to delete files",
      );

      // Auditor deletion attempt -> 403
      const auditorDelRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/files/${fix.fileId}`,
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      expect(auditorDelRes.statusCode).toBe(403);
      expect(auditorDelRes.json().detail).toContain(
        "Role 'auditor' is not authorized to delete files",
      );

      // Admin deletion attempt -> 204 No Content
      const adminDelRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/files/${fix.fileId}`,
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(adminDelRes.statusCode).toBe(204);

      // Verify file is soft-deleted in database
      const fRes = await adminPool.query(`SELECT status, deleted_at FROM files WHERE id = $1`, [
        fix.fileId,
      ]);
      expect(fRes.rows[0].status).toBe('DELETED');
      expect(fRes.rows[0].deleted_at).not.toBeNull();

      // Audit event FILE_DELETED recorded
      const auditRes = await adminPool.query(
        `SELECT * FROM audit_events WHERE action = 'FILE_DELETED' AND file_id = $1`,
        [fix.fileId],
      );
      expect(auditRes.rows).toHaveLength(1);

      // Subsequent download attempt returns 404 File Deleted
      const dlAfterDelRes = await app.inject({
        method: 'GET',
        url: `/api/v1/files/${fix.fileId}`,
        headers: { authorization: `Bearer ${fix.rawApiKey}` },
      });
      expect(dlAfterDelRes.statusCode).toBe(404);
      expect(dlAfterDelRes.json().title).toBe('File Deleted');
    });
  });
});
