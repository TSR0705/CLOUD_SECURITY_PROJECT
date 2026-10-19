/**
 * @sug/test/integration/audit/p21-audit.test.ts
 *
 * Comprehensive Adversarial Integration Test Suite for Phase P21:
 * - audit-01: Unbroken audit chain verification end-to-end
 * - audit-02: Checkpoint creation, Ed25519 signature verification, S3 storage-first persistence, orphan reconciliation
 * - audit-03: Superuser tamper detection (event_hash bitflip, payload modification, interior deletion)
 * - decision.reviewed: Regression test verifying audit_append argument ordering and live PostgreSQL insertion
 * - Tenant isolation & security-events query filtering and RBAC
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
  GetObjectCommand,
} from '@aws-sdk/client-s3';
import { createS3Provider, type StorageProvider } from '@sug/storage';
import { loadConfig } from '@sug/shared/config';
import {
  verifyAuditChainFromDb,
  createAuditCheckpoint,
  verifyCheckpointSignature,
  formatCheckpointKey,
  type AuditCheckpoint,
} from '@sug/audit';
import { createApp } from '../../../services/api/src/app.js';
import { generateRawKey, computeKeyHmac } from '../../../services/api/src/auth/keys.js';
import { createDashboardToken } from '../../../services/api/src/auth/jwt.js';
import { createPool, createBaseFixtures, type FixtureContext } from '../db/helpers.js';

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
const AUDIT_BUCKET = 'sug-audit-local';

describe('Phase P21 Adversarial Integration — Audit Chain & Checkpoints', () => {
  let pool: pg.Pool;
  let rawS3: S3Client;
  let s3Provider: StorageProvider;
  let app: FastifyInstance;
  let jwtPrivateKeyPem: string;
  let checkpointPrivateKeyPem: string;
  let checkpointPublicKeyPem: string;
  let fixtures: FixtureContext;
  let adminToken: string;
  let auditorToken: string;
  let analystToken: string;
  let validApiKey: string;

  beforeAll(async () => {
    pool = createPool('sug_admin', 'sug_dev_password', 15);

    // Ensure LocalStack S3 audit bucket exists with versioning enabled
    rawS3 = new S3Client({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
      forcePathStyle: true,
    });

    try {
      await rawS3.send(new HeadBucketCommand({ Bucket: AUDIT_BUCKET }));
    } catch {
      await rawS3.send(new CreateBucketCommand({ Bucket: AUDIT_BUCKET }));
    }
    await rawS3.send(
      new PutBucketVersioningCommand({
        Bucket: AUDIT_BUCKET,
        VersioningConfiguration: { Status: 'Enabled' },
      }),
    );

    s3Provider = createS3Provider({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
      forcePathStyle: true,
    });

    // Load Checkpoint Ed25519 keys
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    checkpointPrivateKeyPem = fs.readFileSync(
      path.resolve(secretsDir, 'checkpoint_private_key.pem'),
      'utf8',
    );
    checkpointPublicKeyPem = fs.readFileSync(
      path.resolve(secretsDir, 'checkpoint_public_key.pem'),
      'utf8',
    );

    // Generate JWT keys
    const jwtPair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    jwtPrivateKeyPem = jwtPair.privateKey;

    // Load base fixtures
    fixtures = await createBaseFixtures(pool);

    const baseConfig = loadConfig({ secretsDir });

    // Create real API key in DB matching canonical format
    const generated = generateRawKey();
    validApiKey = generated.rawKey;
    const keyHmac = computeKeyHmac(generated.secret, baseConfig.secrets.pepper);

    await pool.query(
      `INSERT INTO api_keys (application_id, key_prefix, key_hmac, created_by, scopes)
       VALUES ($1, $2, $3, $4, '{"audit:read", "files:read"}')`,
      [fixtures.appId, generated.keyPrefix, keyHmac, fixtures.userId],
    );

    // Generate JWT tokens
    adminToken = await createDashboardToken(
      { id: fixtures.userId, email: 'admin@sug.test', role: 'admin', is_active: true },
      jwtPrivateKeyPem,
    );
    auditorToken = await createDashboardToken(
      { id: crypto.randomUUID(), email: 'auditor@sug.test', role: 'auditor', is_active: true },
      jwtPrivateKeyPem,
    );
    analystToken = await createDashboardToken(
      { id: crypto.randomUUID(), email: 'analyst@sug.test', role: 'analyst', is_active: true },
      jwtPrivateKeyPem,
    );

    const testConfig = {
      ...baseConfig,
      secrets: {
        ...baseConfig.secrets,
        jwtPrivateKey: jwtPrivateKeyPem,
        checkpointPrivateKey: checkpointPrivateKeyPem,
      },
    };

    app = await createApp({
      config: testConfig,
      authDb: pool,
      storageProvider: s3Provider,
      checkpointPrivateKeyPem,
      checkpointPublicKeyPem,
      logger: false,
    });
  });

  afterAll(async () => {
    if (app) await app.close();
    if (pool) await pool.end();
  }, 15000);

  describe('audit-01: End-to-End Chain Verification', () => {
    it('verifies unbroken audit chain directly via database stream and API', async () => {
      // Append several distinct events
      const ap1 = await pool.query<{ seq: string }>(
        `SELECT audit_append('service', 'p21_tester', 'SYSTEM_PROBE_1', $1::jsonb, '{"phase": "p21"}'::jsonb) as seq`,
        [JSON.stringify({ application_id: fixtures.appId })],
      );
      const ap2 = await pool.query<{ seq: string }>(
        `SELECT audit_append('service', 'p21_tester', 'SYSTEM_PROBE_2', $1::jsonb, '{"phase": "p21"}'::jsonb) as seq`,
        [JSON.stringify({ application_id: fixtures.appId })],
      );
      const seq1 = ap1.rows[0].seq;
      const seq2 = ap2.rows[0].seq;

      // Verify the slice with recomputeHashes: true
      const sliceResult = await verifyAuditChainFromDb(pool, {
        fromSeq: seq1,
        toSeq: seq2,
        recomputeHashes: true,
      });
      expect(sliceResult.valid).toBe(true);

      // Verify the full chain from genesis
      const dbVerifyResult = await verifyAuditChainFromDb(pool);
      expect(dbVerifyResult.valid).toBe(true);
      if (dbVerifyResult.valid) {
        expect(dbVerifyResult.verifiedCount).toBeGreaterThanOrEqual(2);
        expect(typeof dbVerifyResult.headHash).toBe('string');
        expect(dbVerifyResult.headHash.length).toBe(64);
      }

      // Verify through GET /audit/verify endpoint with Auditor JWT
      const res = await app.inject({
        method: 'GET',
        url: '/audit/verify',
        headers: { authorization: `Bearer ${auditorToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('VALID');
      expect(body.valid).toBe(true);
      expect(body.verifiedCount).toBeGreaterThanOrEqual(2);
      expect(typeof body.headHash).toBe('string');

      // Canonical alias /api/v1/audit/verify returns identical response
      const resV1 = await app.inject({
        method: 'GET',
        url: '/api/v1/audit/verify',
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      expect(resV1.statusCode).toBe(200);
      expect(resV1.body).toBe(res.body);
    });

    it('enforces RBAC on verification: rejects unauthenticated (401), API key (403), analyst (403)', async () => {
      // 1. Unauthenticated
      const unauth = await app.inject({ method: 'GET', url: '/audit/verify' });
      expect(unauth.statusCode).toBe(401);

      // 2. API key
      const apiKeyRes = await app.inject({
        method: 'GET',
        url: '/audit/verify',
        headers: { authorization: `Bearer ${validApiKey}` },
      });
      expect(apiKeyRes.statusCode).toBe(403);

      // 3. Analyst
      const analystRes = await app.inject({
        method: 'GET',
        url: '/audit/verify',
        headers: { authorization: `Bearer ${analystToken}` },
      });
      expect(analystRes.statusCode).toBe(403);
    });
  });

  describe('audit-02: Checkpoint Creation & Storage-First Persistence', () => {
    it('creates Ed25519-signed checkpoint, persists to S3, records in DB, and audits creation', async () => {
      // Trigger checkpoint creation via API with Admin JWT
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/audit/checkpoints',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.checkpoint).toBeDefined();
      const cp: AuditCheckpoint = body.checkpoint;

      expect(cp.schema).toBe('sug.audit_checkpoint/v1');
      expect(BigInt(cp.lastSeq)).toBeGreaterThan(0n);
      expect(typeof cp.chainHash).toBe('string');
      expect(typeof cp.signature).toBe('string');
      expect(body.s3VersionId).toBeDefined();
      expect(body.storedInDb).toBe(true);

      // 1. Verify cryptographic signature with public key
      const sigValid = verifyCheckpointSignature(cp, checkpointPublicKeyPem);
      expect(sigValid).toBe(true);

      // 2. Verify object exists in LocalStack S3
      const key = formatCheckpointKey(cp.lastSeq);
      const s3Obj = await rawS3.send(
        new GetObjectCommand({
          Bucket: AUDIT_BUCKET,
          Key: key,
          VersionId: body.s3VersionId,
        }),
      );
      const s3ContentStr = await s3Obj.Body?.transformToString();
      expect(s3ContentStr).toBeDefined();
      const s3Json = JSON.parse(s3ContentStr!);
      expect(s3Json.signature).toBe(cp.signature);
      expect(s3Json.lastSeq).toBe(cp.lastSeq);

      // 3. Verify record in PostgreSQL audit_checkpoints table
      const dbRow = await pool.query('SELECT * FROM audit_checkpoints WHERE last_seq = $1', [
        cp.lastSeq,
      ]);
      expect(dbRow.rows.length).toBe(1);
      expect(dbRow.rows[0].s3_version_id).toBe(body.s3VersionId);
      expect(dbRow.rows[0].signature.toString('hex')).toBe(cp.signature);

      // 4. Verify audit_events recorded 'checkpoint.created'
      const auditRow = await pool.query(
        "SELECT * FROM audit_events WHERE action = 'checkpoint.created' ORDER BY seq DESC LIMIT 1",
      );
      expect(auditRow.rows.length).toBe(1);
      expect((auditRow.rows[0].details as { last_seq?: string })?.last_seq).toBe(cp.lastSeq);
    });

    it('safely reconciles orphan when S3 write already exists before DB commit', async () => {
      // Append a fresh event to ensure checkpoint has a unique latest seq
      const appendRes = await pool.query<{ seq: string }>(
        `SELECT audit_append('service', 'orphan_test', 'ORPHAN_PREPARE', '{}'::jsonb, '{}'::jsonb) as seq`,
      );
      const lastSeq = appendRes.rows[0].seq;

      // Pre-populate S3 object to simulate an orphan scenario
      const key = formatCheckpointKey(lastSeq);
      const simulatedCheckpoint: AuditCheckpoint = {
        schema: 'sug.audit_checkpoint/v1',
        checkpointId: crypto.randomUUID(),
        createdAt: new Date().toISOString(),
        lastSeq: lastSeq.toString(),
        chainHash: crypto.randomBytes(32).toString('hex'),
        signature: crypto.randomBytes(64).toString('hex'),
        signerKeyId: 'ed25519-2026',
      };

      await rawS3.send(
        new PutObjectCommand({
          Bucket: AUDIT_BUCKET,
          Key: key,
          Body: Buffer.from(JSON.stringify(simulatedCheckpoint), 'utf8'),
          ContentType: 'application/json',
        }),
      );

      // Calling createAuditCheckpoint should detect existing S3 object via head and reconcile without error
      const reconciled = await createAuditCheckpoint({
        db: pool,
        storage: s3Provider,
        auditBucket: AUDIT_BUCKET,
        privateKeyPem: checkpointPrivateKeyPem,
        publicKeyPem: checkpointPublicKeyPem,
      });

      expect(reconciled).toBeDefined();
      expect(reconciled.storedInDb).toBe(true);
      expect(reconciled.s3VersionId).toBeDefined();
    });
  });

  describe('audit-03: Superuser Tamper Detection', () => {
    it('detects event_hash corruption by superuser at exact sequence number', async () => {
      // Append two consecutive target events
      const targetRes = await pool.query<{ seq: string }>(
        `SELECT audit_append('service', 'tamper_sec', 'TARGET_EVENT_A', '{}'::jsonb, '{"payload": 100}'::jsonb) as seq`,
      );
      const targetSeq = targetRes.rows[0].seq;

      const followRes = await pool.query<{ seq: string }>(
        `SELECT audit_append('service', 'tamper_sec', 'FOLLOW_EVENT_A', '{}'::jsonb, '{"payload": 101}'::jsonb) as seq`,
      );
      const nextSeq = followRes.rows[0].seq;

      const targetOriginal = await pool.query(
        'SELECT event_hash FROM audit_events WHERE seq = $1',
        [targetSeq],
      );
      const originalHash = targetOriginal.rows[0].event_hash as Buffer;

      // Superuser bypasses triggers to corrupt event_hash
      const client = await pool.connect();
      try {
        await client.query('ALTER TABLE audit_events DISABLE TRIGGER ALL');
        const tamperedHash = Buffer.from(originalHash);
        tamperedHash[0] ^= 0xff; // Flip first byte
        await client.query('UPDATE audit_events SET event_hash = $1 WHERE seq = $2', [
          tamperedHash,
          targetSeq,
        ]);
        await client.query('ALTER TABLE audit_events ENABLE TRIGGER ALL');

        // Verification must fail at nextSeq because its prev_hash does not match tamperedHash!
        const verifyRes = await app.inject({
          method: 'GET',
          url: '/audit/verify',
          headers: { authorization: `Bearer ${auditorToken}` },
        });

        expect(verifyRes.statusCode).toBe(200);
        const body = JSON.parse(verifyRes.body);
        expect(body.status).toBe('INVALID');
        expect(body.valid).toBe(false);
        expect(body.failedSeq.toString()).toBe(nextSeq);
        expect(body.failureCategory).toBe('CHAIN_BROKEN');
      } finally {
        // Restore original hash
        await client.query('ALTER TABLE audit_events DISABLE TRIGGER ALL');
        await client.query('UPDATE audit_events SET event_hash = $1 WHERE seq = $2', [
          originalHash,
          targetSeq,
        ]);
        await client.query('ALTER TABLE audit_events ENABLE TRIGGER ALL');
        client.release();
      }

      // Verify chain is valid again after restoration
      const restoredRes = await app.inject({
        method: 'GET',
        url: '/audit/verify',
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      const restoredBody = JSON.parse(restoredRes.body);
      expect(restoredBody.status).toBe('VALID');
      expect(restoredBody.valid).toBe(true);
    });

    it('detects payload tampering by superuser via byte-for-byte hash recomputation', async () => {
      // Append target event
      const targetRes = await pool.query<{ seq: string }>(
        `SELECT audit_append('service', 'tamper_payload', 'AUTHENTIC_DATA', '{}'::jsonb, '{"approved": true}'::jsonb) as seq`,
      );
      const targetSeq = targetRes.rows[0].seq;

      // Superuser tampers with details jsonb without changing event_hash
      const client = await pool.connect();
      try {
        await client.query('ALTER TABLE audit_events DISABLE TRIGGER ALL');
        await client.query(
          `UPDATE audit_events SET details = '{"approved": false, "tampered": true}'::jsonb WHERE seq = $1`,
          [targetSeq],
        );
        await client.query('ALTER TABLE audit_events ENABLE TRIGGER ALL');

        // Verification on slice with recompute_hashes=true must detect the content mismatch!
        const verifyRes = await app.inject({
          method: 'GET',
          url: `/audit/verify?from_seq=${targetSeq}&to_seq=${targetSeq}&recompute_hashes=true`,
          headers: { authorization: `Bearer ${auditorToken}` },
        });

        expect(verifyRes.statusCode).toBe(200);
        const body = JSON.parse(verifyRes.body);
        expect(body.status).toBe('INVALID');
        expect(body.valid).toBe(false);
        expect(body.failedSeq.toString()).toBe(targetSeq);
        expect(body.failureCategory).toBe('HASH_MISMATCH');
      } finally {
        // Restore authentic details
        await client.query('ALTER TABLE audit_events DISABLE TRIGGER ALL');
        await client.query(
          `UPDATE audit_events SET details = '{"approved": true}'::jsonb WHERE seq = $1`,
          [targetSeq],
        );
        await client.query('ALTER TABLE audit_events ENABLE TRIGGER ALL');
        client.release();
      }

      // Verify chain slice is valid again
      const restoredRes = await app.inject({
        method: 'GET',
        url: `/audit/verify?from_seq=${targetSeq}&to_seq=${targetSeq}&recompute_hashes=true`,
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      expect(JSON.parse(restoredRes.body).status).toBe('VALID');
    });

    it('detects deletion of interior audit event by superuser', async () => {
      // Append three events
      await pool.query(
        `SELECT audit_append('service', 'del_test', 'BEFORE_DEL', '{}'::jsonb, '{}'::jsonb)`,
      );
      const toDeleteRes = await pool.query<{ seq: string }>(
        `SELECT audit_append('service', 'del_test', 'TO_DELETE', '{}'::jsonb, '{}'::jsonb) as seq`,
      );
      const delSeq = toDeleteRes.rows[0].seq;
      const afterRes = await pool.query<{ seq: string }>(
        `SELECT audit_append('service', 'del_test', 'AFTER_DEL', '{}'::jsonb, '{}'::jsonb) as seq`,
      );
      const afterSeq = afterRes.rows[0].seq;

      // Save deleted record so we can restore it cleanly
      const savedRow = await pool.query('SELECT * FROM audit_events WHERE seq = $1', [delSeq]);

      const client = await pool.connect();
      try {
        await client.query('ALTER TABLE audit_events DISABLE TRIGGER ALL');
        await client.query('DELETE FROM audit_events WHERE seq = $1', [delSeq]);
        await client.query('ALTER TABLE audit_events ENABLE TRIGGER ALL');

        // Verification must detect the missing link at the successor event
        const verifyRes = await app.inject({
          method: 'GET',
          url: '/audit/verify',
          headers: { authorization: `Bearer ${auditorToken}` },
        });

        expect(verifyRes.statusCode).toBe(200);
        const body = JSON.parse(verifyRes.body);
        expect(body.status).toBe('INVALID');
        expect(body.valid).toBe(false);
        expect(body.failedSeq.toString()).toBe(afterSeq);
        expect(body.failureCategory).toBe('CHAIN_BROKEN');
      } finally {
        // Restore deleted row using OVERRIDING SYSTEM VALUE
        const r = savedRow.rows[0];
        await client.query('ALTER TABLE audit_events DISABLE TRIGGER ALL');
        await client.query(
          `INSERT INTO audit_events (
             seq, id, occurred_at, actor_type, actor_id, action,
             application_id, file_id, file_version_id, decision_id,
             request_id, ip, details, prev_hash, event_hash
           ) OVERRIDING SYSTEM VALUE VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
          [
            r.seq,
            r.id,
            r.occurred_at,
            r.actor_type,
            r.actor_id,
            r.action,
            r.application_id,
            r.file_id,
            r.file_version_id,
            r.decision_id,
            r.request_id,
            r.ip,
            JSON.stringify(r.details),
            r.prev_hash,
            r.event_hash,
          ],
        );
        await client.query('ALTER TABLE audit_events ENABLE TRIGGER ALL');
        client.release();
      }

      // Verify chain is valid again
      const restoredRes = await app.inject({
        method: 'GET',
        url: '/audit/verify',
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      expect(JSON.parse(restoredRes.body).status).toBe('VALID');
    });
  });

  describe('decision.reviewed Regression Test', () => {
    it('successfully appends decision.reviewed audit event with live PostgreSQL database', async () => {
      // 1. Create a quarantined decision row using exact schema columns
      const decRes = await pool.query(
        `INSERT INTO security_decisions (
           file_version_id, policy_id, decision, primary_reason,
           severity, confidence, risk_score, policy_result, scanner_result,
           integrity_result, authorization_result, bound_bucket, bound_key,
           bound_storage_version_id, bound_sha256, bound_size, record,
           engine_version, decided_by
         )
         VALUES (
           $1, $2, 'QUARANTINE', 'SUSPICIOUS_MIME',
           'MEDIUM', 'CONFIRMED', 50, 'PASS', 'FLAGGED',
           'MATCH', 'AUTHORIZED', 'sug-quarantine', 'sample/key',
           'v1', decode(repeat('aa', 32), 'hex'), 1024, '{}',
           '1.0.0', 'evaluator-service'
         )
         RETURNING id`,
        [fixtures.fileVersionId, fixtures.policyId],
      );
      const decisionId = decRes.rows[0].id;

      // 2. Execute decision review via API
      const reviewRes = await app.inject({
        method: 'POST',
        url: `/api/v1/security-decisions/${decisionId}/review`,
        headers: { authorization: `Bearer ${adminToken}` },
        payload: {
          action: 'ALLOW',
          justification:
            'Manual analyst override: file confirmed safe by secondary detonation chamber',
        },
      });

      expect(reviewRes.statusCode).toBe(201);
      const newDecision = JSON.parse(reviewRes.body);
      expect(newDecision.decision).toBe('ALLOW');

      // 3. Verify audit_events record was created without argument ordering error
      const auditRes = await pool.query(
        `SELECT * FROM audit_events
         WHERE action = 'decision.reviewed'
           AND decision_id = $1`,
        [newDecision.id],
      );

      expect(auditRes.rows.length).toBe(1);
      const auditRow = auditRes.rows[0];
      expect(auditRow.actor_type).toBe('user');
      expect(auditRow.actor_id).toBe(fixtures.userId);
      expect(auditRow.application_id).toBe(fixtures.appId);
      expect(auditRow.file_id).toBe(fixtures.fileId);

      const details = auditRow.details as {
        priorDecisionId: string;
        priorDecision: string;
        newDecision: string;
        justification: string;
      };
      expect(details.priorDecisionId).toBe(decisionId);
      expect(details.priorDecision).toBe('QUARANTINE');
      expect(details.newDecision).toBe('ALLOW');
      expect(details.justification).toContain('Manual analyst override');

      // 4. Verify hash chain is unbroken after the review event
      const verifyRes = await verifyAuditChainFromDb(pool);
      expect(verifyRes.valid).toBe(true);
    });
  });

  describe('Tenant Isolation & Query Filtering (/security-events)', () => {
    it('restricts API key strictly to its own application_id and rejects cross-tenant query with 403', async () => {
      const otherAppId = crypto.randomUUID();

      // Query with API key without filter -> returns only events for fixtures.appId
      const ownRes = await app.inject({
        method: 'GET',
        url: '/security-events',
        headers: { authorization: `Bearer ${validApiKey}` },
      });

      expect(ownRes.statusCode).toBe(200);
      const ownBody = JSON.parse(ownRes.body);
      expect(ownBody.events).toBeDefined();
      for (const ev of ownBody.events) {
        expect(ev.application_id).toBe(fixtures.appId);
      }

      // Query with other application_id -> 403 Forbidden
      const crossRes = await app.inject({
        method: 'GET',
        url: `/security-events?application_id=${otherAppId}`,
        headers: { authorization: `Bearer ${validApiKey}` },
      });

      expect(crossRes.statusCode).toBe(403);
      const crossBody = JSON.parse(crossRes.body);
      expect(crossBody.title).toBe('Forbidden');
    });

    it('allows Auditor to query security events across all tenants', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/security-events?limit=50',
        headers: { authorization: `Bearer ${auditorToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(Array.isArray(body.events)).toBe(true);
      expect(body.events.length).toBeGreaterThan(0);
    });
  });
});
