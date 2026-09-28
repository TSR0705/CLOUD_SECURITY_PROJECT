import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import { createApp } from '../../../services/api/src/app.js';
import { ApiKeyService } from '../../../services/api/src/auth/service.js';
import { loadConfig } from '@sug/shared/config';
import { createPool } from '../db/helpers.js';
import {
  toCanonicalJson,
  computePolicyHashHex,
  createImagesOnlyPreset,
  parsePolicyDocument,
} from '@sug/policy-engine';
import { verifyUploadToken } from '../../../services/api/src/upload/upload-token.js';

describe('Phase P8: Policy Engine and Upload Session (DoD Test Suite)', () => {
  let app: FastifyInstance;
  let adminPool: pg.Pool;
  let config: ReturnType<typeof loadConfig>;
  let apiKeyService: ApiKeyService;

  // App A
  let userAId: string;
  let appAId: string;
  let apiKeyARaw: string;

  // App B (for tenant isolation tests)
  let appBId: string;
  let apiKeyBRaw: string;

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    config = loadConfig({ secretsDir });
    adminPool = createPool('sug_admin', 'sug_dev_password');

    // 1. Create test user and two distinct applications
    const userRes = await adminPool.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, 'admin')
       RETURNING id`,
      [`p8_owner_${crypto.randomUUID()}@gateway.internal`, 'argon2id$mock'],
    );
    userAId = userRes.rows[0].id;

    const appARes = await adminPool.query(
      `INSERT INTO applications (name, owner_user_id)
       VALUES ($1, $2)
       RETURNING id`,
      [`app_a_${crypto.randomUUID().slice(0, 12)}`, userAId],
    );
    appAId = appARes.rows[0].id;

    const appBRes = await adminPool.query(
      `INSERT INTO applications (name, owner_user_id)
       VALUES ($1, $2)
       RETURNING id`,
      [`app_b_${crypto.randomUUID().slice(0, 12)}`, userAId],
    );
    appBId = appBRes.rows[0].id;

    // 2. Generate P6 API keys for App A and App B
    apiKeyService = new ApiKeyService({
      db: adminPool,
      pepper: config.secrets.pepper,
    });

    const keyA = await apiKeyService.createApiKey({
      applicationId: appAId,
      createdBy: userAId,
      scopes: ['upload', 'read'],
    });
    apiKeyARaw = keyA.rawKey;

    const keyB = await apiKeyService.createApiKey({
      applicationId: appBId,
      createdBy: userAId,
      scopes: ['upload', 'read'],
    });
    apiKeyBRaw = keyB.rawKey;

    // 3. Boot Fastify app
    app = await createApp({ config, logger: false });
    await app.ready();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (adminPool) {
      await adminPool.end();
    }
  });

  // ============================================================
  // policy-01: Schema validation, canonical JSON & SHA-256 hash
  // ============================================================
  describe('DoD: policy-01 — Policy Schema & Canonical SHA-256 Hash', () => {
    it('creates a policy with un-ordered keys and stores deterministic SHA-256 identity', async () => {
      // Document with arbitrary key ordering
      const rawPolicyDoc = {
        requireMimeMatch: true,
        allowedMimeTypes: ['image/jpeg', 'image/png'],
        name: 'unordered-policy',
        maxFileSize: 5 * 1024 * 1024,
        allowedExtensions: ['.jpg', '.jpeg', '.png'],
        schemaVersion: 'sug.policy/v1',
      };

      const expectedCanonical = toCanonicalJson(parsePolicyDocument(rawPolicyDoc));
      const expectedHash = computePolicyHashHex(expectedCanonical);

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/policies',
        headers: {
          authorization: `Bearer ${apiKeyARaw}`,
        },
        payload: rawPolicyDoc,
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.id).toBeDefined();
      expect(body.applicationId).toBe(appAId);
      expect(body.version).toBe(1);
      expect(body.schemaVersion).toBe('sug.policy/v1');
      expect(body.documentSha256).toBe(expectedHash);
      expect(body.isActive).toBe(true);

      // Verify row in database matches canonical hash
      const dbRow = await adminPool.query(
        'SELECT document_sha256 FROM security_policies WHERE id = $1',
        [body.id],
      );
      expect(dbRow.rows[0].document_sha256.toString('hex')).toBe(expectedHash);
    });

    it('rejects policy creation when schemaVersion is invalid or unsupported', async () => {
      const invalidVersionDoc = {
        schemaVersion: 'sug.policy/v2', // Invalid version
        name: 'bad-version',
        maxFileSize: 1024 * 1024,
        allowedExtensions: ['.pdf'],
        allowedMimeTypes: ['application/pdf'],
      };

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/policies',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: invalidVersionDoc,
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().type).toBe('urn:sug:error:validation');
    });

    it('rejects policy creation with unknown injected properties (.strict())', async () => {
      const injectedDoc = {
        schemaVersion: 'sug.policy/v1',
        name: 'injected-keys',
        maxFileSize: 1024 * 1024,
        allowedExtensions: ['.pdf'],
        allowedMimeTypes: ['application/pdf'],
        bypassScanner: true, // Malicious / unknown property
      };

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/policies',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: injectedDoc,
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().detail).toMatch(/Unrecognized key/i);
    });
  });

  // ============================================================
  // policy-02: Tenant Isolation & Policy Pinning Across Versions
  // ============================================================
  describe('DoD: policy-02 — Tenant Isolation and Policy Pinning', () => {
    let policyV1Id: string;
    let policyV1Hash: string;
    let sessionId: string;

    it('creates active policy v1 for Application A', async () => {
      const doc = createImagesOnlyPreset();
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/policies',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: doc,
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      policyV1Id = body.id;
      policyV1Hash = body.documentSha256;
      expect(body.version).toBeGreaterThanOrEqual(1);
    });

    it('TENANT ISOLATION: Application B cannot view Application A policy (404 zero-oracle)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/policies/${policyV1Id}`,
        headers: { authorization: `Bearer ${apiKeyBRaw}` },
      });

      expect(res.statusCode).toBe(404);
      expect(res.json().type).toBe('urn:sug:error:not-found');
    });

    it('creates upload session pinning policy v1 to session record', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'profile.jpg',
          declaredSize: 1024 * 200,
          declaredMime: 'image/jpeg',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      sessionId = body.sessionId;
      expect(body.policy.id).toBe(policyV1Id);
      expect(body.policy.documentSha256).toBe(policyV1Hash);

      // Verify in DB that policy_id, policy_version, policy_hash are explicitly pinned
      const sessionRow = await adminPool.query(
        'SELECT policy_id, policy_version, policy_hash FROM upload_sessions WHERE id = $1',
        [sessionId],
      );
      expect(sessionRow.rows[0].policy_id).toBe(policyV1Id);
      expect(sessionRow.rows[0].policy_hash.toString('hex')).toBe(policyV1Hash);
    });

    it('updates policy to v2 via PUT /api/v1/policies/:id and verifies v1 remains immutable', async () => {
      const updatedDoc = {
        ...createImagesOnlyPreset(),
        maxFileSize: 20 * 1024 * 1024, // upgraded to 20 MB
      };

      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/policies/${policyV1Id}`,
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: updatedDoc,
      });

      expect(res.statusCode).toBe(200);
      const v2Body = res.json();
      expect(v2Body.id).not.toBe(policyV1Id); // Brand new immutable row!
      expect(v2Body.version).toBeGreaterThan(1);
      expect(v2Body.isActive).toBe(true);

      // Verify v1 in DB was NOT mutated
      const v1Row = await adminPool.query(
        'SELECT document_sha256 FROM security_policies WHERE id = $1',
        [policyV1Id],
      );
      expect(v1Row.rows[0].document_sha256.toString('hex')).toBe(policyV1Hash);
    });

    it('PINNING VERIFICATION: existing session still points to v1 after v2 creation', async () => {
      const sessionRow = await adminPool.query(
        'SELECT policy_id, policy_hash FROM upload_sessions WHERE id = $1',
        [sessionId],
      );
      expect(sessionRow.rows[0].policy_id).toBe(policyV1Id);
      expect(sessionRow.rows[0].policy_hash.toString('hex')).toBe(policyV1Hash);
    });
  });

  // ============================================================
  // val-02: File Extension Validation at API Level
  // ============================================================
  describe('DoD: val-02 — File Extension Validation at API Level', () => {
    it('rejects upload session when extension is not permitted by policy (400 EXTENSION_NOT_ALLOWED)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'report.pdf', // Only images are permitted on App A
          declaredSize: 1024 * 50,
          declaredMime: 'application/pdf',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.type).toBe('urn:sug:error:validation');
      expect(body.detail).toContain('is not permitted by policy');
    });

    it('rejects upload session when extension is explicitly blocked (400 EXTENSION_BLOCKED)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'payload.exe',
          declaredSize: 1024 * 50,
          declaredMime: 'application/x-executable',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.type).toBe('urn:sug:error:validation');
      expect(body.detail).toContain('is explicitly blocked by policy');
    });
  });

  // ============================================================
  // val-05: File Size Limits at API Level
  // ============================================================
  describe('DoD: val-05 — File Size Limits at API Level', () => {
    it('rejects upload session when declared size exceeds policy maxFileSize (400 SIZE_EXCEEDS_POLICY)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'large.jpg',
          declaredSize: 25 * 1024 * 1024, // 25 MB > 20 MB limit
          declaredMime: 'image/jpeg',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.type).toBe('urn:sug:error:validation');
      expect(body.detail).toContain('exceeds policy limit');
    });

    it('rejects upload session when declared size exceeds global ceiling of 50 MB (400 SIZE_EXCEEDS_GLOBAL_LIMIT)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'giant.jpg',
          declaredSize: 55 * 1024 * 1024, // 55 MB > 50 MB
          declaredMime: 'image/jpeg',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.type).toBe('urn:sug:error:validation');
    });

    it('rejects upload session when declared size is <= 0 (400 INVALID_SIZE)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'zero.jpg',
          declaredSize: 0,
          declaredMime: 'image/jpeg',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.type).toBe('urn:sug:error:validation');
    });
  });

  // ============================================================
  // val-09: Filename Normalization and Security Validation
  // ============================================================
  describe('DoD: val-09 — Filename Normalization at API Level', () => {
    it('normalizes path traversal and strips directory components', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: '../../../etc/passwd.jpg',
          declaredSize: 1024 * 100,
          declaredMime: 'image/jpeg',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.precheck.normalizedFilename).toBe('passwd.jpg');

      // Verify database stored the sanitized filename
      const sessionRow = await adminPool.query(
        'SELECT original_filename FROM upload_sessions WHERE id = $1',
        [body.sessionId],
      );
      expect(sessionRow.rows[0].original_filename).toBe('passwd.jpg');
    });

    it('rejects filenames with Unicode Right-to-Left Override (U+202E) spoofing (400 SUSPICIOUS_FILENAME)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'invoice\u202Egpj.exe',
          declaredSize: 1024 * 100,
          declaredMime: 'image/jpeg',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.type).toBe('urn:sug:error:validation');
      expect(body.detail).toContain('Unicode directional override');
    });

    it('rejects filenames with disguised executable double extensions (400 SUSPICIOUS_FILENAME)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'vacation.exe.jpg',
          declaredSize: 1024 * 100,
          declaredMime: 'image/jpeg',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.type).toBe('urn:sug:error:validation');
      expect(body.detail).toContain('disguised executable extension');
    });
  });

  // ============================================================
  // Single-Use Token Claims & Concurrency Protection
  // ============================================================
  describe('Upload Token Single-Use Claim & Concurrency', () => {
    let freshSessionId: string;
    let uploadToken: string;

    beforeAll(async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'valid.jpg',
          declaredSize: 1024 * 100,
          declaredMime: 'image/jpeg',
        },
      });
      const body = res.json();
      freshSessionId = body.sessionId;
      uploadToken = body.uploadToken;
    });

    it('issues an upload token with aud=sug-upload verifiable by EdDSA verifier', async () => {
      const publicKey = crypto.createPublicKey(config.secrets.jwtPrivateKey).export({
        type: 'spki',
        format: 'pem',
      }) as string;

      const payload = await verifyUploadToken(uploadToken, publicKey);
      expect(payload.aud).toBe('sug-upload');
      expect(payload.sub).toBe(appAId);
      expect(payload.sid).toBe(freshSessionId);
    });

    it('first claim succeeds and transitions session to UPLOADING', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/upload/session/${freshSessionId}/claim`,
        headers: { authorization: `Bearer ${uploadToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.claimed).toBe(true);
      expect(body.status).toBe('UPLOADING');
    });

    it('second claim on the same session is rejected with 409 Conflict (ALREADY_CLAIMED)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/upload/session/${freshSessionId}/claim`,
        headers: { authorization: `Bearer ${uploadToken}` },
      });

      expect(res.statusCode).toBe(409);
      const body = res.json();
      expect(body.type).toBe('urn:sug:error:conflict');
      expect(body.detail).toContain('already been claimed');
    });

    it('CONCURRENCY TEST: exactly one of concurrent claims succeeds', async () => {
      // Create another session
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/session',
        headers: { authorization: `Bearer ${apiKeyARaw}` },
        payload: {
          filename: 'race.jpg',
          declaredSize: 1024 * 100,
          declaredMime: 'image/jpeg',
        },
      });
      const { sessionId: raceSessionId, uploadToken: raceToken } = createRes.json();

      // Launch 5 simultaneous claims against the same session
      const attempts = await Promise.all([
        app.inject({
          method: 'POST',
          url: `/api/v1/upload/session/${raceSessionId}/claim`,
          headers: { authorization: `Bearer ${raceToken}` },
        }),
        app.inject({
          method: 'POST',
          url: `/api/v1/upload/session/${raceSessionId}/claim`,
          headers: { authorization: `Bearer ${raceToken}` },
        }),
        app.inject({
          method: 'POST',
          url: `/api/v1/upload/session/${raceSessionId}/claim`,
          headers: { authorization: `Bearer ${raceToken}` },
        }),
      ]);

      const successCount = attempts.filter((r) => r.statusCode === 200).length;
      const conflictCount = attempts.filter((r) => r.statusCode === 409).length;

      expect(successCount).toBe(1);
      expect(conflictCount).toBe(2);
    });
  });

  // ============================================================
  // Audit Trail & Zero Credentials
  // ============================================================
  describe('Audit Trail Verification', () => {
    it('verifies policy and upload session events exist in audit_events with zero credentials', async () => {
      const res = await adminPool.query(
        `SELECT action, actor_type, actor_id, details
         FROM audit_events
         WHERE action IN ('policy.created', 'policy.version_created', 'upload_session.created', 'upload_session.claimed')
         ORDER BY id DESC LIMIT 10`,
      );

      expect(res.rows.length).toBeGreaterThanOrEqual(4);

      for (const row of res.rows) {
        const detailsStr = JSON.stringify(row.details);
        // Ensure no private keys, HMACs, or bearer tokens leaked
        expect(detailsStr).not.toContain('sug_');
        expect(detailsStr).not.toContain('PRIVATE KEY');
        expect(detailsStr).not.toContain('pepper');
      }
    });
  });
});
