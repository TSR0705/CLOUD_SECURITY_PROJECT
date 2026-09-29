import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import { createApp } from '../../../services/api/src/app.js';
import { ApiKeyService } from '../../../services/api/src/auth/service.js';
import { loadConfig } from '@sug/shared/config';
import { createPool } from '../db/helpers.js';
import { createDocumentsPreset } from '@sug/policy-engine';

describe('Phase P10: Streaming Upload and Resource Limits (DoD Test Suite)', () => {
  let app: FastifyInstance;
  let adminPool: pg.Pool;
  let config: ReturnType<typeof loadConfig>;
  let apiKeyService: ApiKeyService;

  let userAId: string;
  let appAId: string;
  let apiKeyARaw: string;

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    config = loadConfig({ secretsDir });
    adminPool = createPool('sug_admin', 'sug_dev_password');

    // 1. Create test user and application
    const userRes = await adminPool.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, 'admin')
       RETURNING id`,
      [`p10_owner_${crypto.randomUUID()}@gateway.internal`, 'argon2id$mock'],
    );
    userAId = userRes.rows[0].id;

    const appARes = await adminPool.query(
      `INSERT INTO applications (name, owner_user_id)
       VALUES ($1, $2)
       RETURNING id`,
      [`app_p10_${crypto.randomUUID().slice(0, 12)}`, userAId],
    );
    appAId = appARes.rows[0].id;

    // 2. Provision API key
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

    // 3. Boot Fastify app
    app = await createApp({ config, logger: false });
    await app.ready();

    // 4. Create standard policy via API (5 MB limit)
    const policyDoc = {
      ...createDocumentsPreset(),
      maxFileSize: 5 * 1024 * 1024, // 5 MB
    };

    const policyRes = await app.inject({
      method: 'POST',
      url: '/api/v1/policies',
      headers: {
        authorization: `Bearer ${apiKeyARaw}`,
        'content-type': 'application/json',
      },
      payload: {
        name: 'p10-standard-policy',
        document: policyDoc,
      },
    });

    expect(policyRes.statusCode).toBe(201);
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (adminPool) {
      await adminPool.end();
    }
  });

  // Helper to create an upload session
  async function createTestSession(params: {
    filename?: string;
    declaredSize?: number;
    declaredMime?: string;
    declaredSha256?: string;
  }) {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/upload/session',
      headers: {
        authorization: `Bearer ${apiKeyARaw}`,
        'content-type': 'application/json',
      },
      payload: {
        filename: params.filename ?? 'test-document.pdf',
        declaredSize: params.declaredSize ?? 1024,
        declaredMime: params.declaredMime ?? 'application/pdf',
        ...(params.declaredSha256 ? { declaredSha256: params.declaredSha256 } : {}),
      },
    });

    expect(res.statusCode).toBe(201);
    return JSON.parse(res.body) as {
      sessionId: string;
      uploadToken: string;
      quarantineKey: string;
    };
  }

  // ============================================================
  // Canonical DoD: val-10 - Lying / Oversized Declared Size
  // ============================================================
  describe('Canonical DoD: val-10 - Oversized Stream & Flat RSS Memory', () => {
    it('returns HTTP 413 when streamed bytes exceed declaredSize', async () => {
      // Declare 100 bytes
      const session = await createTestSession({ declaredSize: 100 });

      // Client streams 50,000 bytes (lying client)
      const oversizedChunk = Buffer.alloc(50_000, 0x41);
      const stream = Readable.from([oversizedChunk]);

      const rssBefore = process.memoryUsage().rss;

      const res = await app.inject({
        method: 'PUT',
        url: `/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'application/octet-stream',
        },
        body: stream,
      });

      const rssAfter = process.memoryUsage().rss;

      expect(res.statusCode).toBe(413);
      const problem = JSON.parse(res.body);
      expect(problem.status).toBe(413);
      expect(problem.type).toBe('urn:sug:error:payload-too-large');

      // Verify RSS memory remains flat (difference < 15MB)
      const rssDeltaMb = Math.abs(rssAfter - rssBefore) / (1024 * 1024);
      expect(rssDeltaMb).toBeLessThan(15);
    });

    it('returns HTTP 413 immediately when Content-Length header exceeds effectiveLimit', async () => {
      // Session declared with 1024 bytes
      const session = await createTestSession({ declaredSize: 1024 });

      const res = await app.inject({
        method: 'PUT',
        url: `/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'application/octet-stream',
          'content-length': '2048', // Exceeds declared 1024 bytes
        },
        body: Readable.from([Buffer.alloc(2048, 0x42)]),
      });

      expect(res.statusCode).toBe(413);
      const problem = JSON.parse(res.body);
      expect(problem.status).toBe(413);
    });

    it('returns HTTP 413 when stream exceeds policy maxFileSize', async () => {
      // Create special policy with 200 bytes limit
      const tightPolicyDoc = {
        ...createDocumentsPreset(),
        maxFileSize: 200,
      };

      const tightPolRes = await app.inject({
        method: 'POST',
        url: '/api/v1/policies',
        headers: {
          authorization: `Bearer ${apiKeyARaw}`,
          'content-type': 'application/json',
        },
        payload: {
          name: 'tight-policy',
          document: tightPolicyDoc,
        },
      });
      expect(tightPolRes.statusCode).toBe(201);

      // Create session under tight policy
      const session = await createTestSession({ declaredSize: 150 });

      // Stream 300 bytes
      const res = await app.inject({
        method: 'PUT',
        url: `/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'application/octet-stream',
        },
        body: Readable.from([Buffer.alloc(300, 0x43)]),
      });

      expect(res.statusCode).toBe(413);
    });
  });

  // ============================================================
  // Canonical DoD: authz-05 - Concurrent Token/Session Reuse Race
  // ============================================================
  describe('Canonical DoD: authz-05 - Concurrent Token Reuse Single-Claim Guarantee', () => {
    it('concurrent token reuse results in exactly one stored object and one successful claim', async () => {
      const data = Buffer.from('Single winner concurrent payload');
      const session = await createTestSession({ declaredSize: data.length });

      // Launch 10 concurrent PUT requests with the identical upload token
      const concurrency = 10;
      const requests = Array.from({ length: concurrency }, () => {
        return app.inject({
          method: 'PUT',
          url: `/upload/${session.sessionId}`,
          headers: {
            authorization: `Bearer ${session.uploadToken}`,
            'content-type': 'application/octet-stream',
            'content-length': String(data.length),
          },
          body: Readable.from([data]),
        });
      });

      const responses = await Promise.all(requests);

      const successResponses = responses.filter((r) => r.statusCode === 202);
      const conflictResponses = responses.filter((r) => r.statusCode === 409);

      // Exactly ONE winner
      expect(successResponses.length).toBe(1);
      // All other 9 attempts are rejected with 409 Conflict
      expect(conflictResponses.length).toBe(concurrency - 1);

      // Verify database state: exactly ONE files row created for this session
      const fileRes = await adminPool.query(
        `SELECT id, status, current_version_id FROM files WHERE upload_session_id = $1`,
        [session.sessionId],
      );
      expect(fileRes.rows.length).toBe(1);

      // Verify exactly ONE file_versions row created
      const fileVersionRes = await adminPool.query(
        `SELECT id, storage_version_id FROM file_versions WHERE file_id = $1`,
        [fileRes.rows[0].id],
      );
      expect(fileVersionRes.rows.length).toBe(1);

      // Verify exactly ONE scan_jobs row created
      const scanJobRes = await adminPool.query(
        `SELECT id, status FROM scan_jobs WHERE file_version_id = $1`,
        [fileVersionRes.rows[0].id],
      );
      expect(scanJobRes.rows.length).toBe(1);
      expect(scanJobRes.rows[0].status).toBe('QUEUED');
    });
  });

  // ============================================================
  // Canonical DoD: file_versions.storage_version_id & Acceptance
  // ============================================================
  describe('Canonical DoD: file_versions.storage_version_id and HTTP 202 Acceptance', () => {
    it('accepts valid streaming upload, captures VersionId, and creates files/file_versions/scan_jobs', async () => {
      const payload = Buffer.from('canonical acceptance payload test content');
      const sha256Expected = crypto.createHash('sha256').update(payload).digest('hex');

      const session = await createTestSession({
        filename: 'report.pdf',
        declaredSize: payload.length,
        declaredSha256: sha256Expected,
      });

      const res = await app.inject({
        method: 'PUT',
        url: `/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'application/octet-stream',
          'content-length': String(payload.length),
        },
        body: Readable.from([payload]),
      });

      expect(res.statusCode).toBe(202);
      const body = JSON.parse(res.body);

      expect(body.fileId).toBeDefined();
      expect(body.fileVersionId).toBeDefined();
      expect(body.scanJobId).toBeDefined();
      expect(body.status).toBe('QUARANTINED');
      expect(body.versionId).toBeDefined();
      expect(typeof body.versionId).toBe('string');
      expect(body.versionId.length).toBeGreaterThan(0);
      expect(body.size).toBe(payload.length);
      expect(body.sha256).toBe(sha256Expected);

      // Verify DB table file_versions: storage_version_id is populated
      const fvDb = await adminPool.query(
        `SELECT id, storage_version_id, size_bytes, sha256_ingest FROM file_versions WHERE id = $1`,
        [body.fileVersionId],
      );
      expect(fvDb.rows.length).toBe(1);
      const fvRow = fvDb.rows[0];
      expect(fvRow.storage_version_id).toBe(body.versionId);
      expect(Number(fvRow.size_bytes)).toBe(payload.length);
      expect(Buffer.from(fvRow.sha256_ingest).toString('hex')).toBe(sha256Expected);

      // Verify files table
      const fileDb = await adminPool.query(
        `SELECT id, status, current_version_id, display_filename FROM files WHERE id = $1`,
        [body.fileId],
      );
      expect(fileDb.rows.length).toBe(1);
      expect(fileDb.rows[0].status).toBe('QUARANTINED');
      expect(fileDb.rows[0].current_version_id).toBe(body.fileVersionId);
      expect(fileDb.rows[0].display_filename).toBe('report.pdf');

      // Verify scan_jobs table
      const sjDb = await adminPool.query(
        `SELECT id, file_version_id, status FROM scan_jobs WHERE id = $1`,
        [body.scanJobId],
      );
      expect(sjDb.rows.length).toBe(1);
      expect(sjDb.rows[0].status).toBe('QUEUED');
      expect(sjDb.rows[0].file_version_id).toBe(body.fileVersionId);

      // Verify upload_sessions status is UPLOADED
      const sessDb = await adminPool.query(
        `SELECT status, completed_at FROM upload_sessions WHERE id = $1`,
        [session.sessionId],
      );
      expect(sessDb.rows[0].status).toBe('UPLOADED');
      expect(sessDb.rows[0].completed_at).not.toBeNull();
    });
  });

  // ============================================================
  // Additional P10 Security Controls
  // ============================================================
  describe('P10 Protocol Security Invariants', () => {
    it('rejects multipart/form-data upload with HTTP 415', async () => {
      const session = await createTestSession({ declaredSize: 100 });

      const res = await app.inject({
        method: 'PUT',
        url: `/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'multipart/form-data; boundary=---------------------------123',
        },
        body: Readable.from(['---------------------------123\r\n']),
      });

      expect(res.statusCode).toBe(415);
    });

    it('rejects upload with mismatching declared SHA-256', async () => {
      const declaredSha = crypto.createHash('sha256').update('expected content').digest('hex');
      const session = await createTestSession({
        declaredSize: 50,
        declaredSha256: declaredSha,
      });

      // Stream different content
      const actualContent = Buffer.from('different payload totally mismatching hash');
      const res = await app.inject({
        method: 'PUT',
        url: `/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'application/octet-stream',
        },
        body: Readable.from([actualContent]),
      });

      expect(res.statusCode).toBe(400);
      const problem = JSON.parse(res.body);
      expect(problem.detail).toContain('SHA-256');
    });

    it('rejects empty upload body with HTTP 400', async () => {
      const session = await createTestSession({ declaredSize: 100 });

      const res = await app.inject({
        method: 'PUT',
        url: `/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'application/octet-stream',
        },
        body: Readable.from([]), // 0 bytes
      });

      expect(res.statusCode).toBe(400);
      const problem = JSON.parse(res.body);
      expect(problem.detail).toContain('empty');
    });

    it('rejects truncated stream mismatching Content-Length header with HTTP 400', async () => {
      const session = await createTestSession({ declaredSize: 150 });

      const res = await app.inject({
        method: 'PUT',
        url: `/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'application/octet-stream',
          'content-length': '150',
        },
        body: Readable.from([Buffer.from('only 20 bytes here!')]), // 20 bytes vs 150
      });

      expect(res.statusCode).toBe(400);
      const problem = JSON.parse(res.body);
      expect(problem.detail).toContain('prematurely');
    });
  });

  // ============================================================
  // GET /upload/:id/status
  // ============================================================
  describe('GET /upload/:id/status', () => {
    it('returns status with fileId after successful upload', async () => {
      const payload = Buffer.from('status check test payload');
      const session = await createTestSession({ declaredSize: payload.length });

      // 1. Upload
      const putRes = await app.inject({
        method: 'PUT',
        url: `/upload/${session.sessionId}`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
          'content-type': 'application/octet-stream',
        },
        body: Readable.from([payload]),
      });
      expect(putRes.statusCode).toBe(202);
      const putBody = JSON.parse(putRes.body);

      // 2. Query status using upload token
      const statusRes = await app.inject({
        method: 'GET',
        url: `/upload/${session.sessionId}/status`,
        headers: {
          authorization: `Bearer ${session.uploadToken}`,
        },
      });

      expect(statusRes.statusCode).toBe(200);
      const statusBody = JSON.parse(statusRes.body);
      expect(statusBody.sessionId).toBe(session.sessionId);
      expect(statusBody.status).toBe('UPLOADED');
      expect(statusBody.fileId).toBe(putBody.fileId);
      expect(statusBody.fileStatus).toBe('QUARANTINED');

      // 3. Query status using API key
      const statusApiKeyRes = await app.inject({
        method: 'GET',
        url: `/api/v1/upload/${session.sessionId}/status`,
        headers: {
          authorization: `Bearer ${apiKeyARaw}`,
        },
      });

      expect(statusApiKeyRes.statusCode).toBe(200);
      const apiKeyStatusBody = JSON.parse(statusApiKeyRes.body);
      expect(apiKeyStatusBody.sessionId).toBe(session.sessionId);
      expect(apiKeyStatusBody.status).toBe('UPLOADED');
    });

    it('returns 401 when Authorization header is missing', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/upload/${crypto.randomUUID()}/status`,
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 404 for nonexistent upload session ID', async () => {
      // Use API key to query non-existent ID
      const res = await app.inject({
        method: 'GET',
        url: `/upload/${crypto.randomUUID()}/status`,
        headers: {
          authorization: `Bearer ${apiKeyARaw}`,
        },
      });

      expect(res.statusCode).toBe(404);
    });
  });
});
