import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import { createApp } from '../../../services/api/src/app.js';
import { ApiKeyService } from '../../../services/api/src/auth/service.js';
import { UploadAuthorizationService } from '../../../services/api/src/auth/session-service.js';
import { loadConfig } from '@sug/shared/config';
import { createPool, createBaseFixtures, type FixtureContext } from '../db/helpers.js';

describe('Integration — Upload Authorization Foundation & Tenant Isolation (Phase P7)', () => {
  let app: FastifyInstance;
  let adminPool: pg.Pool;
  let config: ReturnType<typeof loadConfig>;
  let fixturesA: FixtureContext;
  let fixturesB: FixtureContext;
  let keyA: { apiKeyId: string; rawKey: string; keyPrefix: string };
  let keyB: { apiKeyId: string; rawKey: string; keyPrefix: string };
  let uploadAuthService: UploadAuthorizationService;

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    config = loadConfig({ secretsDir });
    adminPool = createPool('sug_admin', 'sug_dev_password');

    // Provision Tenant A
    fixturesA = await createBaseFixtures(adminPool);

    // Provision Tenant B
    fixturesB = await createBaseFixtures(adminPool);

    const adminKeyService = new ApiKeyService({
      db: adminPool,
      pepper: config.secrets.pepper,
    });

    keyA = await adminKeyService.createApiKey({
      applicationId: fixturesA.appId,
      createdBy: fixturesA.userId,
      scopes: ['upload', 'read'],
    });

    keyB = await adminKeyService.createApiKey({
      applicationId: fixturesB.appId,
      createdBy: fixturesB.userId,
      scopes: ['upload', 'read'],
    });

    // Fastify app connects with sug_api least-privileged credentials from config
    app = await createApp({ config, logger: false });
    await app.ready();

    const apiPool = createPool('sug_api', 'sug_api_dev_password');
    uploadAuthService = new UploadAuthorizationService({ db: apiPool });
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (adminPool) {
      await adminPool.end();
    }
  });

  it('authorizes upload session with live PostgreSQL 18 and verifies database row', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/upload/authorize',
      headers: {
        authorization: `Bearer ${keyA.rawKey}`,
        'x-request-id': 'session-req-001',
      },
      payload: {
        filename: 'quarterly_report.pdf',
        declaredSize: 1048576, // 1 MB
        declaredMime: 'application/pdf',
        clientRef: 'inv-2026-001',
      },
    });

    expect(res.statusCode).toBe(201);
    const body = JSON.parse(res.body);
    expect(body.sessionId).toBeDefined();
    expect(body.applicationId).toBe(fixturesA.appId);
    expect(body.status).toBe('CREATED');
    expect(body.quarantineKey).toBe(`incoming/${fixturesA.appId}/${body.sessionId}`);
    expect(body.declaredSize).toBe(1048576);

    // Verify row directly in PostgreSQL 18 with adminPool
    const dbRes = await adminPool.query(`SELECT * FROM upload_sessions WHERE id = $1`, [
      body.sessionId,
    ]);
    expect(dbRes.rowCount).toBe(1);
    const row = dbRes.rows[0];
    expect(row.application_id).toBe(fixturesA.appId);
    expect(row.original_filename).toBe('quarterly_report.pdf');
    expect(row.status).toBe('CREATED');
    expect(row.token_jti).toBe(body.tokenJti);

    // Verify audit event
    const auditRes = await adminPool.query(
      `SELECT action, actor_id, details
       FROM audit_events
       WHERE action = 'upload_session.created' AND details->>'session_id' = $1`,
      [body.sessionId],
    );
    expect(auditRes.rowCount).toBe(1);
    expect(auditRes.rows[0].details.original_filename).toBe('quarterly_report.pdf');
    // Ensure raw secret or authorization header is never in audit
    expect(JSON.stringify(auditRes.rows[0])).not.toContain(keyA.rawKey);
  });

  it('enforces strict cross-tenant isolation (App B cannot view or abort App A session)', async () => {
    // 1. App A creates a session
    const createRes = await app.inject({
      method: 'POST',
      url: '/api/v1/upload/authorize',
      headers: { authorization: `Bearer ${keyA.rawKey}` },
      payload: {
        filename: 'tenant_a_confidential.pdf',
        declaredSize: 2048,
        declaredMime: 'application/pdf',
      },
    });
    const sessionA = JSON.parse(createRes.body);

    // 2. App B attempts to retrieve App A's session -> must return 404 (zero information leak)
    const crossGetRes = await app.inject({
      method: 'GET',
      url: `/api/v1/upload/sessions/${sessionA.sessionId}`,
      headers: { authorization: `Bearer ${keyB.rawKey}` },
    });
    expect(crossGetRes.statusCode).toBe(404);
    const body404 = JSON.parse(crossGetRes.body);
    expect(body404.type).toBe('urn:sug:error:not-found');

    // 3. App B attempts to abort App A's session -> must return 404
    const crossAbortRes = await app.inject({
      method: 'POST',
      url: `/api/v1/upload/sessions/${sessionA.sessionId}/abort`,
      headers: { authorization: `Bearer ${keyB.rawKey}` },
    });
    expect(crossAbortRes.statusCode).toBe(404);

    // 4. App A can retrieve its own session -> returns 200
    const ownGetRes = await app.inject({
      method: 'GET',
      url: `/api/v1/upload/sessions/${sessionA.sessionId}`,
      headers: { authorization: `Bearer ${keyA.rawKey}` },
    });
    expect(ownGetRes.statusCode).toBe(200);
    expect(JSON.parse(ownGetRes.body).id).toBe(sessionA.sessionId);
  });

  it('rejects client application ID spoofing attempt with 403 Forbidden', async () => {
    // Client presents Key A, but supplies App B ID in request body
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/upload/authorize',
      headers: { authorization: `Bearer ${keyA.rawKey}` },
      payload: {
        filename: 'spoof_attempt.pdf',
        declaredSize: 1024,
        declaredMime: 'application/pdf',
        applicationId: fixturesB.appId, // Mismatch!
      },
    });

    expect(res.statusCode).toBe(403);
    const body = JSON.parse(res.body);
    expect(body.type).toBe('urn:sug:error:forbidden');
    expect(body.detail).toContain('client application ID does not match');
  });

  it('enforces optimistic concurrency: prevents duplicate claims on the same session', async () => {
    const createRes = await app.inject({
      method: 'POST',
      url: '/api/v1/upload/authorize',
      headers: { authorization: `Bearer ${keyA.rawKey}` },
      payload: {
        filename: 'race_test.pdf',
        declaredSize: 1024,
        declaredMime: 'application/pdf',
      },
    });
    const session = JSON.parse(createRes.body);

    // Run two concurrent claim attempts
    const [claim1, claim2] = await Promise.all([
      uploadAuthService.authorizeSession(session.sessionId, fixturesA.appId),
      uploadAuthService.authorizeSession(session.sessionId, fixturesA.appId),
    ]);

    // Exactly one must succeed and one must fail with ALREADY_CLAIMED
    const results = [claim1, claim2];
    const successes = results.filter((r) => r.isAuthorized);
    const failures = results.filter((r) => !r.isAuthorized);

    expect(successes).toHaveLength(1);
    expect(failures).toHaveLength(1);
    expect(failures[0].reason).toBe('ALREADY_CLAIMED');
  });

  it('enforces server-side expiration: rejects expired sessions', async () => {
    const createRes = await app.inject({
      method: 'POST',
      url: '/api/v1/upload/authorize',
      headers: { authorization: `Bearer ${keyA.rawKey}` },
      payload: {
        filename: 'expire_test.pdf',
        declaredSize: 1024,
        declaredMime: 'application/pdf',
      },
    });
    const session = JSON.parse(createRes.body);

    // Fast-forward expiration in database directly with adminPool
    await adminPool.query(
      `UPDATE upload_sessions SET expires_at = NOW() - interval '5 seconds' WHERE id = $1`,
      [session.sessionId],
    );

    // Attempt to claim expired session -> must fail with EXPIRED
    const claim = await uploadAuthService.authorizeSession(session.sessionId, fixturesA.appId);
    expect(claim.isAuthorized).toBe(false);
    expect(claim.reason).toBe('EXPIRED');

    // Session retrieval reflects EXPIRED status
    const retrieved = await uploadAuthService.getSession(session.sessionId, fixturesA.appId);
    expect(retrieved?.status).toBe('EXPIRED');
  });

  it('handles 50 concurrent session reservations without pool exhaustion', async () => {
    const requests = Array.from({ length: 50 }, (_, i) =>
      app.inject({
        method: 'POST',
        url: '/api/v1/upload/authorize',
        headers: {
          authorization: `Bearer ${keyA.rawKey}`,
          'x-request-id': `concurrent-session-${i}`,
        },
        payload: {
          filename: `batch_doc_${i}.pdf`,
          declaredSize: 1000 + i,
          declaredMime: 'application/pdf',
          clientRef: `batch-item-${i}`,
        },
      }),
    );

    const responses = await Promise.all(requests);
    for (let i = 0; i < responses.length; i++) {
      const res = responses[i];
      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.sessionId).toBeDefined();
      expect(body.status).toBe('CREATED');
    }
  });
});
