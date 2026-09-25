import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import { createApp } from '../../../services/api/src/app.js';
import { ApiKeyService } from '../../../services/api/src/auth/service.js';
import { parseRawKey, computeKeyHmac } from '../../../services/api/src/auth/keys.js';
import { loadConfig } from '@sug/shared/config';
import { createPool, createBaseFixtures, type FixtureContext } from '../db/helpers.js';

describe('Integration — API Key Authentication & Verification (Phase P6)', () => {
  let app: FastifyInstance;
  let adminPool: pg.Pool;
  let fixtures: FixtureContext;
  let adminKeyService: ApiKeyService;
  let config: ReturnType<typeof loadConfig>;

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    config = loadConfig({ secretsDir });
    adminPool = createPool('sug_admin', 'sug_dev_password');

    // Create base fixtures (user, application, active policy)
    fixtures = await createBaseFixtures(adminPool);

    adminKeyService = new ApiKeyService({
      db: adminPool,
      pepper: config.secrets.pepper,
    });

    // Fastify app connects with sug_api least-privileged credentials from config
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

  it('provisions a new API key with HMAC stored and raw secret returned only once', async () => {
    const created = await adminKeyService.createApiKey({
      applicationId: fixtures.appId,
      createdBy: fixtures.userId,
      scopes: ['upload:create', 'upload:read'],
    });

    expect(created.apiKeyId).toBeDefined();
    expect(created.keyPrefix).toHaveLength(8);
    expect(created.rawKey).toMatch(/^sug_[0-9a-f]{8}_[0-9a-f]{64}$/);
    expect(created.scopes).toEqual(['upload:create', 'upload:read']);

    // Inspect database row directly with adminPool
    const dbRes = await adminPool.query(
      'SELECT id, application_id, key_prefix, key_hmac, scopes, revoked_at FROM api_keys WHERE id = $1',
      [created.apiKeyId],
    );

    expect(dbRes.rowCount).toBe(1);
    const row = dbRes.rows[0];
    expect(row.key_prefix).toBe(created.keyPrefix);
    expect(row.revoked_at).toBeNull();
    expect(row.scopes).toEqual(['upload:create', 'upload:read']);

    // Validate that key_hmac is a 32-byte binary Buffer matching expected HMAC
    const parsed = parseRawKey(created.rawKey);
    expect(parsed).not.toBeNull();
    const expectedHmac = computeKeyHmac(parsed!.secret, config.secrets.pepper);
    expect(row.key_hmac).toEqual(expectedHmac);

    // Verify raw key and raw secret are NOT in database
    const textSearch = await adminPool.query(
      `SELECT count(*)::int as count FROM api_keys WHERE $1 = ANY(scopes) OR key_prefix = $2`,
      [created.rawKey, parsed!.secret],
    );
    expect(textSearch.rows[0].count).toBe(0);

    // Verify audit event was logged
    const auditRes = await adminPool.query(
      `SELECT action, actor_id, details
       FROM audit_events
       WHERE action = 'api_key.created' AND details->>'key_prefix' = $1`,
      [created.keyPrefix],
    );
    expect(auditRes.rowCount).toBe(1);
    expect(auditRes.rows[0].details.key_prefix).toBe(created.keyPrefix);
    expect(auditRes.rows[0].details.scopes).toEqual(['upload:create', 'upload:read']);
    // Ensure raw secret is not in audit details
    expect(JSON.stringify(auditRes.rows[0].details)).not.toContain(parsed!.secret);
  });

  it('GET /api/v1/auth/probe authenticates successfully with live Fastify app using sug_api role', async () => {
    const created = await adminKeyService.createApiKey({
      applicationId: fixtures.appId,
      createdBy: fixtures.userId,
      scopes: ['upload:create', 'upload:read'],
    });

    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/probe',
      headers: {
        authorization: `Bearer ${created.rawKey}`,
        'x-request-id': 'probe-req-001',
      },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.status).toBe('authenticated');
    expect(body.applicationId).toBe(fixtures.appId);
    expect(body.keyPrefix).toBe(created.keyPrefix);
    expect(body.scopes).toEqual(['upload:create', 'upload:read']);
    expect(res.headers['x-request-id']).toBe('probe-req-001');

    // Verify audit event was recorded for auth_success
    const auditRes = await adminPool.query(
      `SELECT action, actor_id, details
       FROM audit_events
       WHERE action = 'api_key.auth_success' AND details->>'key_prefix' = $1`,
      [created.keyPrefix],
    );
    expect(auditRes.rowCount).toBeGreaterThanOrEqual(1);
    const event = auditRes.rows[0];
    expect(event.details.key_prefix).toBe(created.keyPrefix);
    expect(JSON.stringify(event.details)).not.toContain(created.rawKey);
  });

  it('GET /api/v1/auth/probe rejects unauthenticated requests with RFC 7807 401 Problem Details', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/probe',
    });

    expect(res.statusCode).toBe(401);
    expect(res.headers['content-type']).toContain('application/problem+json');
    const body = JSON.parse(res.body);
    expect(body.type).toBe('urn:sug:error:unauthorized');
    expect(body.title).toBe('Unauthorized');
    expect(body.status).toBe(401);
    expect(body.instance).toBe('/api/v1/auth/probe');
    expect(body.requestId).toBeDefined();
  });

  it('GET /api/v1/auth/probe returns identical generic 401 for invalid, expired, and revoked keys (zero oracle)', async () => {
    // 1. Unknown prefix
    const fakeKey = `sug_${crypto.randomBytes(4).toString('hex')}_${crypto.randomBytes(32).toString('hex')}`;
    const resUnknown = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/probe',
      headers: { authorization: `Bearer ${fakeKey}` },
    });
    expect(resUnknown.statusCode).toBe(401);
    const bodyUnknown = JSON.parse(resUnknown.body);
    expect(bodyUnknown.detail).toBe('Authentication failed');

    // 2. Valid prefix, invalid secret
    const validKey = await adminKeyService.createApiKey({
      applicationId: fixtures.appId,
      createdBy: fixtures.userId,
      scopes: ['upload:create'],
    });
    const parsed = parseRawKey(validKey.rawKey)!;
    const tamperedSecret = '0'.repeat(64);
    const tamperedKey = `sug_${parsed.prefix}_${tamperedSecret}`;

    const resTampered = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/probe',
      headers: { authorization: `Bearer ${tamperedKey}` },
    });
    expect(resTampered.statusCode).toBe(401);
    const bodyTampered = JSON.parse(resTampered.body);
    expect(bodyTampered.detail).toBe('Authentication failed');

    // 3. Expired key
    const expiredKey = await adminKeyService.createApiKey({
      applicationId: fixtures.appId,
      createdBy: fixtures.userId,
    });
    await adminPool.query(
      `UPDATE api_keys SET expires_at = NOW() - interval '1 hour' WHERE id = $1`,
      [expiredKey.apiKeyId],
    );

    const resExpired = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/probe',
      headers: { authorization: `Bearer ${expiredKey.rawKey}` },
    });
    expect(resExpired.statusCode).toBe(401);
    const bodyExpired = JSON.parse(resExpired.body);
    expect(bodyExpired.detail).toBe('Authentication failed');

    // 4. Revoked key
    const revokeTarget = await adminKeyService.createApiKey({
      applicationId: fixtures.appId,
      createdBy: fixtures.userId,
    });
    await adminKeyService.revokeApiKey(revokeTarget.apiKeyId, fixtures.userId);

    const resRevoked = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/probe',
      headers: { authorization: `Bearer ${revokeTarget.rawKey}` },
    });
    expect(resRevoked.statusCode).toBe(401);
    const bodyRevoked = JSON.parse(resRevoked.body);
    expect(bodyRevoked.detail).toBe('Authentication failed');

    // All 4 scenarios return identical error status and message
    expect(bodyUnknown.detail).toBe(bodyTampered.detail);
    expect(bodyTampered.detail).toBe(bodyExpired.detail);
    expect(bodyExpired.detail).toBe(bodyRevoked.detail);
  });

  it('revocation takes immediate effect against live Fastify endpoints', async () => {
    const key = await adminKeyService.createApiKey({
      applicationId: fixtures.appId,
      createdBy: fixtures.userId,
    });

    // Before revocation: 200
    const beforeRes = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/probe',
      headers: { authorization: `Bearer ${key.rawKey}` },
    });
    expect(beforeRes.statusCode).toBe(200);

    // Revoke key
    const revoked = await adminKeyService.revokeApiKey(key.apiKeyId, fixtures.userId);
    expect(revoked).toBe(true);

    // After revocation: immediate 401
    const afterRes = await app.inject({
      method: 'GET',
      url: '/api/v1/auth/probe',
      headers: { authorization: `Bearer ${key.rawKey}` },
    });
    expect(afterRes.statusCode).toBe(401);

    // Verify revoked audit event
    const auditRes = await adminPool.query(
      `SELECT action, actor_id, details
       FROM audit_events
       WHERE action = 'api_key.revoked' AND details->>'key_prefix' = $1`,
      [key.keyPrefix],
    );
    expect(auditRes.rowCount).toBe(1);
    expect(auditRes.rows[0].actor_id).toBe(fixtures.userId);
  });

  it('handles 50 concurrent authenticated requests without connection pool exhaustion', async () => {
    const key = await adminKeyService.createApiKey({
      applicationId: fixtures.appId,
      createdBy: fixtures.userId,
      scopes: ['upload:create', 'upload:read'],
    });

    const requests = Array.from({ length: 50 }, (_, i) =>
      app.inject({
        method: 'GET',
        url: '/api/v1/auth/probe',
        headers: {
          authorization: `Bearer ${key.rawKey}`,
          'x-request-id': `concurrent-auth-${i}`,
        },
      }),
    );

    const responses = await Promise.all(requests);
    for (let i = 0; i < responses.length; i++) {
      const res = responses[i];
      expect(res.statusCode).toBe(200);
      expect(res.headers['x-request-id']).toBe(`concurrent-auth-${i}`);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('authenticated');
    }
  });

  it('proves sug_api role has SELECT on api_keys and EXECUTE on audit_append, but cannot DROP or TRUNCATE', async () => {
    const apiPool = createPool('sug_api', 'sug_api_dev_password');
    try {
      // 1. SELECT succeeds
      const selectRes = await apiPool.query('SELECT count(*)::int as count FROM api_keys');
      expect(selectRes.rows[0].count).toBeGreaterThan(0);

      // 2. audit_append succeeds
      const auditRes = await apiPool.query(
        `SELECT audit_append('service', 'api_service', 'system.probe', json_build_object('application_id', $1::text)::jsonb, '{"test": true}'::jsonb) AS seq`,
        [fixtures.appId],
      );
      expect(auditRes.rows[0].seq).toBeDefined();

      // 3. TRUNCATE fails with permission denied
      await expect(apiPool.query('TRUNCATE TABLE api_keys')).rejects.toThrow(/permission denied/);

      // 4. DROP TABLE fails with permission denied
      await expect(apiPool.query('DROP TABLE api_keys')).rejects.toThrow(/must be owner/);
    } finally {
      await apiPool.end();
    }
  });
});
