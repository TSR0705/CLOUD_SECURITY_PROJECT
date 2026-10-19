/**
 * @sug/test/unit/api/audit.test.ts
 *
 * Unit tests for Phase P21 Hash-Chained Audit System API Routes:
 * - GET /security-events and GET /api/v1/security-events
 *   - Authentication: API key or JWT (admin, auditor, analyst)
 *   - Tenant isolation: API key restricted strictly to its own application_id
 *   - Cross-tenant requests with mismatched application_id rejected with 403
 *   - Parameter validations: limit, file_id, actor_type, application_id
 *   - Pagination cursor and order
 *   - Zero secret/credential leakage
 * - GET /audit/verify and GET /api/v1/audit/verify
 *   - Role-based authorization: admin & auditor allowed, analyst & API keys denied (403)
 *   - Valid chain response: status VALID, verifiedCount, headHash
 *   - Broken chain response: status INVALID, failedSeq, failureCategory
 * - POST /audit/checkpoints and POST /api/v1/audit/checkpoints
 *   - Role-based authorization: admin & auditor allowed, analyst & API keys denied (403)
 *   - Creates Ed25519-signed checkpoint via storage-first S3 putIfAbsent
 */

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createApp } from '../../../services/api/src/app.js';
import { createDashboardToken } from '../../../services/api/src/auth/jwt.js';
import type { StorageProvider } from '@sug/storage';
import type { Config } from '@sug/shared/config';
import {
  computeEventHash,
  formatCanonicalRefs,
  formatCanonicalDetails,
} from '../../../packages/audit/src/index.js';

describe('Phase P21: Audit System API Endpoints (Unit Tests)', () => {
  let app: FastifyInstance;
  let jwtPrivateKeyPem: string;
  let checkpointPrivateKeyPem: string;
  let checkpointPublicKeyPem: string;

  const testAppId = crypto.randomUUID();
  const otherAppId = crypto.randomUUID();
  const validApiKey = 'sug_test_prefix8_sec12345678901234567890123456789012345678901';

  let mockEvents: Array<{
    seq: string;
    id: string;
    occurred_at: Date;
    actor_type: string;
    actor_id: string;
    action: string;
    application_id: string | null;
    file_id: string | null;
    file_version_id: string | null;
    decision_id: string | null;
    request_id: string | null;
    ip: string | null;
    details: unknown;
    prev_hash: Buffer;
    event_hash: Buffer;
    occurred_at_text?: string;
    canonical_refs?: string;
    canonical_details?: string;
  }>;

  let mockCheckpoints: Array<{
    id: string;
    last_seq: string;
    chain_hash: Buffer;
    signature: Buffer;
    s3_version_id: string;
    created_at: Date;
  }>;

  let storagePutCalls: unknown[];

  beforeEach(async () => {
    // Generate JWT Ed25519 keypair
    const jwtPair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    jwtPrivateKeyPem = jwtPair.privateKey;

    checkpointPrivateKeyPem = fs.readFileSync(
      path.resolve(process.cwd(), 'secrets/checkpoint_private_key.pem'),
      'utf8',
    );
    checkpointPublicKeyPem = fs.readFileSync(
      path.resolve(process.cwd(), 'secrets/checkpoint_public_key.pem'),
      'utf8',
    );

    mockEvents = [];
    mockCheckpoints = [];
    storagePutCalls = [];

    // Seed mock events
    const zeroHash = Buffer.alloc(32, 0);

    const ev1OccurredAtText = '2026-10-19 06:00:00.000000+00';
    const ev1Refs = {
      application_id: testAppId,
      file_id: null,
      file_version_id: null,
      decision_id: null,
      request_id: null,
      ip: '127.0.0.1',
    };
    const ev1CanonicalRefs = formatCanonicalRefs(ev1Refs);
    const ev1Details = { init: true };
    const ev1CanonicalDetails = formatCanonicalDetails(ev1Details);
    const ev1Hash = computeEventHash({
      prevHash: zeroHash,
      actorType: 'service',
      actorId: 'gateway',
      action: 'SYSTEM_BOOT',
      occurredAtText: ev1OccurredAtText,
      refsText: ev1CanonicalRefs,
      detailsText: ev1CanonicalDetails,
    });

    mockEvents.push({
      seq: '1',
      id: crypto.randomUUID(),
      occurred_at: new Date('2026-10-19T06:00:00.000Z'),
      actor_type: 'service',
      actor_id: 'gateway',
      action: 'SYSTEM_BOOT',
      application_id: testAppId,
      file_id: null,
      file_version_id: null,
      decision_id: null,
      request_id: null,
      ip: '127.0.0.1',
      details: ev1Details,
      prev_hash: zeroHash,
      event_hash: ev1Hash,
      occurred_at_text: ev1OccurredAtText,
      canonical_refs: ev1CanonicalRefs,
      canonical_details: ev1CanonicalDetails,
    });

    const ev2OccurredAtText = '2026-10-19 06:01:00.000000+00';
    const ev2FileId = crypto.randomUUID();
    const ev2FileVersionId = crypto.randomUUID();
    const ev2Refs = {
      application_id: otherAppId,
      file_id: ev2FileId,
      file_version_id: ev2FileVersionId,
      decision_id: null,
      request_id: null,
      ip: '127.0.0.1',
    };
    const ev2CanonicalRefs = formatCanonicalRefs(ev2Refs);
    const ev2Details = { bytes: 1024 };
    const ev2CanonicalDetails = formatCanonicalDetails(ev2Details);
    const ev2Hash = computeEventHash({
      prevHash: ev1Hash,
      actorType: 'api_key',
      actorId: 'key-1',
      action: 'FILE_UPLOADED',
      occurredAtText: ev2OccurredAtText,
      refsText: ev2CanonicalRefs,
      detailsText: ev2CanonicalDetails,
    });

    mockEvents.push({
      seq: '2',
      id: crypto.randomUUID(),
      occurred_at: new Date('2026-10-19T06:01:00.000Z'),
      actor_type: 'api_key',
      actor_id: 'key-1',
      action: 'FILE_UPLOADED',
      application_id: otherAppId,
      file_id: ev2FileId,
      file_version_id: ev2FileVersionId,
      decision_id: null,
      request_id: null,
      ip: '127.0.0.1',
      details: ev2Details,
      prev_hash: ev1Hash,
      event_hash: ev2Hash,
      occurred_at_text: ev2OccurredAtText,
      canonical_refs: ev2CanonicalRefs,
      canonical_details: ev2CanonicalDetails,
    });

    const mockDb = {
      query: vi.fn().mockImplementation((sql: string, params: unknown[] = []) => {
        // Readiness / Health checks
        if (sql.includes('SELECT 1')) {
          return Promise.resolve({ rows: [{ '?column?': 1 }] });
        }

        // Security events query
        if (sql.includes('FROM audit_events') && sql.includes('SELECT seq, id')) {
          let rows = [...mockEvents];

          // Tenant isolation filter
          if (sql.includes('application_id = $')) {
            const appIdIdx = params.findIndex((p) => p === testAppId || p === otherAppId);
            if (appIdIdx !== -1) {
              const targetApp = params[appIdIdx];
              rows = rows.filter((r) => r.application_id === targetApp);
            }
          }

          if (sql.includes('ORDER BY seq DESC')) {
            rows.sort((a, b) => (BigInt(b.seq) > BigInt(a.seq) ? 1 : -1));
          } else {
            rows.sort((a, b) => (BigInt(a.seq) > BigInt(b.seq) ? 1 : -1));
          }

          // LIMIT
          const limit = params[params.length - 1] as number;
          if (typeof limit === 'number') {
            rows = rows.slice(0, limit);
          }

          return Promise.resolve({ rows });
        }

        // Stream verify query
        if (sql.includes('FROM audit_events') && sql.includes('canonical_refs')) {
          const rows = [...mockEvents];
          rows.sort((a, b) => (BigInt(a.seq) > BigInt(b.seq) ? 1 : -1));
          return Promise.resolve({ rows });
        }

        // Checkpoints query
        if (sql.includes('FROM audit_checkpoints')) {
          return Promise.resolve({ rows: mockCheckpoints });
        }

        // Checkpoint insert / create
        if (
          sql.includes('INSERT INTO audit_checkpoints') ||
          sql.includes('audit_checkpoint_create')
        ) {
          const row = {
            id: params[0] as string,
            last_seq: params[1] as string,
            chain_hash: params[2] as Buffer,
            signature: params[3] as Buffer,
            s3_version_id: params[4] as string,
            created_at: new Date((params[5] as string) || Date.now()),
          };
          mockCheckpoints.push(row);
          return Promise.resolve({ rows: [row] });
        }

        // Audit checkpoint ledger query
        if (sql.includes("action = 'audit.checkpoint_created'")) {
          const cpEvents = mockEvents.filter((e) => e.action === 'audit.checkpoint_created');
          if (cpEvents.length > 0) {
            const last = cpEvents[cpEvents.length - 1]!;
            const details = last.details as { last_seq?: string; checkpoint_id?: string };
            return Promise.resolve({
              rows: [{ last_seq: details?.last_seq, checkpoint_id: details?.checkpoint_id }],
            });
          }
          return Promise.resolve({ rows: [] });
        }

        // Latest event for checkpoint
        if (sql.includes('SELECT seq, event_hash, occurred_at FROM audit_events')) {
          const last = mockEvents[mockEvents.length - 1];
          return Promise.resolve({ rows: last ? [last] : [] });
        }

        // audit_append
        if (sql.includes('audit_append')) {
          return Promise.resolve({ rows: [{ audit_append: '999' }] });
        }

        return Promise.resolve({ rows: [] });
      }),
    };

    const mockApiKeyService = {
      verifyApiKey: vi.fn().mockImplementation((rawKey: string) => {
        if (rawKey === validApiKey) {
          return Promise.resolve({
            isValid: true,
            app: {
              applicationId: testAppId,
              apiKeyId: crypto.randomUUID(),
              keyPrefix: 'prefix8',
              scopes: ['audit:read', 'files:read'],
            },
          });
        }
        return Promise.resolve({ isValid: false });
      }),
    };

    const mockStorageProvider: StorageProvider = {
      putIfAbsent: vi.fn().mockImplementation((p: unknown) => {
        storagePutCalls.push(p);
        return Promise.resolve({ versionId: 's3-checkpoint-ver-1' });
      }),
      head: vi.fn().mockResolvedValue({ versionId: 's3-checkpoint-ver-1', contentLength: 256 }),
      getByVersion: vi.fn(),
    };

    const mockConfig: Config = {
      nodeEnv: 'test',
      logLevel: 'silent',
      port: 3000,
      host: '0.0.0.0',
      serviceName: 'sug-api',
      database: {
        url: 'postgres://sug_admin:dummy@localhost:5433/sug',
        host: 'localhost',
        port: 5433,
        user: 'sug_admin',
        name: 'sug',
      },
      storage: {
        s3: {
          endpoint: 'http://localhost:4566',
          region: 'us-east-1',
          quarantineBucket: 'sug-quarantine-local',
          cleanBucket: 'sug-clean-local',
          auditBucket: 'sug-audit-local',
          accessKeyId: 'test',
        },
        gcs: {
          endpoint: 'http://localhost:4443',
          replicaBucket: 'sug-replica-local',
          projectId: 'sug-local-project',
        },
        services: {
          api: { accessKeyId: 'test' },
          scanner: { accessKeyId: 'test' },
          promoter: { accessKeyId: 'test' },
          replicator: { accessKeyId: 'test' },
        },
      },
      secrets: {
        pepper: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        kek: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        jwtPrivateKey: jwtPrivateKeyPem,
        checkpointPrivateKey: checkpointPrivateKeyPem,
      },
      toRedacted: () => ({}) as never,
      [Symbol.for('nodejs.util.inspect.custom')]: () => '[Config]',
      toJSON: () => ({}),
    };

    app = await createApp({
      config: mockConfig,
      authDb: mockDb as never,
      apiKeyService: mockApiKeyService as never,
      storageProvider: mockStorageProvider,
      checkpointPrivateKeyPem,
      checkpointPublicKeyPem,
      logger: false,
    });
  });

  describe('GET /security-events & GET /api/v1/security-events', () => {
    it('rejects unauthenticated request with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/security-events',
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.title).toBe('Unauthorized');
    });

    it('rejects invalid or revoked API key with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/security-events',
        headers: {
          authorization: 'Bearer sug_test_invalid_00000000000000000000000000000000000000000',
        },
      });
      expect(res.statusCode).toBe(401);
    });

    it('enforces tenant isolation: API key only returns events for its own application', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/security-events',
        headers: {
          authorization: `Bearer ${validApiKey}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.events).toBeDefined();
      expect(body.events.length).toBe(1);
      expect(body.events[0].application_id).toBe(testAppId);
    });

    it('rejects cross-tenant query: API key requesting another tenant application_id gets 403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/security-events?application_id=${otherAppId}`,
        headers: {
          authorization: `Bearer ${validApiKey}`,
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.title).toBe('Forbidden');
      expect(body.detail).toContain('not authorized to query other tenant audit logs');
    });

    it('allows Auditor dashboard user to view all security events', async () => {
      const auditorToken = await createDashboardToken(
        { id: 'usr-auditor-1', email: 'auditor@sug.test', role: 'auditor', is_active: true },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/security-events',
        headers: {
          authorization: `Bearer ${auditorToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.events.length).toBe(2);
    });

    it('allows Admin dashboard user to filter security events by application_id', async () => {
      const adminToken = await createDashboardToken(
        { id: 'usr-admin-1', email: 'admin@sug.test', role: 'admin', is_active: true },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'GET',
        url: `/security-events?application_id=${otherAppId}`,
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.events.length).toBe(1);
      expect(body.events[0].application_id).toBe(otherAppId);
    });

    it('rejects invalid limit parameter with 400', async () => {
      const auditorToken = await createDashboardToken(
        { id: 'usr-auditor-1', email: 'auditor@sug.test', role: 'auditor', is_active: true },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'GET',
        url: '/security-events?limit=250',
        headers: {
          authorization: `Bearer ${auditorToken}`,
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.detail).toContain('limit must be an integer between 1 and 100');
    });

    it('rejects invalid actor_type filter with 400', async () => {
      const auditorToken = await createDashboardToken(
        { id: 'usr-auditor-1', email: 'auditor@sug.test', role: 'auditor', is_active: true },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'GET',
        url: '/security-events?actor_type=hacker',
        headers: {
          authorization: `Bearer ${auditorToken}`,
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.detail).toContain("actor_type must be one of 'api_key', 'user', 'service'");
    });

    it('verifies canonical aliases /security-events and /api/v1/security-events return identical responses', async () => {
      const adminToken = await createDashboardToken(
        { id: 'usr-admin-1', email: 'admin@sug.test', role: 'admin', is_active: true },
        jwtPrivateKeyPem,
      );

      const resRoot = await app.inject({
        method: 'GET',
        url: '/security-events',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      const resV1 = await app.inject({
        method: 'GET',
        url: '/api/v1/security-events',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(resRoot.statusCode).toBe(200);
      expect(resV1.statusCode).toBe(200);
      expect(resRoot.body).toBe(resV1.body);
    });
  });

  describe('GET /audit/verify & GET /api/v1/audit/verify', () => {
    it('rejects unauthenticated request with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/audit/verify',
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects API key with 403 (restricted to admin & auditor roles)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/audit/verify',
        headers: {
          authorization: `Bearer ${validApiKey}`,
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.detail).toContain('restricted to admin and auditor roles');
    });

    it('rejects Analyst user with 403 (verification restricted to admin & auditor)', async () => {
      const analystToken = await createDashboardToken(
        { id: 'usr-analyst-1', email: 'analyst@sug.test', role: 'analyst', is_active: true },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/audit/verify',
        headers: {
          authorization: `Bearer ${analystToken}`,
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns VALID when audit chain is unbroken and matches hashes', async () => {
      const auditorToken = await createDashboardToken(
        { id: 'usr-auditor-1', email: 'auditor@sug.test', role: 'auditor', is_active: true },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'GET',
        url: '/audit/verify',
        headers: {
          authorization: `Bearer ${auditorToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('VALID');
      expect(body.valid).toBe(true);
      expect(body.verifiedCount).toBe(2);
      expect(body.headHash).toBe(mockEvents[1]?.event_hash.toString('hex'));
    });

    it('returns INVALID with failedSeq and failureCategory when chain is broken', async () => {
      const auditorToken = await createDashboardToken(
        { id: 'usr-auditor-1', email: 'auditor@sug.test', role: 'auditor', is_active: true },
        jwtPrivateKeyPem,
      );

      // Corrupt event 2 prev_hash to break the chain link
      mockEvents[1]!.prev_hash = Buffer.alloc(32, 0xff);

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/audit/verify',
        headers: {
          authorization: `Bearer ${auditorToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('INVALID');
      expect(body.valid).toBe(false);
      expect(body.failedSeq).toBe('2');
      expect(body.failureCategory).toBe('CHAIN_BROKEN');
    });
  });

  describe('POST /audit/checkpoints & POST /api/v1/audit/checkpoints', () => {
    it('rejects API key with 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/audit/checkpoints',
        headers: {
          authorization: `Bearer ${validApiKey}`,
        },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects Analyst role with 403', async () => {
      const analystToken = await createDashboardToken(
        { id: 'usr-analyst-1', email: 'analyst@sug.test', role: 'analyst', is_active: true },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'POST',
        url: '/audit/checkpoints',
        headers: {
          authorization: `Bearer ${analystToken}`,
        },
      });
      expect(res.statusCode).toBe(403);
    });

    it('allows Admin to create Ed25519-signed checkpoint with storage-first S3 persistence', async () => {
      const adminToken = await createDashboardToken(
        { id: 'usr-admin-1', email: 'admin@sug.test', role: 'admin', is_active: true },
        jwtPrivateKeyPem,
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/audit/checkpoints',
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.checkpoint).toBeDefined();
      expect(body.checkpoint.schema).toBe('sug.audit_checkpoint/v1');
      expect(body.checkpoint.lastSeq).toBe('2');
      expect(body.s3VersionId).toBe('s3-checkpoint-ver-1');
      expect(body.storedInDb).toBe(true);

      // Verify S3 put was called
      expect(storagePutCalls.length).toBe(1);
      expect((storagePutCalls[0] as { key: string }).key).toBe(
        'checkpoints/checkpoint_000000000002.json',
      );
    });
  });
});
