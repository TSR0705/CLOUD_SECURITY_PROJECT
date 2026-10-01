/**
 * @sug/test/integration/api/p17-scans-api
 * Integration test suite for GET /api/v1/scans/:id:
 * - Authentication enforcement (401 for missing/invalid auth)
 * - UUID validation (400 for malformed UUID)
 * - Resource not found (404)
 * - Tenant isolation (403 when Application B accesses Application A scan)
 * - Deterministic sorting by check_id ASC
 * - Complete findings schema with ArtifactIdentity
 * - Dashboard JWT authorization
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import { createApp } from '../../../services/api/src/app.js';
import { ApiKeyService } from '../../../services/api/src/auth/service.js';
import { createDashboardToken } from '../../../services/api/src/auth/jwt.js';
import { loadConfig } from '@sug/shared/config';
import { createPool, createBaseFixtures, type FixtureContext } from '../db/helpers.js';

describe('Integration — GET /api/v1/scans/:id Findings & Authorization Suite (Phase P17)', () => {
  let app: FastifyInstance;
  let adminPool: pg.Pool;
  let config: ReturnType<typeof loadConfig>;
  let fixturesA: FixtureContext;
  let fixturesB: FixtureContext;
  let keyA: { apiKeyId: string; rawKey: string; keyPrefix: string };
  let keyB: { apiKeyId: string; rawKey: string; keyPrefix: string };
  let adminJwt: string;
  let scanJobIdA: string;
  let scanJobIdB: string;
  let storageVerA: string;

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    config = loadConfig({ secretsDir });
    adminPool = createPool('sug_admin', 'sug_dev_password');

    // 1. Provision Tenant A and Tenant B
    fixturesA = await createBaseFixtures(adminPool);
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

    adminJwt = await createDashboardToken(
      {
        id: fixturesA.userId,
        email: 'admin@tenant-a.com',
        role: 'admin',
      },
      config.secrets.jwtPrivateKey,
    );

    // 2. Insert FileVersion and ScanJob for Tenant A
    const fileVersionIdA = crypto.randomUUID();
    scanJobIdA = crypto.randomUUID();
    const shaA = crypto.createHash('sha256').update('test-content-A').digest();
    const objKeyA = `quarantine/${fixturesA.appId}/${crypto.randomUUID()}`;
    storageVerA = crypto.randomUUID();

    await adminPool.query(
      `INSERT INTO file_versions (
         id, file_id, version_no, provider, bucket, object_key,
         storage_version_id, size_bytes, sha256_ingest
       ) VALUES ($1, $2, (SELECT COALESCE(MAX(version_no), 0) + 1 FROM file_versions WHERE file_id = $2),
                 'aws', 'sug-quarantine-local', $3, $4, 100, $5)`,
      [fileVersionIdA, fixturesA.fileId, objKeyA, storageVerA, shaA],
    );

    await adminPool.query(
      `INSERT INTO scan_jobs (id, file_version_id, status, max_attempts, finished_at)
       VALUES ($1, $2, 'SUCCEEDED', 3, NOW())`,
      [scanJobIdA, fileVersionIdA],
    );

    // Insert multiple findings for Tenant A in reverse alphabetical order to test sorting
    await adminPool.query(
      `INSERT INTO scan_results (
         scan_job_id, file_version_id, check_id, engine, engine_version,
         outcome, reason_code, severity, confidence, evidence,
         scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
       ) VALUES
       ($1, $2, 'scanner.yara', 'yara-x', '1.20.0', 'PASS', 'CLEAN', 'INFO', 'CONFIRMED', '{}'::jsonb, $4, $3, 100, 20),
       ($1, $2, 'scanner.clamav', 'clamav', '1.4.6', 'PASS', 'CLEAN', 'INFO', 'CONFIRMED', '{}'::jsonb, $4, $3, 100, 45),
       ($1, $2, 'scanner.archive', 'yauzl', '3.4.0', 'PASS', 'CLEAN', 'INFO', 'CONFIRMED', '{}'::jsonb, $4, $3, 100, 15)`,
      [scanJobIdA, fileVersionIdA, shaA, storageVerA],
    );

    // 3. Insert FileVersion and ScanJob for Tenant B
    const fileVersionIdB = crypto.randomUUID();
    scanJobIdB = crypto.randomUUID();
    const shaB = crypto.createHash('sha256').update('test-content-B').digest();
    const objKeyB = `quarantine/${fixturesB.appId}/${crypto.randomUUID()}`;
    const storageVerB = crypto.randomUUID();

    await adminPool.query(
      `INSERT INTO file_versions (
         id, file_id, version_no, provider, bucket, object_key,
         storage_version_id, size_bytes, sha256_ingest
       ) VALUES ($1, $2, (SELECT COALESCE(MAX(version_no), 0) + 1 FROM file_versions WHERE file_id = $2),
                 'aws', 'sug-quarantine-local', $3, $4, 200, $5)`,
      [fileVersionIdB, fixturesB.fileId, objKeyB, storageVerB, shaB],
    );

    await adminPool.query(
      `INSERT INTO scan_jobs (id, file_version_id, status, max_attempts, finished_at)
       VALUES ($1, $2, 'SUCCEEDED', 3, NOW())`,
      [scanJobIdB, fileVersionIdB],
    );

    // 4. Initialize Fastify API app
    app = await createApp({ config, logger: false });
    await app.ready();
  });

  afterAll(async () => {
    if (app) await app.close();
    if (adminPool) await adminPool.end();
  });

  it('rejects unauthenticated requests with 401 Problem Details', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/scans/${scanJobIdA}`,
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.type).toBe('urn:sug:error:unauthorized');
    expect(body.status).toBe(401);
  });

  it('rejects invalid UUID format with 400 Problem Details', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/scans/not-a-valid-uuid',
      headers: {
        authorization: `Bearer ${keyA.rawKey}`,
      },
    });

    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.type).toBe('urn:sug:error:validation');
  });

  it('returns 404 Problem Details when scan job does not exist', async () => {
    const nonExistentId = crypto.randomUUID();
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/scans/${nonExistentId}`,
      headers: {
        authorization: `Bearer ${keyA.rawKey}`,
      },
    });

    expect(res.statusCode).toBe(404);
    const body = res.json();
    expect(body.type).toBe('urn:sug:error:not-found');
  });

  it('enforces tenant application boundary (returns 403 when App B accesses App A scan)', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/scans/${scanJobIdA}`,
      headers: {
        authorization: `Bearer ${keyB.rawKey}`, // Key B attempting to view Scan Job A
      },
    });

    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.type).toBe('urn:sug:error:forbidden');
  });

  it('returns scan status and deterministically sorted findings for authorized API key', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/scans/${scanJobIdA}`,
      headers: {
        authorization: `Bearer ${keyA.rawKey}`,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();

    expect(body.id).toBe(scanJobIdA);
    expect(body.status).toBe('SUCCEEDED');
    expect(body.findings).toHaveLength(3);

    // Must be sorted deterministically by check_id ASC
    expect(body.findings[0].checkId).toBe('scanner.archive');
    expect(body.findings[1].checkId).toBe('scanner.clamav');
    expect(body.findings[2].checkId).toBe('scanner.yara');

    // Assert findings schema & ArtifactIdentity format
    const clamavFinding = body.findings[1];
    expect(clamavFinding.engine).toBe('clamav');
    expect(clamavFinding.outcome).toBe('PASS');
    expect(clamavFinding.reasonCode).toBe('CLEAN');
    expect(clamavFinding.severity).toBe('INFO');
    expect(clamavFinding.confidence).toBe('CONFIRMED');
    expect(clamavFinding.scannedStorageVersionId).toBe(storageVerA);
    expect(clamavFinding.scannedSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(clamavFinding.scannedSize).toBe(100);
  });

  it('allows access to scan job for authorized Dashboard User JWT', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/scans/${scanJobIdA}`,
      headers: {
        authorization: `Bearer ${adminJwt}`,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.id).toBe(scanJobIdA);
    expect(body.status).toBe('SUCCEEDED');
  });
});
