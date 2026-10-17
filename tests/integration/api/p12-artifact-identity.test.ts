import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import {
  S3Client,
  HeadBucketCommand,
  CreateBucketCommand,
  PutBucketVersioningCommand,
} from '@aws-sdk/client-s3';
import { createApp } from '../../../services/api/src/app.js';
import { ApiKeyService } from '../../../services/api/src/auth/service.js';
import { loadConfig } from '@sug/shared/config';
import { createPool } from '../db/helpers.js';
import { createDocumentsPreset } from '@sug/policy-engine';
import { buildQuarantineKey } from '@sug/storage';
import {
  ArtifactIdentity,
  compareArtifactIdentities,
  validateArtifactIdentity,
  isArtifactIdentity,
} from '@sug/shared';

describe('Phase P12: SHA-256 Artifact Identity (Integration Suite)', () => {
  let app: FastifyInstance;
  let adminPool: pg.Pool;
  let config: ReturnType<typeof loadConfig>;
  let apiKeyService: ApiKeyService;

  let userId: string;
  let appId: string;
  let apiKeyRaw: string;

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    config = loadConfig({ secretsDir });
    adminPool = createPool('sug_admin', 'sug_dev_password');

    // Ensure S3 quarantine bucket exists with versioning enabled (with retry for emulator readiness)
    const rawS3 = new S3Client({
      endpoint: config.storage.s3.endpoint || 'http://localhost:4566',
      region: config.storage.s3.region || 'us-east-1',
      credentials: {
        accessKeyId: config.storage.services.api.accessKeyId || 'test',
        secretAccessKey:
          config.secrets.services?.api?.secretAccessKey ??
          config.secrets.awsSecretAccessKey ??
          'test',
      },
      forcePathStyle: true,
    });

    for (let attempt = 0; attempt < 15; attempt++) {
      try {
        try {
          await rawS3.send(new HeadBucketCommand({ Bucket: config.storage.s3.quarantineBucket }));
        } catch {
          await rawS3.send(new CreateBucketCommand({ Bucket: config.storage.s3.quarantineBucket }));
        }
        await rawS3.send(
          new PutBucketVersioningCommand({
            Bucket: config.storage.s3.quarantineBucket,
            VersioningConfiguration: { Status: 'Enabled' },
          }),
        );
        break;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    // 1. Create test user and application
    const userRes = await adminPool.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, 'admin')
       RETURNING id`,
      [`p12_test_${crypto.randomUUID()}@gateway.internal`, 'argon2id$mock'],
    );
    userId = userRes.rows[0].id;

    const appRes = await adminPool.query(
      `INSERT INTO applications (name, owner_user_id)
       VALUES ($1, $2)
       RETURNING id`,
      [`app_p12_${crypto.randomUUID().slice(0, 12)}`, userId],
    );
    appId = appRes.rows[0].id;

    // 2. Provision API key
    apiKeyService = new ApiKeyService({
      db: adminPool,
      pepper: config.secrets.pepper,
    });

    const key = await apiKeyService.createApiKey({
      applicationId: appId,
      createdBy: userId,
      scopes: ['upload', 'read'],
    });
    apiKeyRaw = key.rawKey;

    // 3. Boot Fastify app
    app = await createApp({ config, logger: false });
    await app.ready();

    // 4. Create standard policy via API
    const policyDoc = {
      ...createDocumentsPreset(),
      maxFileSize: 10 * 1024 * 1024,
    };

    const policyRes = await app.inject({
      method: 'POST',
      url: '/api/v1/policies',
      headers: {
        authorization: `Bearer ${apiKeyRaw}`,
        'content-type': 'application/json',
      },
      payload: {
        name: 'p12-standard-policy',
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

  async function createUploadSession(params: {
    filename?: string;
    declaredMime?: string;
    declaredSize?: number;
    declaredSha256?: string;
  }) {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/upload/session',
      headers: {
        authorization: `Bearer ${apiKeyRaw}`,
        'content-type': 'application/json',
      },
      payload: {
        filename: params.filename ?? 'artifact-identity-test.pdf',
        declaredMime: params.declaredMime ?? 'application/pdf',
        ...(params.declaredSize !== undefined ? { declaredSize: params.declaredSize } : {}),
        ...(params.declaredSha256 !== undefined ? { declaredSha256: params.declaredSha256 } : {}),
      },
    });

    expect(res.statusCode).toBe(201);
    return JSON.parse(res.body) as {
      sessionId: string;
      uploadUrl: string;
      uploadToken: string;
      maxSizeBytes: number;
      expiresAt: string;
    };
  }

  it('binds exact ArtifactIdentity on streaming upload and exposes it via GET /upload/:id/status', async () => {
    const payload = Buffer.from('Cryptographically Bound Artifact Content - P12 Verification');
    const expectedSha256 = crypto.createHash('sha256').update(payload).digest('hex').toLowerCase();

    const session = await createUploadSession({
      filename: 'financial-report.pdf',
      declaredMime: 'application/pdf',
      declaredSize: payload.length,
    });

    // Verify status before upload: CREATED with null identity
    const pendingStatusRes = await app.inject({
      method: 'GET',
      url: `/upload/${session.sessionId}/status`,
      headers: {
        authorization: `Bearer ${session.uploadToken}`,
      },
    });
    expect(pendingStatusRes.statusCode).toBe(200);
    const pendingStatus = JSON.parse(pendingStatusRes.body);
    expect(pendingStatus.status).toBe('CREATED');
    expect(pendingStatus.identity).toBeNull();

    // Perform streaming PUT upload
    const putRes = await app.inject({
      method: 'PUT',
      url: `/upload/${session.sessionId}`,
      headers: {
        authorization: `Bearer ${session.uploadToken}`,
        'content-type': 'application/pdf',
        'content-length': String(payload.length),
      },
      body: Readable.from([payload]),
    });

    expect(putRes.statusCode).toBe(202);
    const putBody = JSON.parse(putRes.body);

    // Validate 202 response includes identity
    expect(putBody.identity).toBeDefined();
    const putIdentity: ArtifactIdentity = putBody.identity;

    expect(validateArtifactIdentity(putIdentity).valid).toBe(true);
    expect(isArtifactIdentity(putIdentity)).toBe(true);
    expect(putIdentity.sha256).toBe(expectedSha256);
    expect(putIdentity.sizeBytes).toBe(payload.length);
    expect(putIdentity.versionId).toBe(putBody.versionId);
    expect(typeof putIdentity.versionId).toBe('string');
    expect(putIdentity.versionId.length).toBeGreaterThan(0);
    expect(putIdentity.bucket).toBe(config.storage.s3.quarantineBucket);
    expect(putIdentity.objectKey).toBe(buildQuarantineKey(appId, session.sessionId));

    // Verify DB file_versions record has exact sha256_ingest and storage_version_id
    const dbFv = await adminPool.query(
      `SELECT bucket, object_key, storage_version_id, size_bytes, sha256_ingest
       FROM file_versions
       WHERE id = $1`,
      [putBody.fileVersionId],
    );
    expect(dbFv.rows.length).toBe(1);
    const fvRow = dbFv.rows[0];
    expect(fvRow.bucket).toBe(putIdentity.bucket);
    expect(fvRow.object_key).toBe(putIdentity.objectKey);
    expect(fvRow.storage_version_id).toBe(putIdentity.versionId);
    expect(Number(fvRow.size_bytes)).toBe(putIdentity.sizeBytes);
    expect(Buffer.from(fvRow.sha256_ingest).toString('hex')).toBe(expectedSha256);

    // Query GET /upload/:id/status with upload token
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
    expect(statusBody.identity).toBeDefined();

    const statusIdentity: ArtifactIdentity = statusBody.identity;
    expect(validateArtifactIdentity(statusIdentity).valid).toBe(true);

    // Cryptographic identity comparison between PUT response and GET status response
    const comparison = compareArtifactIdentities(putIdentity, statusIdentity);
    expect(comparison.equal).toBe(true);
    expect(comparison.mismatches).toEqual([]);

    // Query GET /api/v1/upload/:id/status with application API key
    const apiStatusRes = await app.inject({
      method: 'GET',
      url: `/api/v1/upload/${session.sessionId}/status`,
      headers: {
        authorization: `Bearer ${apiKeyRaw}`,
      },
    });

    expect(apiStatusRes.statusCode).toBe(200);
    const apiStatusBody = JSON.parse(apiStatusRes.body);
    expect(apiStatusBody.identity).toBeDefined();
    const apiComparison = compareArtifactIdentities(putIdentity, apiStatusBody.identity);
    expect(apiComparison.equal).toBe(true);
    expect(apiComparison.mismatches).toEqual([]);
  });

  it('rejects upload with CHECKSUM_MISMATCH when declared SHA-256 differs from computed hash', async () => {
    const payload = Buffer.from('Authentic Payload Content');
    const wrongSha256 = '0'.repeat(64);

    const session = await createUploadSession({
      filename: 'tampered.pdf',
      declaredMime: 'application/pdf',
      declaredSize: payload.length,
      declaredSha256: wrongSha256,
    });

    const putRes = await app.inject({
      method: 'PUT',
      url: `/upload/${session.sessionId}`,
      headers: {
        authorization: `Bearer ${session.uploadToken}`,
        'content-type': 'application/pdf',
        'content-length': String(payload.length),
      },
      body: Readable.from([payload]),
    });

    expect(putRes.statusCode).toBe(400);
    const errBody = JSON.parse(putRes.body);
    expect(errBody.title).toBe('Validation Error');
    expect(errBody.detail).toContain('does not match declared digest');

    // Status is FAILED and identity is null
    const statusRes = await app.inject({
      method: 'GET',
      url: `/upload/${session.sessionId}/status`,
      headers: {
        authorization: `Bearer ${session.uploadToken}`,
      },
    });

    expect(statusRes.statusCode).toBe(200);
    const statusBody = JSON.parse(statusRes.body);
    expect(statusBody.status).toBe('FAILED');
    expect(statusBody.identity).toBeNull();
  });
});
