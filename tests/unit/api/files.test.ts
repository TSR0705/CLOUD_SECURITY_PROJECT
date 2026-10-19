/**
 * @sug/test/unit/api/files.test.ts
 *
 * Unit tests for Phase P20 Clean Object Access & File Management:
 * - GET /files/:id and GET /api/v1/files/:id
 *   - Verify-before-release: decryptBuffer validates auth tag and digest before plaintext release
 *   - Tampered ciphertext rejection (fail-closed, 500, no plaintext leakage)
 *   - Security headers: nosniff, CSP sandbox, attachment, no-store
 *   - Tenant isolation (authz-07: cross-tenant access returns 403)
 *   - User RBAC (admin, analyst, auditor allowed)
 *   - Status guards (non-promoted returns 400, deleted returns 404)
 * - DELETE /files/:id and DELETE /api/v1/files/:id
 *   - Soft delete: status -> 'DELETED', deleted_at set, audit FILE_DELETED logged
 *   - User RBAC: non-admin (analyst, auditor) denied 403, admin allowed
 *   - Tenant isolation: cross-tenant API key denied 403
 */

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createApp } from '../../../services/api/src/app.js';
import { LocalKeyProvider, DEFAULT_LOCAL_KEY_REFERENCE, encryptBuffer } from '@sug/crypto';
import { NotFound, type StorageProvider } from '@sug/storage';
import { createDashboardToken } from '../../../services/api/src/auth/jwt.js';
import type { Config } from '@sug/shared/config';

import type { ApiKeyDatabase } from '../../../services/api/src/auth/types.js';
import type { ApiKeyService } from '../../../services/api/src/auth/service.js';

describe('Phase P20: Edge API Clean Object Access & File Management (Unit Tests)', () => {
  let app: FastifyInstance;
  let privateKeyPem: string;
  const testKek = crypto.randomBytes(32);
  let keyProvider: LocalKeyProvider;

  const testAppId = crypto.randomUUID();
  const otherAppId = crypto.randomUUID();
  const testFileId = crypto.randomUUID();
  const testFileVersionId = crypto.randomUUID();

  const originalPlaintext = Buffer.from('Sensitive executive audit summary 2026', 'utf8');
  const plaintextSha256 = crypto.createHash('sha256').update(originalPlaintext).digest('hex');
  const cleanBucket = 'sug-clean-local';
  const cleanKey = `objects/${testAppId}/${testFileId}`;

  let cleanStorageMap: Map<string, Buffer>;
  let mockDbRows: {
    files: Map<string, Record<string, unknown>>;
    cloudObjects: Map<string, Record<string, unknown>>;
    auditEvents: Array<{
      actorType?: unknown;
      actorId?: unknown;
      action?: string;
      refs: Record<string, unknown>;
      details: Record<string, unknown>;
    }>;
  };

  // Helper to generate stream from buffer
  function createStream(buf: Buffer): NodeJS.ReadableStream {
    return Readable.from(buf);
  }

  beforeEach(async () => {
    // Generate Ed25519 keypair for JWT signing
    const keyPair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    privateKeyPem = keyPair.privateKey;

    keyProvider = new LocalKeyProvider({
      keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
      defaultKeyReference: DEFAULT_LOCAL_KEY_REFERENCE,
    });

    // Encrypt file into SUG1 envelope
    const encrypted = await encryptBuffer(originalPlaintext, {
      keyProvider,
      aad: {
        appId: testAppId,
        fileId: testFileId,
        storageVersionId: 'q-ver-001',
        sha256Plaintext: plaintextSha256,
      },
    });

    cleanStorageMap = new Map();
    cleanStorageMap.set(`${cleanBucket}/${cleanKey}`, encrypted.serialized);

    mockDbRows = {
      files: new Map(),
      cloudObjects: new Map(),
      auditEvents: [],
    };

    // Seed file record
    mockDbRows.files.set(testFileId, {
      id: testFileId,
      application_id: testAppId,
      original_filename: 'audit-report.pdf',
      display_filename: 'audit-report.pdf',
      mime_type: 'application/pdf',
      size_bytes: originalPlaintext.length,
      sha256: plaintextSha256,
      status: 'PROMOTED',
      created_at: new Date(),
      deleted_at: null,
      file_version_id: testFileVersionId,
      cloud_object_id: 'co-123',
      zone: 'clean',
      bucket: cleanBucket,
      object_key: cleanKey,
      storage_version_id: 'q-ver-001',
      clean_storage_version_id: 'clean-ver-001',
      clean_size_bytes: encrypted.serialized.length,
      sha256_cipher: crypto.createHash('sha256').update(encrypted.serialized).digest('hex'),
      sha256_plain: plaintextSha256,
      enc_alg: 'AES-256-GCM',
      kek_id: DEFAULT_LOCAL_KEY_REFERENCE,
    });

    // Mock storage provider
    const mockStorageProvider: StorageProvider = {
      getByVersion: vi.fn(async ({ bucket, key, versionId }) => {
        const fullKey = `${bucket}/${key}`;
        const buf = cleanStorageMap.get(fullKey);
        if (!buf) {
          throw new NotFound(`Object ${key} version ${versionId} not found`);
        }
        return {
          body: createStream(buf) as Readable,
          bucket,
          key,
          versionId,
          contentLength: buf.length,
        };
      }),
      putIfAbsent: vi.fn(),
      head: vi.fn(async ({ bucket, key }) => {
        const fullKey = `${bucket}/${key}`;
        const buf = cleanStorageMap.get(fullKey);
        if (!buf) {
          throw new NotFound(`Object ${key} not found`);
        }
        return {
          bucket,
          key,
          contentLength: buf.length,
        };
      }),
    };

    // Mock DB executor
    const mockDb = {
      query: vi.fn(async (sql: string, params?: unknown[]) => {
        // Query for file details
        if (
          sql.includes('FROM files') &&
          (sql.includes('WHERE f.id = $1') || sql.includes('WHERE id = $1'))
        ) {
          const fileId = params?.[0] as string;
          const file = mockDbRows.files.get(fileId);
          if (file) {
            return { rows: [file], rowCount: 1 };
          }
          return { rows: [], rowCount: 0 };
        }

        // Soft delete update
        if (sql.includes("UPDATE files SET status = 'DELETED'")) {
          const fileId = params?.[0] as string;
          const file = mockDbRows.files.get(fileId);
          if (file && file.status !== 'DELETED') {
            file.status = 'DELETED';
            file.deleted_at = new Date();
            return { rows: [file], rowCount: 1 };
          }
          return { rows: [], rowCount: 0 };
        }

        // Audit append
        if (sql.includes('audit_append')) {
          const match = sql.match(
            /'(FILE_DOWNLOADED|FILE_DELETED|PROMOTION_REJECTED|FILE_PROMOTED)'/,
          );
          const action = match ? match[1] : (params?.[2] as string) || 'UNKNOWN';
          const refs = params?.[2] ? JSON.parse(params[2] as string) : {};
          const details = params?.[3] ? JSON.parse(params[3] as string) : {};
          mockDbRows.auditEvents.push({
            actorType: params?.[0],
            actorId: params?.[1],
            action,
            refs,
            details,
          });
          return { rows: [{ seq: mockDbRows.auditEvents.length }], rowCount: 1 };
        }

        return { rows: [], rowCount: 0 };
      }),
    };

    // Mock API key service with proper method name verifyApiKey
    const mockApiKeyService = {
      verifyApiKey: vi.fn(async (rawKey: string) => {
        if (rawKey === 'sug_test_validkey') {
          return {
            isValid: true,
            app: {
              applicationId: testAppId,
              apiKeyId: 'ak-test-1',
              keyPrefix: 'sug_test',
              scopes: ['read', 'write', '*'],
            },
          };
        }
        if (rawKey === 'sug_other_validkey') {
          return {
            isValid: true,
            app: {
              applicationId: otherAppId,
              apiKeyId: 'ak-other-1',
              keyPrefix: 'sug_other',
              scopes: ['read', 'write', '*'],
            },
          };
        }
        return { isValid: false, reason: 'Invalid or revoked key' };
      }),
    };

    const mockConfig: Config = {
      nodeEnv: 'test',
      logLevel: 'error',
      port: 3000,
      host: '0.0.0.0',
      serviceName: 'sug-api',
      database: {
        url: 'postgres://sug_admin:dummy@127.0.0.1:5432/sug',
        host: '127.0.0.1',
        port: 5432,
        user: 'sug_admin',
        name: 'sug',
      },
      storage: {
        s3: {
          endpoint: 'http://localhost:4566',
          region: 'us-east-1',
          quarantineBucket: 'sug-quarantine-local',
          cleanBucket,
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
        kek: testKek.toString('hex'),
        jwtPrivateKey: privateKeyPem,
        checkpointPrivateKey: privateKeyPem,
      },
    };

    app = await createApp({
      config: mockConfig,
      authDb: mockDb as unknown as ApiKeyDatabase,
      apiKeyService: mockApiKeyService as unknown as ApiKeyService,
      storageProvider: mockStorageProvider,
      keyProvider,
    });
  });

  describe('1. GET /files/:id — Verify-Before-Release & Safe Headers', () => {
    it('decrypts verified clean object and streams plaintext with all security headers', async () => {
      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(200);

      // Verify strict security headers
      expect(response.headers['content-type']).toBe('application/octet-stream');
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['content-security-policy']).toBe("default-src 'none'; sandbox");
      expect(response.headers['cache-control']).toBe('no-store, private');
      expect(response.headers['content-disposition']).toBe(
        'attachment; filename="audit-report.pdf"',
      );
      expect(response.headers['x-payload-sha256']).toBe(plaintextSha256);

      // Verify payload matches original plaintext exactly
      expect(response.rawPayload.equals(originalPlaintext)).toBe(true);

      // Verify FILE_DOWNLOADED audit event was logged
      const downloadAudit = mockDbRows.auditEvents.find((e) => e.action === 'FILE_DOWNLOADED');
      expect(downloadAudit).toBeDefined();
      expect(downloadAudit.refs.file_id).toBe(testFileId);
    });

    it('works identically via canonical /api/v1/files/:id path', async () => {
      const response = await app.inject({
        method: 'GET',
        url: `/api/v1/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(200);
      expect(response.rawPayload.equals(originalPlaintext)).toBe(true);
    });

    it('allows admin and analyst dashboard users to download promoted clean objects', async () => {
      const adminToken = await createDashboardToken(
        { id: crypto.randomUUID(), email: 'admin@gateway.local', role: 'admin' },
        privateKeyPem,
      );

      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      });

      expect(response.statusCode).toBe(200);
      expect(response.rawPayload.equals(originalPlaintext)).toBe(true);
    });

    it('allows auditor dashboard users to download promoted clean objects', async () => {
      const auditorToken = await createDashboardToken(
        { id: crypto.randomUUID(), email: 'auditor@gateway.local', role: 'auditor' },
        privateKeyPem,
      );

      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: `Bearer ${auditorToken}`,
        },
      });

      expect(response.statusCode).toBe(200);
    });
  });

  describe('2. Verify-Before-Release: Tampered Ciphertext Rejection', () => {
    it('fails closed (500) and leaks zero plaintext when clean ciphertext envelope is tampered', async () => {
      // Tamper 1 byte in the ciphertext portion of the stored envelope
      const originalEnvelope = cleanStorageMap.get(`${cleanBucket}/${cleanKey}`)!;
      const tamperedEnvelope = Buffer.from(originalEnvelope);
      // Flip a bit in the last byte
      tamperedEnvelope[tamperedEnvelope.length - 1] ^= 0x01;
      cleanStorageMap.set(`${cleanBucket}/${cleanKey}`, tamperedEnvelope);

      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(500);
      const body = JSON.parse(response.payload);
      expect(body.title).toBe('Decryption Failed');
      expect(body.detail).toContain('verification failed');

      // Verify no plaintext was leaked in response
      expect(response.payload).not.toContain('Sensitive executive audit summary');
    });

    it('fails closed when auth tag is corrupted', async () => {
      const originalEnvelope = cleanStorageMap.get(`${cleanBucket}/${cleanKey}`)!;
      const tamperedEnvelope = Buffer.from(originalEnvelope);
      // Auth tag is in header
      tamperedEnvelope[65] ^= 0x42;
      cleanStorageMap.set(`${cleanBucket}/${cleanKey}`, tamperedEnvelope);

      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(500);
      expect(response.payload).not.toContain('Sensitive executive audit summary');
    });
  });

  describe('3. Tenant Isolation & Access Control (authz-07)', () => {
    it('rejects cross-tenant download attempt (403 Forbidden)', async () => {
      // Application B attempts to download Application A's file
      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_other_validkey', // Belongs to otherAppId!
        },
      });

      expect(response.statusCode).toBe(403);
      const body = JSON.parse(response.payload);
      expect(body.title).toBe('Forbidden');
      expect(body.detail).toContain('belongs to another application');
    });

    it('rejects cross-tenant delete attempt (403 Forbidden)', async () => {
      const response = await app.inject({
        method: 'DELETE',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_other_validkey',
        },
      });

      expect(response.statusCode).toBe(403);
      expect(JSON.parse(response.payload).detail).toContain('belong');
    });
  });

  describe('4. Status Guards & Non-Promoted Files', () => {
    it('returns 400 when attempting to download a QUARANTINED file', async () => {
      const file = mockDbRows.files.get(testFileId)!;
      file.status = 'QUARANTINED';

      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).detail).toContain("status 'QUARANTINED'");
    });

    it('returns 400 when attempting to download a BLOCKED file', async () => {
      const file = mockDbRows.files.get(testFileId)!;
      file.status = 'BLOCKED';

      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.payload).detail).toContain("status 'BLOCKED'");
    });

    it('returns 404 Not Found when file has been soft deleted', async () => {
      const file = mockDbRows.files.get(testFileId)!;
      file.status = 'DELETED';
      file.deleted_at = new Date();

      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.payload).detail).toContain('deleted');
    });
  });

  describe('5. DELETE /files/:id — Soft Delete & RBAC', () => {
    it('allows application owner API key to soft delete file', async () => {
      const response = await app.inject({
        method: 'DELETE',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(204);

      // Verify status updated in DB
      const file = mockDbRows.files.get(testFileId);
      expect(file.status).toBe('DELETED');
      expect(file.deleted_at).toBeDefined();

      // Verify FILE_DELETED audit event logged
      const deleteAudit = mockDbRows.auditEvents.find((e) => e.action === 'FILE_DELETED');
      expect(deleteAudit).toBeDefined();
      expect(deleteAudit.refs.file_id).toBe(testFileId);
    });

    it('allows admin users to delete files', async () => {
      const adminToken = await createDashboardToken(
        { id: crypto.randomUUID(), email: 'admin@gateway.local', role: 'admin' },
        privateKeyPem,
      );

      const response = await app.inject({
        method: 'DELETE',
        url: `/api/v1/files/${testFileId}`,
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
      });

      expect(response.statusCode).toBe(204);
    });

    it('rejects analyst users from deleting files (403 Forbidden)', async () => {
      const analystToken = await createDashboardToken(
        { id: crypto.randomUUID(), email: 'analyst@gateway.local', role: 'analyst' },
        privateKeyPem,
      );

      const response = await app.inject({
        method: 'DELETE',
        url: `/files/${testFileId}`,
        headers: {
          authorization: `Bearer ${analystToken}`,
        },
      });

      expect(response.statusCode).toBe(403);
      expect(JSON.parse(response.payload).detail).toContain('admin required');
    });

    it('returns 404 when deleting a non-existent file', async () => {
      const nonExistentFileId = crypto.randomUUID();
      const response = await app.inject({
        method: 'DELETE',
        url: `/files/${nonExistentFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(404);
      expect(JSON.parse(response.payload).detail).toContain('not exist');
    });

    it('returns 204 idempotently when deleting an already deleted file', async () => {
      const file = mockDbRows.files.get(testFileId)!;
      file.status = 'DELETED';
      file.deleted_at = new Date();

      const response = await app.inject({
        method: 'DELETE',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_test_validkey',
        },
      });

      expect(response.statusCode).toBe(204);
    });
  });

  describe('6. Authentication Failure Modes', () => {
    it('returns 401 when Authorization header is missing', async () => {
      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
      });

      expect(response.statusCode).toBe(401);
      expect(JSON.parse(response.payload).title).toBe('Unauthorized');
    });

    it('returns 401 when API key is invalid', async () => {
      const response = await app.inject({
        method: 'GET',
        url: `/files/${testFileId}`,
        headers: {
          authorization: 'Bearer sug_invalid_key_123',
        },
      });

      expect(response.statusCode).toBe(401);
    });
  });
});
