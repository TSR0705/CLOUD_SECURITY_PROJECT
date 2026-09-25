import { describe, it, expect, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import { createApp } from '../../../services/api/src/app.js';
import {
  generateRawKey,
  parseRawKey,
  computeKeyHmac,
  constantTimeCompare,
  KEY_PREFIX_LENGTH,
  SECRET_HEX_LENGTH,
} from '../../../services/api/src/auth/keys.js';
import { ApiKeyService } from '../../../services/api/src/auth/service.js';
import type { ApiKeyDatabase } from '../../../services/api/src/auth/types.js';
import type { Config } from '@sug/shared/config';

describe('Phase P6: Application API Keys (Unit Tests)', () => {
  const TEST_PEPPER = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  describe('1. Cryptographic Key Generation & Format', () => {
    it('generates a key with the expected structure and exact lengths', () => {
      const { rawKey, keyPrefix, secret } = generateRawKey();

      expect(rawKey).toMatch(/^sug_[a-f0-9]{8}_[a-f0-9]{64}$/);
      expect(keyPrefix).toHaveLength(KEY_PREFIX_LENGTH);
      expect(secret).toHaveLength(SECRET_HEX_LENGTH);
      expect(rawKey).toBe(`sug_${keyPrefix}_${secret}`);
    });

    it('generates cryptographically random keys that never collide across 1,000 samples', () => {
      const prefixes = new Set<string>();
      const secrets = new Set<string>();
      const count = 1000;

      for (let i = 0; i < count; i++) {
        const { keyPrefix, secret } = generateRawKey();
        prefixes.add(keyPrefix);
        secrets.add(secret);
      }

      expect(prefixes.size).toBe(count);
      expect(secrets.size).toBe(count);
    });

    it('parses valid raw keys correctly', () => {
      const validKey =
        'sug_a1b2c3d4_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const parsed = parseRawKey(validKey);

      expect(parsed).not.toBeNull();
      expect(parsed?.keyPrefix).toBe('a1b2c3d4');
      expect(parsed?.secret).toBe(
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      );
    });

    it('rejects malformed raw keys safely', () => {
      expect(parseRawKey('')).toBeNull();
      expect(parseRawKey(null)).toBeNull();
      expect(parseRawKey(undefined)).toBeNull();
      expect(parseRawKey(12345)).toBeNull();
      // Missing sug_ prefix
      expect(
        parseRawKey('a1b2c3d4_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
      ).toBeNull();
      // Wrong prefix length (7 chars)
      expect(
        parseRawKey('sug_a1b2c3d_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
      ).toBeNull();
      // Wrong prefix length (9 chars)
      expect(
        parseRawKey(
          'sug_a1b2c3d4e_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        ),
      ).toBeNull();
      // Non-hex characters in prefix
      expect(
        parseRawKey(
          'sug_a1b2c3z4_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        ),
      ).toBeNull();
      // Short secret (63 chars)
      expect(parseRawKey('sug_a1b2c3d4_' + 'a'.repeat(63))).toBeNull();
      // Long secret (65 chars)
      expect(parseRawKey('sug_a1b2c3d4_' + 'a'.repeat(65))).toBeNull();
      // Non-hex secret
      expect(parseRawKey('sug_a1b2c3d4_' + 'g'.repeat(64))).toBeNull();
      // Delimiter injection
      expect(parseRawKey('sug_a1b2c3d4_secret_extra')).toBeNull();
    });
  });

  describe('2. HMAC-SHA-256 & Peppered Storage', () => {
    it('computes deterministic 32-byte HMAC digest given same secret and pepper', () => {
      const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const hmac1 = computeKeyHmac(secret, TEST_PEPPER);
      const hmac2 = computeKeyHmac(secret, TEST_PEPPER);

      expect(Buffer.isBuffer(hmac1)).toBe(true);
      expect(hmac1.length).toBe(32);
      expect(hmac1.equals(hmac2)).toBe(true);
    });

    it('produces completely different HMACs under different peppers (avalanche effect)', () => {
      const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const otherPepper = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
      const hmac1 = computeKeyHmac(secret, TEST_PEPPER);
      const hmac2 = computeKeyHmac(secret, otherPepper);

      expect(hmac1.equals(hmac2)).toBe(false);
    });

    it('throws when secret or pepper is missing', () => {
      expect(() => computeKeyHmac('', TEST_PEPPER)).toThrow();
      expect(() => computeKeyHmac('secret', '')).toThrow();
    });
  });

  describe('3. Constant-Time Comparison', () => {
    it('returns true for matching 32-byte buffers', () => {
      const b1 = crypto.randomBytes(32);
      const b2 = Buffer.from(b1);
      expect(constantTimeCompare(b1, b2)).toBe(true);
    });

    it('returns false for mismatched 32-byte buffers', () => {
      const b1 = crypto.randomBytes(32);
      const b2 = crypto.randomBytes(32);
      expect(constantTimeCompare(b1, b2)).toBe(false);
    });

    it('safely returns false on buffer length mismatch without throwing RangeError', () => {
      const b32 = crypto.randomBytes(32);
      const b31 = crypto.randomBytes(31);
      const b64 = crypto.randomBytes(64);

      expect(constantTimeCompare(b32, b31)).toBe(false);
      expect(constantTimeCompare(b31, b32)).toBe(false);
      expect(constantTimeCompare(b32, b64)).toBe(false);
      expect(constantTimeCompare(null, b32)).toBe(false);
      expect(constantTimeCompare(b32, 'string')).toBe(false);
    });
  });

  describe('4. ApiKeyService Domain Logic', () => {
    let mockQueries: Array<{ sql: string; params?: unknown[] }>;
    let mockDb: ApiKeyDatabase;
    let service: ApiKeyService;

    const fakeAppId = '018f3a5e-7a42-7000-8000-000000000001';
    const fakeUserId = '018f3a5e-7a42-7000-8000-000000000002';
    const fakeKeyId = '018f3a5e-7a42-7000-8000-000000000003';

    beforeEach(() => {
      mockQueries = [];
      mockDb = {
        query: async <T>(sql: string, params?: unknown[]) => {
          mockQueries.push({ sql, params });
          return { rows: [] as T[] };
        },
      };
      service = new ApiKeyService({ db: mockDb, pepper: TEST_PEPPER });
    });

    it('createApiKey computes HMAC, stores only hash, and logs audit event', async () => {
      mockDb.query = async <T>(sql: string, params?: unknown[]) => {
        mockQueries.push({ sql, params });
        if (sql.includes('INSERT INTO api_keys')) {
          return {
            rows: [{ id: fakeKeyId, created_at: new Date() }] as unknown as T[],
          };
        }
        return { rows: [] as T[] };
      };

      const result = await service.createApiKey({
        applicationId: fakeAppId,
        createdBy: fakeUserId,
        scopes: ['upload', 'read'],
        expiresInDays: 30,
      });

      expect(result.apiKeyId).toBe(fakeKeyId);
      expect(result.rawKey).toMatch(/^sug_[a-f0-9]{8}_[a-f0-9]{64}$/);
      expect(result.applicationId).toBe(fakeAppId);
      expect(result.scopes).toEqual(['upload', 'read']);
      expect(result.expiresAt).not.toBeNull();

      // Check DB query parameters
      const insertQuery = mockQueries.find((q) => q.sql.includes('INSERT INTO api_keys'));
      expect(insertQuery).toBeDefined();
      // Ensure rawKey is NEVER stored in database params
      expect(JSON.stringify(insertQuery?.params)).not.toContain(result.rawKey);
      // Ensure the secret is NEVER stored in database params
      const parsed = parseRawKey(result.rawKey);
      expect(JSON.stringify(insertQuery?.params)).not.toContain(parsed?.secret);

      // Check audit event
      const auditQuery = mockQueries.find((q) => q.sql.includes('audit_append'));
      expect(auditQuery).toBeDefined();
      expect(auditQuery?.params?.[2]).toBe('api_key.created');
      expect(JSON.stringify(auditQuery?.params)).not.toContain(result.rawKey);
      expect(JSON.stringify(auditQuery?.params)).not.toContain(parsed?.secret);
    });

    it('verifyApiKey succeeds and returns app context for valid key', async () => {
      const { rawKey, keyPrefix, secret } = generateRawKey();
      const expectedHmac = computeKeyHmac(secret, TEST_PEPPER);

      mockDb.query = async <T>(sql: string, params?: unknown[]) => {
        mockQueries.push({ sql, params });
        if (sql.includes('SELECT id, application_id')) {
          return {
            rows: [
              {
                id: fakeKeyId,
                application_id: fakeAppId,
                key_prefix: keyPrefix,
                key_hmac: expectedHmac,
                scopes: ['upload', 'read'],
                expires_at: null,
                revoked_at: null,
              },
            ] as unknown as T[],
          };
        }
        return { rows: [] as T[] };
      };

      const result = await service.verifyApiKey(rawKey);

      expect(result.isValid).toBe(true);
      expect(result.app).toEqual({
        applicationId: fakeAppId,
        apiKeyId: fakeKeyId,
        keyPrefix,
        scopes: ['upload', 'read'],
      });

      // Audit verification: api_key.auth_success logged
      const auditSuccess = mockQueries.find(
        (q) => q.sql.includes('audit_append') && q.params?.[2] === 'api_key.auth_success',
      );
      expect(auditSuccess).toBeDefined();
    });

    it('verifyApiKey fails when key prefix is not in database', async () => {
      const { rawKey } = generateRawKey();

      mockDb.query = async <T>(sql: string, params?: unknown[]) => {
        mockQueries.push({ sql, params });
        return { rows: [] as T[] };
      };

      const result = await service.verifyApiKey(rawKey);
      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('KEY_NOT_FOUND');

      const auditFail = mockQueries.find(
        (q) => q.sql.includes('audit_append') && q.params?.[2] === 'api_key.auth_failure',
      );
      expect(auditFail).toBeDefined();
    });

    it('verifyApiKey fails when secret HMAC does not match', async () => {
      const { rawKey, keyPrefix } = generateRawKey();
      // Store a completely different HMAC in database
      const randomHmac = crypto.randomBytes(32);

      mockDb.query = async <T>(sql: string, params?: unknown[]) => {
        mockQueries.push({ sql, params });
        if (sql.includes('SELECT id, application_id')) {
          return {
            rows: [
              {
                id: fakeKeyId,
                application_id: fakeAppId,
                key_prefix: keyPrefix,
                key_hmac: randomHmac,
                scopes: ['upload'],
                expires_at: null,
                revoked_at: null,
              },
            ] as unknown as T[],
          };
        }
        return { rows: [] as T[] };
      };

      const result = await service.verifyApiKey(rawKey);
      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('HMAC_MISMATCH');
    });

    it('verifyApiKey fails when key is revoked', async () => {
      const { rawKey, keyPrefix, secret } = generateRawKey();
      const expectedHmac = computeKeyHmac(secret, TEST_PEPPER);

      mockDb.query = async <T>(sql: string, params?: unknown[]) => {
        mockQueries.push({ sql, params });
        if (sql.includes('SELECT id, application_id')) {
          return {
            rows: [
              {
                id: fakeKeyId,
                application_id: fakeAppId,
                key_prefix: keyPrefix,
                key_hmac: expectedHmac,
                scopes: ['upload'],
                expires_at: null,
                revoked_at: new Date(), // Revoked
              },
            ] as unknown as T[],
          };
        }
        return { rows: [] as T[] };
      };

      const result = await service.verifyApiKey(rawKey);
      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('KEY_REVOKED');
    });

    it('verifyApiKey fails when key is expired', async () => {
      const { rawKey, keyPrefix, secret } = generateRawKey();
      const expectedHmac = computeKeyHmac(secret, TEST_PEPPER);

      mockDb.query = async <T>(sql: string, params?: unknown[]) => {
        mockQueries.push({ sql, params });
        if (sql.includes('SELECT id, application_id')) {
          return {
            rows: [
              {
                id: fakeKeyId,
                application_id: fakeAppId,
                key_prefix: keyPrefix,
                key_hmac: expectedHmac,
                scopes: ['upload'],
                expires_at: new Date(Date.now() - 10000), // Expired 10s ago
                revoked_at: null,
              },
            ] as unknown as T[],
          };
        }
        return { rows: [] as T[] };
      };

      const result = await service.verifyApiKey(rawKey);
      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('KEY_EXPIRED');
    });

    it('revokeApiKey updates revoked_at and logs audit event', async () => {
      mockDb.query = async <T>(sql: string, params?: unknown[]) => {
        mockQueries.push({ sql, params });
        if (sql.includes('UPDATE api_keys')) {
          return {
            rows: [
              {
                id: fakeKeyId,
                application_id: fakeAppId,
                key_prefix: 'a1b2c3d4',
              },
            ] as unknown as T[],
          };
        }
        return { rows: [] as T[] };
      };

      const ok = await service.revokeApiKey(fakeKeyId, fakeUserId);
      expect(ok).toBe(true);

      const revokeAudit = mockQueries.find(
        (q) => q.sql.includes('audit_append') && q.params?.[2] === 'api_key.revoked',
      );
      expect(revokeAudit).toBeDefined();
    });
  });

  describe('5. Fastify Authentication Middleware & HTTP Behavior', () => {
    let app: Awaited<ReturnType<typeof createApp>>;
    let mockService: ApiKeyService;
    const validKey =
      'sug_a1b2c3d4_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    const mockConfig: Config = {
      nodeEnv: 'test',
      logLevel: 'silent',
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
          cleanBucket: 'sug-clean-local',
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
        pepper: TEST_PEPPER,
        kek: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        jwtPrivateKey: 'dummy',
        checkpointPrivateKey: 'dummy',
      },
      toRedacted: () => ({}) as unknown as ReturnType<Config['toRedacted']>,
      toJSON: () => ({}),
    } as unknown as Config;

    const mockDb = { checkReachability: async () => {} };
    const mockStorage = { checkReachability: async () => {} };

    beforeEach(async () => {
      const fakeDb: ApiKeyDatabase = {
        query: async () => ({ rows: [] }),
      };
      mockService = new ApiKeyService({ db: fakeDb, pepper: TEST_PEPPER });

      // Mock verifyApiKey
      mockService.verifyApiKey = async (rawKey: unknown) => {
        if (rawKey === validKey) {
          return {
            isValid: true,
            app: {
              applicationId: '018f3a5e-7a42-7000-8000-000000000001',
              apiKeyId: '018f3a5e-7a42-7000-8000-000000000002',
              keyPrefix: 'a1b2c3d4',
              scopes: ['upload', 'read'],
            },
          };
        }
        return { isValid: false, reason: 'KEY_NOT_FOUND' };
      };

      app = await createApp({
        config: mockConfig,
        db: mockDb,
        storage: mockStorage,
        apiKeyService: mockService,
      });

      // Also add scoped test route
      const { authenticateApiKey } = await import('../../../services/api/src/auth/middleware.js');
      app.get(
        '/admin-scoped',
        { preHandler: authenticateApiKey(mockService, { requiredScopes: ['admin'] }) },
        async () => ({ ok: true }),
      );

      await app.ready();
    });

    it('returns 401 Problem Details when Authorization header is missing', async () => {
      const res = await app.inject({ method: 'GET', url: '/api/v1/auth/probe' });

      expect(res.statusCode).toBe(401);
      expect(res.headers['content-type']).toContain('application/problem+json');
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:unauthorized');
      expect(body.title).toBe('Unauthorized');
      expect(body.detail).toBe('Missing or invalid authorization header');
    });

    it('returns 401 when Authorization header scheme is not Bearer', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/probe',
        headers: { authorization: 'Basic dXNlcjpwYXNz' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:unauthorized');
      expect(body.detail).toContain('Invalid authorization scheme');
    });

    it('returns 401 with generic message when API key is invalid', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/probe',
        headers: {
          authorization:
            'Bearer sug_wrongkey_0000000000000000000000000000000000000000000000000000000000000000',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:unauthorized');
      expect(body.detail).toBe('Authentication failed');
    });

    it('returns 200 and returns auth context when valid Bearer key is provided', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/probe',
        headers: { authorization: `Bearer ${validKey}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('authenticated');
      expect(body.applicationId).toBe('018f3a5e-7a42-7000-8000-000000000001');
      expect(body.keyPrefix).toBe('a1b2c3d4');
      expect(body.scopes).toEqual(['upload', 'read']);
    });

    it('returns 403 Problem Details when API key lacks required scope', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/admin-scoped',
        headers: { authorization: `Bearer ${validKey}` },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:forbidden');
      expect(body.title).toBe('Forbidden');
      expect(body.detail).toBe('Insufficient API key scopes');
    });
  });

  describe('6. Adversarial Header & Secret Injection Attacks', () => {
    let app: Awaited<ReturnType<typeof createApp>>;
    let mockService: ApiKeyService;

    const mockConfig: Config = {
      nodeEnv: 'test',
      logLevel: 'silent',
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
          cleanBucket: 'sug-clean-local',
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
        pepper: TEST_PEPPER,
        kek: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        jwtPrivateKey: 'dummy',
        checkpointPrivateKey: 'dummy',
      },
      toRedacted: () => ({}) as unknown as ReturnType<Config['toRedacted']>,
      toJSON: () => ({}),
    } as unknown as Config;

    const mockDb = { checkReachability: async () => {} };
    const mockStorage = { checkReachability: async () => {} };

    beforeEach(async () => {
      const fakeDb: ApiKeyDatabase = { query: async () => ({ rows: [] }) };
      mockService = new ApiKeyService({ db: fakeDb, pepper: TEST_PEPPER });
      mockService.verifyApiKey = async () => ({ isValid: false, reason: 'KEY_NOT_FOUND' });

      app = await createApp({
        config: mockConfig,
        db: mockDb,
        storage: mockStorage,
        apiKeyService: mockService,
      });

      await app.ready();
    });

    it('rejects duplicate/array Authorization headers (header smuggling defense)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/probe',
        headers: {
          authorization: [
            'Bearer sug_a1b2c3d4_xxx',
            'Bearer sug_ffffffff_yyy',
          ] as unknown as string,
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.detail).toContain('Duplicate or ambiguous');
    });

    it('rejects CRLF and newline injection in Authorization header', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/probe',
        headers: {
          authorization: 'Bearer sug_a1b2c3d4_xxx\r\nInjected: evil',
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('evil');
    });

    it('handles oversized 10,000-character Authorization header safely without crash', async () => {
      const hugeToken = 'Bearer sug_' + 'f'.repeat(10000);
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/probe',
        headers: { authorization: hugeToken },
      });

      expect(res.statusCode).toBe(401);
    });

    it('rejects Unicode confusables and non-ASCII characters in API key', async () => {
      const unicodeToken = 'Bearer sug_a1b2c3d4_🚀🚀🚀';
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/probe',
        headers: { authorization: unicodeToken },
      });

      expect(res.statusCode).toBe(401);
    });
  });
});
