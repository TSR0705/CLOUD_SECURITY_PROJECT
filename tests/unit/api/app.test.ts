import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp, resolveRequestId } from '../../../services/api/src/app.js';
import type {
  ReadinessDatabase,
  ReadinessStorage,
} from '../../../services/api/src/health/types.js';
import type { Config } from '@sug/shared/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

describe('Fastify API Foundation (Phase P5)', () => {
  let mockConfig: Config;
  let mockDb: ReadinessDatabase;
  let mockStorage: ReadinessStorage;

  beforeEach(() => {
    mockConfig = {
      nodeEnv: 'test',
      logLevel: 'error',
      port: 3000,
      host: '0.0.0.0',
      serviceName: 'sug-api',
      database: {
        url: 'postgres://sug_admin:dummy_pass@127.0.0.1:5432/sug',
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
        pepper: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        kek: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        jwtPrivateKey: 'dummy',
        checkpointPrivateKey: 'dummy',
      },
      toRedacted: () => ({}) as unknown as ReturnType<Config['toRedacted']>,
      toJSON: () => ({}),
    } as unknown as Config;

    mockDb = {
      checkReachability: async () => {},
    };

    mockStorage = {
      checkReachability: async () => {},
    };
  });

  describe('1. Application Factory', () => {
    it('initializes Fastify application instance without binding to network socket', async () => {
      const app = await createApp({
        config: mockConfig,
        db: mockDb,
        storage: mockStorage,
      });

      expect(app).toBeDefined();
      expect(typeof app.inject).toBe('function');
      expect(typeof app.listen).toBe('function');

      await app.close();
    });

    it('shuts down cleanly and calls dependency close hooks', async () => {
      let dbClosed = false;
      let storageClosed = false;

      const closingDb: ReadinessDatabase = {
        checkReachability: async () => {},
        close: async () => {
          dbClosed = true;
        },
      };

      const closingStorage: ReadinessStorage = {
        checkReachability: async () => {},
        close: async () => {
          storageClosed = true;
        },
      };

      const app = await createApp({
        config: mockConfig,
        db: closingDb,
        storage: closingStorage,
      });

      await app.close();
      expect(dbClosed).toBe(true);
      expect(storageClosed).toBe(true);
    });
  });

  describe('2. Request ID Handling & Policy', () => {
    it('generates a random UUID when incoming request has no X-Request-ID', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });

      const response = await app.inject({
        method: 'GET',
        url: '/healthz',
      });

      expect(response.statusCode).toBe(200);
      const reqId = response.headers['x-request-id'];
      expect(reqId).toBeDefined();
      expect(typeof reqId).toBe('string');
      // Must be a valid UUID format
      expect(reqId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

      await app.close();
    });

    it('accepts and preserves a valid incoming X-Request-ID', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });
      const validId = 'client-req-12345-abcdef_xyz';

      const response = await app.inject({
        method: 'GET',
        url: '/healthz',
        headers: {
          'x-request-id': validId,
        },
      });

      expect(response.statusCode).toBe(200);
      expect(response.headers['x-request-id']).toBe(validId);

      await app.close();
    });

    it('rejects oversized incoming X-Request-ID and replaces it with generated UUID', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });
      const oversizedId = 'a'.repeat(65);

      const response = await app.inject({
        method: 'GET',
        url: '/healthz',
        headers: {
          'x-request-id': oversizedId,
        },
      });

      expect(response.statusCode).toBe(200);
      const returnedId = response.headers['x-request-id'];
      expect(returnedId).not.toBe(oversizedId);
      expect(returnedId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

      await app.close();
    });

    it('rejects incoming X-Request-ID containing newlines or control characters (log injection defense)', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });
      const maliciousId = 'req-1\r\nINJECTED_LOG_ENTRY: admin';

      const response = await app.inject({
        method: 'GET',
        url: '/healthz',
        headers: {
          'x-request-id': maliciousId,
        },
      });

      expect(response.statusCode).toBe(200);
      const returnedId = response.headers['x-request-id'];
      expect(returnedId).not.toContain('\r');
      expect(returnedId).not.toContain('\n');
      expect(returnedId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

      await app.close();
    });

    it('resolveRequestId unit test enforces alphanumeric, hyphen, underscore within 64 chars', () => {
      expect(resolveRequestId('valid-id_123')).toBe('valid-id_123');
      expect(resolveRequestId('')).toMatch(/^[0-9a-f-]{36}$/);
      expect(resolveRequestId('   ')).toMatch(/^[0-9a-f-]{36}$/);
      expect(resolveRequestId('with spaces')).toMatch(/^[0-9a-f-]{36}$/);
      expect(resolveRequestId('with$special#chars!')).toMatch(/^[0-9a-f-]{36}$/);
      expect(resolveRequestId('a'.repeat(64))).toBe('a'.repeat(64));
      expect(resolveRequestId('a'.repeat(65))).toMatch(/^[0-9a-f-]{36}$/);
    });
  });

  describe('3. RFC 7807 / RFC 9457 Problem Details Error Responses', () => {
    it('returns application/problem+json on 404 Not Found', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });

      const response = await app.inject({
        method: 'GET',
        url: '/non-existent-route',
      });

      expect(response.statusCode).toBe(404);
      expect(response.headers['content-type']).toContain('application/problem+json');

      const body = JSON.parse(response.body);
      expect(body.type).toBe('urn:sug:error:not-found');
      expect(body.title).toBe('Not Found');
      expect(body.status).toBe(404);
      expect(body.detail).toContain('/non-existent-route');
      expect(body.instance).toBe('/non-existent-route');
      expect(body.requestId).toBeDefined();

      await app.close();
    });

    it('returns application/problem+json on schema validation failure (400)', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });

      // Add a test route with schema validation
      app.post(
        '/test-validate',
        {
          schema: {
            body: {
              type: 'object',
              required: ['filename'],
              properties: {
                filename: { type: 'string', minLength: 3 },
              },
            },
          },
        },
        async () => ({ ok: true }),
      );

      const response = await app.inject({
        method: 'POST',
        url: '/test-validate',
        headers: { 'content-type': 'application/json' },
        payload: { filename: 'ab' }, // minLength is 3
      });

      expect(response.statusCode).toBe(400);
      expect(response.headers['content-type']).toContain('application/problem+json');

      const body = JSON.parse(response.body);
      expect(body.type).toBe('urn:sug:error:validation');
      expect(body.title).toBe('Validation Error');
      expect(body.status).toBe(400);
      expect(body.requestId).toBeDefined();

      await app.close();
    });

    it('sanitizes 500 internal errors: never leaks stack trace, SQL, paths, or secrets', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });

      const SENSITIVE_SENTINEL = 'SUPER_SECRET_INTERNAL_DB_PASSWORD_12345';
      const SENSITIVE_SQL = 'SELECT * FROM users WHERE password_hash = "secret"';

      app.get('/test-error', async () => {
        const error = new Error(
          `Database error at C:\\Users\\ACER\\project\\secret.ts: ${SENSITIVE_SQL} with password ${SENSITIVE_SENTINEL}`,
        );
        throw error;
      });

      const response = await app.inject({
        method: 'GET',
        url: '/test-error',
      });

      expect(response.statusCode).toBe(500);
      expect(response.headers['content-type']).toContain('application/problem+json');

      const body = JSON.parse(response.body);
      expect(body.type).toBe('urn:sug:error:internal');
      expect(body.title).toBe('Internal Server Error');
      expect(body.detail).toBe('An internal server error occurred');
      expect(body.requestId).toBeDefined();

      // Ensure no internal details leaked
      expect(response.body).not.toContain(SENSITIVE_SENTINEL);
      expect(response.body).not.toContain(SENSITIVE_SQL);
      expect(response.body).not.toContain('stack');
      expect(response.body).not.toContain('secret.ts');

      await app.close();
    });

    it('includes request ID in problem details matching X-Request-ID response header', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });
      const customId = 'trace-id-abc-789';

      const response = await app.inject({
        method: 'GET',
        url: '/unknown-resource',
        headers: { 'x-request-id': customId },
      });

      expect(response.statusCode).toBe(404);
      expect(response.headers['x-request-id']).toBe(customId);

      const body = JSON.parse(response.body);
      expect(body.requestId).toBe(customId);

      await app.close();
    });
  });

  describe('4. Security Headers (Helmet)', () => {
    it('sets standard defensive security headers on all responses', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });

      const response = await app.inject({
        method: 'GET',
        url: '/healthz',
      });

      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['strict-transport-security']).toBeDefined();

      await app.close();
    });
  });

  describe('5. In-Memory Rate Limiting', () => {
    it('allows requests within threshold and returns rate limit headers', async () => {
      const app = await createApp({
        config: mockConfig,
        db: mockDb,
        storage: mockStorage,
        rateLimitMax: 5,
        rateLimitTimeWindow: '1 minute',
      });

      app.get('/test-rate', async () => ({ status: 'ok' }));

      const response = await app.inject({
        method: 'GET',
        url: '/test-rate',
      });

      expect(response.statusCode).toBe(200);
      expect(Number(response.headers['x-ratelimit-limit'])).toBe(5);
      expect(response.headers['x-ratelimit-remaining']).toBeDefined();

      await app.close();
    });

    it('returns 429 problem+json when request threshold is exceeded', async () => {
      const app = await createApp({
        config: mockConfig,
        db: mockDb,
        storage: mockStorage,
        rateLimitMax: 2,
        rateLimitTimeWindow: '1 minute',
      });

      app.get('/test-rate-exhaust', async () => ({ status: 'ok' }));

      // Request 1: 200
      const res1 = await app.inject({ method: 'GET', url: '/test-rate-exhaust' });
      expect(res1.statusCode).toBe(200);

      // Request 2: 200
      const res2 = await app.inject({ method: 'GET', url: '/test-rate-exhaust' });
      expect(res2.statusCode).toBe(200);

      // Request 3: 429
      const res3 = await app.inject({ method: 'GET', url: '/test-rate-exhaust' });
      expect(res3.statusCode).toBe(429);
      expect(res3.headers['content-type']).toContain('application/problem+json');

      const body = JSON.parse(res3.body);
      expect(body.type).toBe('urn:sug:error:rate-limit');
      expect(body.title).toBe('Too Many Requests');
      expect(body.status).toBe(429);
      expect(body.detail).toContain('Rate limit exceeded');
      expect(body.requestId).toBeDefined();

      await app.close();
    });

    it('exempts /healthz and /readyz from global rate limiting', async () => {
      const app = await createApp({
        config: mockConfig,
        db: mockDb,
        storage: mockStorage,
        rateLimitMax: 2,
        rateLimitTimeWindow: '1 minute',
      });

      // Exhaust regular endpoint limit
      app.get('/api-traffic', async () => ({ ok: true }));
      await app.inject({ method: 'GET', url: '/api-traffic' });
      await app.inject({ method: 'GET', url: '/api-traffic' });
      const blocked = await app.inject({ method: 'GET', url: '/api-traffic' });
      expect(blocked.statusCode).toBe(429);

      // Health endpoints remain accessible and return 200
      for (let i = 0; i < 5; i++) {
        const healthRes = await app.inject({ method: 'GET', url: '/healthz' });
        expect(healthRes.statusCode).toBe(200);
        const readyRes = await app.inject({ method: 'GET', url: '/readyz' });
        expect(readyRes.statusCode).toBe(200);
      }

      await app.close();
    });
  });

  describe('6. Liveness Probe (GET /healthz)', () => {
    it('returns 200 { status: "ok" } immediately', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });

      const response = await app.inject({
        method: 'GET',
        url: '/healthz',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body).toEqual({ status: 'ok' });

      await app.close();
    });

    it('healthz never calls database or storage dependencies', async () => {
      let dbCalled = false;
      let storageCalled = false;

      const failingDb: ReadinessDatabase = {
        checkReachability: async () => {
          dbCalled = true;
          throw new Error('DB should not be called');
        },
      };

      const failingStorage: ReadinessStorage = {
        checkReachability: async () => {
          storageCalled = true;
          throw new Error('Storage should not be called');
        },
      };

      const app = await createApp({
        config: mockConfig,
        db: failingDb,
        storage: failingStorage,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/healthz',
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body)).toEqual({ status: 'ok' });
      expect(dbCalled).toBe(false);
      expect(storageCalled).toBe(false);

      await app.close();
    });
  });

  describe('7. Readiness Probe (GET /readyz)', () => {
    it('returns 200 { status: "ready" } when both DB and storage are reachable', async () => {
      const app = await createApp({ config: mockConfig, db: mockDb, storage: mockStorage });

      const response = await app.inject({
        method: 'GET',
        url: '/readyz',
      });

      expect(response.statusCode).toBe(200);
      expect(JSON.parse(response.body)).toEqual({ status: 'ready' });

      await app.close();
    });

    it('returns 503 { status: "not_ready" } when PostgreSQL fails', async () => {
      const failingDb: ReadinessDatabase = {
        checkReachability: async () => {
          throw new Error('ECONNREFUSED 127.0.0.1:5432');
        },
      };

      const app = await createApp({
        config: mockConfig,
        db: failingDb,
        storage: mockStorage,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/readyz',
      });

      expect(response.statusCode).toBe(503);
      expect(JSON.parse(response.body)).toEqual({ status: 'not_ready' });
      // Crucial: no error details leaked
      expect(response.body).not.toContain('ECONNREFUSED');
      expect(response.body).not.toContain('127.0.0.1');

      await app.close();
    });

    it('returns 503 { status: "not_ready" } when Storage fails', async () => {
      const failingStorage: ReadinessStorage = {
        checkReachability: async () => {
          throw new Error('AWS S3 Endpoint unreachable: timeout');
        },
      };

      const app = await createApp({
        config: mockConfig,
        db: mockDb,
        storage: failingStorage,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/readyz',
      });

      expect(response.statusCode).toBe(503);
      expect(JSON.parse(response.body)).toEqual({ status: 'not_ready' });
      // Crucial: no AWS error details leaked
      expect(response.body).not.toContain('AWS');
      expect(response.body).not.toContain('S3');

      await app.close();
    });

    it('returns 503 { status: "not_ready" when both DB and Storage fail', async () => {
      const failingDb: ReadinessDatabase = {
        checkReachability: async () => {
          throw new Error('DB Down');
        },
      };
      const failingStorage: ReadinessStorage = {
        checkReachability: async () => {
          throw new Error('Storage Down');
        },
      };

      const app = await createApp({
        config: mockConfig,
        db: failingDb,
        storage: failingStorage,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/readyz',
      });

      expect(response.statusCode).toBe(503);
      expect(JSON.parse(response.body)).toEqual({ status: 'not_ready' });

      await app.close();
    });

    it('returns 503 { status: "not_ready" } on readiness check timeout', async () => {
      // Wrap with a quick timeout check
      let timedOut = false;
      const timeoutDb: ReadinessDatabase = {
        checkReachability: async () => {
          await new Promise<never>((_, reject) => {
            setTimeout(() => {
              timedOut = true;
              reject(new Error('Timeout'));
            }, 50);
          });
        },
      };

      const app = await createApp({
        config: mockConfig,
        db: timeoutDb,
        storage: mockStorage,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/readyz',
      });

      expect(response.statusCode).toBe(503);
      expect(JSON.parse(response.body)).toEqual({ status: 'not_ready' });
      expect(timedOut).toBe(true);

      await app.close();
    });

    it('recovers to 200 { status: "ready" } once dependency becomes reachable again', async () => {
      let isHealthy = false;

      const dynamicDb: ReadinessDatabase = {
        checkReachability: async () => {
          if (!isHealthy) {
            throw new Error('Temporarily offline');
          }
        },
      };

      const app = await createApp({
        config: mockConfig,
        db: dynamicDb,
        storage: mockStorage,
      });

      // 1. Initial failing state -> 503
      const res1 = await app.inject({ method: 'GET', url: '/readyz' });
      expect(res1.statusCode).toBe(503);
      expect(JSON.parse(res1.body)).toEqual({ status: 'not_ready' });

      // 2. Dependency recovers
      isHealthy = true;

      // 3. Subsequent check -> 200
      const res2 = await app.inject({ method: 'GET', url: '/readyz' });
      expect(res2.statusCode).toBe(200);
      expect(JSON.parse(res2.body)).toEqual({ status: 'ready' });

      await app.close();
    });
  });

  describe('8. OpenAPI Specification & Contract', () => {
    it('verifies committed docs/openapi.json contains valid OpenAPI 3.0 schema and no secrets', () => {
      const openApiPath = path.join(rootDir, 'docs', 'openapi.json');
      expect(fs.existsSync(openApiPath)).toBe(true);

      const content = fs.readFileSync(openApiPath, 'utf8');
      const spec = JSON.parse(content);

      expect(spec.openapi).toBe('3.0.3');
      expect(spec.info.title).toBe('Secure Upload Gateway API');
      expect(spec.paths['/healthz']).toBeDefined();
      expect(spec.paths['/readyz']).toBeDefined();
      expect(spec.components.schemas.ProblemDetails).toBeDefined();

      // Zero-leak check: verify no secrets or internal strings exist in OpenAPI
      expect(content).not.toContain('sug_dev_password');
      expect(content).not.toContain('AWS_SECRET_ACCESS_KEY');
      expect(content).not.toContain('pepper');
      expect(content).not.toContain('kek');
      expect(content).not.toContain('PRIVATE KEY');
    });
  });
});
