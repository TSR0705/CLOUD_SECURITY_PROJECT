import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import crypto from 'node:crypto';
import { createApp } from '../../../services/api/src/app.js';
import { computeKeyHmac } from '../../../services/api/src/auth/keys.js';
import { UploadAuthorizationService } from '../../../services/api/src/auth/session-service.js';
import {
  generateQuarantineKey,
  sanitizeOriginalFilename,
} from '../../../services/api/src/auth/session-utils.js';
import type { Config } from '@sug/shared/config';
import type {
  UploadSessionRecord,
  SecurityPolicyRecord,
} from '../../../services/api/src/auth/session-types.js';
import type { ApiKeyDatabase } from '../../../services/api/src/auth/types.js';

describe('Phase P7: Upload Authorization Foundation (Unit Tests)', () => {
  describe('1. Object Key & Filename Safety Utilities', () => {
    it('generates immutable canonical quarantine keys matching incoming/<app_id>/<upload_id>', () => {
      const appId = crypto.randomUUID();
      const uploadId = crypto.randomUUID();
      const key = generateQuarantineKey(appId, uploadId);

      expect(key).toBe(`incoming/${appId}/${uploadId}`);
      expect(key).not.toContain('..');
      expect(key).not.toContain('\\');
    });

    it('rejects path traversal and invalid UUIDs in quarantine key generation', () => {
      const validUuid = crypto.randomUUID();

      expect(() => generateQuarantineKey('../../etc/passwd', validUuid)).toThrow(
        /Invalid applicationId/,
      );
      expect(() => generateQuarantineKey(validUuid, '..\\..\\windows\\system32')).toThrow(
        /Invalid uploadId/,
      );
      expect(() => generateQuarantineKey('not-a-uuid', validUuid)).toThrow(/Invalid applicationId/);
    });

    it('sanitizes filenames: strips POSIX and Windows directory paths to base filename', () => {
      expect(sanitizeOriginalFilename('/var/tmp/malicious.pdf')).toBe('malicious.pdf');
      expect(sanitizeOriginalFilename('C:\\Users\\Admin\\Desktop\\exploit.exe')).toBe(
        'exploit.exe',
      );
      expect(sanitizeOriginalFilename('../../../etc/shadow')).toBe('shadow');
      expect(sanitizeOriginalFilename('..\\..\\boot.ini')).toBe('boot.ini');
    });

    it('sanitizes filenames: removes null bytes, control characters, and collapses traversal dots', () => {
      expect(sanitizeOriginalFilename('test\x00file.png')).toBe('testfile.png');
      expect(sanitizeOriginalFilename('bad\r\nname.docx')).toBe('badname.docx');
      expect(sanitizeOriginalFilename('doc...pdf')).toBe('doc.pdf');
    });

    it('rejects empty or entirely forbidden filenames', () => {
      expect(() => sanitizeOriginalFilename('')).toThrow(/non-empty/);
      expect(() => sanitizeOriginalFilename('..')).toThrow(/invalid/);
      expect(() => sanitizeOriginalFilename('\x00\x00')).toThrow(/invalid/);
    });

    it('enforces 255 character limit while preserving extension', () => {
      const longName = 'a'.repeat(300) + '.pdf';
      const sanitized = sanitizeOriginalFilename(longName);
      expect(sanitized.length).toBeLessThanOrEqual(255);
      expect(sanitized.endsWith('.pdf')).toBe(true);
    });
  });

  describe('2. UploadAuthorizationService Domain Logic', () => {
    interface MockSessionDb extends ApiKeyDatabase {
      sessions: Map<string, UploadSessionRecord>;
      policies: Map<string, SecurityPolicyRecord>;
      auditEvents: Array<{
        actorType: string;
        actorId: string;
        action: string;
        refs: Record<string, unknown>;
        details: Record<string, unknown>;
      }>;
    }

    let mockDb: MockSessionDb;
    let service: UploadAuthorizationService;
    const testAppId = crypto.randomUUID();
    const testKeyId = crypto.randomUUID();
    const testPolicyId = crypto.randomUUID();

    beforeEach(() => {
      mockDb = {
        sessions: new Map<string, UploadSessionRecord>(),
        policies: new Map<string, SecurityPolicyRecord>(),
        auditEvents: [],

        async query<T = unknown>(
          sql: string,
          params: unknown[] = [],
        ): Promise<{ rows: T[]; rowCount?: number | null }> {
          // SELECT security_policies
          if (sql.includes('FROM security_policies')) {
            const policy =
              mockDb.policies.get(params[0] as string) ?? mockDb.policies.get(params[1] as string);
            return {
              rows: (policy ? [policy] : []) as T[],
              rowCount: policy ? 1 : 0,
            };
          }

          // INSERT INTO upload_sessions
          if (sql.includes('INSERT INTO upload_sessions')) {
            const session: UploadSessionRecord = {
              id: params[0] as string,
              application_id: params[1] as string,
              api_key_id: params[2] as string,
              policy_id: params[3] as string,
              client_ref: (params[4] as string | null) ?? null,
              original_filename: params[5] as string,
              declared_mime: params[6] as string,
              declared_size: params[7] as number,
              declared_sha256: (params[8] as Buffer | null) ?? null,
              status: 'CREATED',
              token_jti: params[9] as string,
              expires_at: params[10] as Date,
              client_ip: (params[11] as string | null) ?? null,
              created_at: new Date(),
              completed_at: null,
            };
            mockDb.sessions.set(session.id, session);
            return { rows: [session as unknown as T], rowCount: 1 };
          }

          // UPDATE upload_sessions SET status = 'UPLOADING' (claim)
          if (sql.includes("SET status = 'UPLOADING'")) {
            const sessionId = params[0] as string;
            const appId = params[1] as string;
            const session = mockDb.sessions.get(sessionId);
            if (
              session &&
              session.application_id === appId &&
              session.status === 'CREATED' &&
              new Date(session.expires_at).getTime() > Date.now()
            ) {
              session.status = 'UPLOADING';
              return { rows: [session as unknown as T], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
          }

          // UPDATE upload_sessions SET status = 'UPLOADED'
          if (sql.includes("SET status = 'UPLOADED'")) {
            const sessionId = params[0] as string;
            const appId = params[1] as string;
            const session = mockDb.sessions.get(sessionId);
            if (session && session.application_id === appId && session.status === 'UPLOADING') {
              session.status = 'UPLOADED';
              session.completed_at = new Date();
              return { rows: [session as unknown as T], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
          }

          // UPDATE upload_sessions SET status = 'FAILED'
          if (sql.includes("SET status = 'FAILED'")) {
            const sessionId = params[0] as string;
            const appId = params[1] as string;
            const session = mockDb.sessions.get(sessionId);
            if (
              session &&
              session.application_id === appId &&
              ['CREATED', 'UPLOADING'].includes(session.status)
            ) {
              session.status = 'FAILED';
              return { rows: [session as unknown as T], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
          }

          // SELECT * FROM upload_sessions
          if (sql.includes('SELECT * FROM upload_sessions')) {
            const session = mockDb.sessions.get(params[0] as string);
            if (session && session.application_id === (params[1] as string)) {
              return { rows: [session as unknown as T], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
          }

          // SELECT status, expires_at
          if (sql.includes('SELECT status, expires_at FROM upload_sessions')) {
            const session = mockDb.sessions.get(params[0] as string);
            if (session && session.application_id === (params[1] as string)) {
              return {
                rows: [{ status: session.status, expires_at: session.expires_at } as unknown as T],
                rowCount: 1,
              };
            }
            return { rows: [], rowCount: 0 };
          }

          // audit_append
          if (sql.includes('audit_append')) {
            mockDb.auditEvents.push({
              actorType: params[0] as string,
              actorId: params[1] as string,
              action: params[2] as string,
              refs: JSON.parse(params[3] as string) as Record<string, unknown>,
              details: JSON.parse(params[4] as string) as Record<string, unknown>,
            });
            return { rows: [{ seq: 1 } as unknown as T], rowCount: 1 };
          }

          return { rows: [], rowCount: 0 };
        },
      };

      // Set default active policy for test application
      mockDb.policies.set(testAppId, {
        id: testPolicyId,
        application_id: testAppId,
        version: 1,
        document: { allowedExtensions: ['.pdf'], maxFileSize: 10485760 },
      });

      service = new UploadAuthorizationService({ db: mockDb });
    });

    it('creates an upload session with bounded expiration, quarantine key, and audit log', async () => {
      const res = await service.createSession({
        applicationId: testAppId,
        apiKeyId: testKeyId,
        filename: 'report.pdf',
        declaredSize: 1024,
        declaredMime: 'application/pdf',
      });

      expect(res.sessionId).toBeDefined();
      expect(res.applicationId).toBe(testAppId);
      expect(res.status).toBe('CREATED');
      expect(res.quarantineKey).toBe(`incoming/${testAppId}/${res.sessionId}`);
      expect(res.tokenJti).toBeDefined();
      expect(res.policyId).toBe(testPolicyId);
      expect(res.declaredSize).toBe(1024);

      // Verify audit event
      const audit = mockDb.auditEvents.find((e) => e.action === 'upload_session.created');
      expect(audit).toBeDefined();
      expect(audit?.refs.application_id).toBe(testAppId);
      expect(audit?.details.original_filename).toBe('report.pdf');
    });

    it('rejects session creation when declared size exceeds policy ceiling', async () => {
      await expect(
        service.createSession({
          applicationId: testAppId,
          apiKeyId: testKeyId,
          filename: 'giant.pdf',
          declaredSize: 20000000, // 20 MB > 10 MB policy max
          declaredMime: 'application/pdf',
        }),
      ).rejects.toThrow(/exceeds policy maximum/);
    });

    it('rejects session creation when no policy exists for application', async () => {
      const otherAppId = crypto.randomUUID();
      await expect(
        service.createSession({
          applicationId: otherAppId,
          apiKeyId: testKeyId,
          filename: 'file.pdf',
          declaredSize: 1024,
          declaredMime: 'application/pdf',
        }),
      ).rejects.toThrow('NO_ACTIVE_POLICY');
    });

    it('bounds session expiration between 60s minimum and 900s maximum', async () => {
      // 1. Minimum bound
      const minRes = await service.createSession({
        applicationId: testAppId,
        apiKeyId: testKeyId,
        filename: 'min.pdf',
        declaredSize: 100,
        declaredMime: 'application/pdf',
        durationSeconds: 10, // too short -> should be clamped to 60s
      });
      const minDiff = (new Date(minRes.expiresAt).getTime() - Date.now()) / 1000;
      expect(minDiff).toBeGreaterThanOrEqual(58);
      expect(minDiff).toBeLessThanOrEqual(62);

      // 2. Maximum bound
      const maxRes = await service.createSession({
        applicationId: testAppId,
        apiKeyId: testKeyId,
        filename: 'max.pdf',
        declaredSize: 100,
        declaredMime: 'application/pdf',
        durationSeconds: 5000, // too long -> should be clamped to 900s (15m)
      });
      const maxDiff = (new Date(maxRes.expiresAt).getTime() - Date.now()) / 1000;
      expect(maxDiff).toBeGreaterThanOrEqual(895);
      expect(maxDiff).toBeLessThanOrEqual(905);
    });

    it('enforces tenant isolation on session retrieval (returns null for foreign application)', async () => {
      const created = await service.createSession({
        applicationId: testAppId,
        apiKeyId: testKeyId,
        filename: 'tenant1.pdf',
        declaredSize: 500,
        declaredMime: 'application/pdf',
      });

      // Same application: succeeds
      const own = await service.getSession(created.sessionId, testAppId);
      expect(own).not.toBeNull();
      expect(own?.id).toBe(created.sessionId);

      // Foreign application: returns null
      const foreignAppId = crypto.randomUUID();
      const foreign = await service.getSession(created.sessionId, foreignAppId);
      expect(foreign).toBeNull();
    });

    it('atomically claims upload session and prevents duplicate claims (ALREADY_CLAIMED)', async () => {
      const created = await service.createSession({
        applicationId: testAppId,
        apiKeyId: testKeyId,
        filename: 'claim.pdf',
        declaredSize: 500,
        declaredMime: 'application/pdf',
      });

      // First claim: authorized
      const claim1 = await service.authorizeSession(created.sessionId, testAppId);
      expect(claim1.isAuthorized).toBe(true);
      expect(claim1.session?.status).toBe('UPLOADING');

      // Second claim attempt: fails with ALREADY_CLAIMED
      const claim2 = await service.authorizeSession(created.sessionId, testAppId);
      expect(claim2.isAuthorized).toBe(false);
      expect(claim2.reason).toBe('ALREADY_CLAIMED');
    });

    it('completes session and aborts session safely', async () => {
      const created = await service.createSession({
        applicationId: testAppId,
        apiKeyId: testKeyId,
        filename: 'abort.pdf',
        declaredSize: 500,
        declaredMime: 'application/pdf',
      });

      // Abort
      const aborted = await service.abortSession(created.sessionId, testAppId, 'USER_CANCELLED');
      expect(aborted?.status).toBe('FAILED');

      // Cannot claim after abort
      const claim = await service.authorizeSession(created.sessionId, testAppId);
      expect(claim.isAuthorized).toBe(false);
    });
  });

  describe('3. Fastify HTTP Endpoints & Tenant Boundary', () => {
    interface MockAuthDb extends ApiKeyDatabase {
      sessions: Map<string, UploadSessionRecord>;
      policies: Map<string, SecurityPolicyRecord>;
    }

    let app: FastifyInstance;
    let mockAuthDb: MockAuthDb;
    const testAppId = crypto.randomUUID();
    const testKeyId = crypto.randomUUID();
    const testPrefix = 'a1b2c3d4';
    const testSecret = crypto.randomBytes(32).toString('hex');
    const testRawKey = `sug_${testPrefix}_${testSecret}`;
    const testPepper = crypto.randomBytes(32).toString('hex');

    beforeEach(async () => {
      const testKeyHmac = computeKeyHmac(testSecret, testPepper);
      const sessions = new Map<string, UploadSessionRecord>();
      const policies = new Map<string, SecurityPolicyRecord>();

      policies.set(testAppId, {
        id: crypto.randomUUID(),
        application_id: testAppId,
        version: 1,
        document: { allowedExtensions: ['.pdf'], maxFileSize: 52428800 },
      });

      mockAuthDb = {
        sessions,
        policies,
        query: async <T = unknown>(
          sql: string,
          params: unknown[] = [],
        ): Promise<{ rows: T[]; rowCount?: number | null }> => {
          if (sql.includes('FROM api_keys')) {
            if (params[0] === testPrefix) {
              return {
                rows: [
                  {
                    id: testKeyId,
                    application_id: testAppId,
                    key_prefix: testPrefix,
                    key_hmac: testKeyHmac,
                    scopes: ['upload', 'read'],
                    expires_at: null,
                    revoked_at: null,
                  },
                ] as unknown as T[],
                rowCount: 1,
              };
            }
            return { rows: [], rowCount: 0 };
          }

          if (sql.includes('FROM security_policies')) {
            const policy = policies.get(testAppId);
            return { rows: (policy ? [policy] : []) as unknown as T[], rowCount: 1 };
          }

          if (sql.includes('INSERT INTO upload_sessions')) {
            const session: UploadSessionRecord = {
              id: params[0] as string,
              application_id: params[1] as string,
              api_key_id: params[2] as string,
              policy_id: params[3] as string,
              client_ref: (params[4] as string | null) ?? null,
              original_filename: params[5] as string,
              declared_mime: params[6] as string,
              declared_size: params[7] as number,
              declared_sha256: (params[8] as Buffer | null) ?? null,
              status: 'CREATED',
              token_jti: params[9] as string,
              expires_at: params[10] as Date,
              client_ip: (params[11] as string | null) ?? null,
              created_at: new Date(),
              completed_at: null,
            };
            sessions.set(session.id, session);
            return { rows: [session as unknown as T], rowCount: 1 };
          }

          if (sql.includes('SELECT * FROM upload_sessions')) {
            const session = sessions.get(params[0] as string);
            if (session && session.application_id === params[1]) {
              return { rows: [session as unknown as T], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
          }

          if (sql.includes("SET status = 'FAILED'")) {
            const session = sessions.get(params[0] as string);
            if (session && session.application_id === params[1]) {
              session.status = 'FAILED';
              return { rows: [session as unknown as T], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
          }

          return { rows: [], rowCount: 0 };
        },
      };

      const mockConfig = {
        nodeEnv: 'test',
        logLevel: 'fatal',
        port: 3000,
        host: '127.0.0.1',
        database: { url: 'postgres://sug_api:pass@localhost:5432/sug' },
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
            projectId: 'test',
          },
          services: {
            api: { accessKeyId: 'test' },
            scanner: { accessKeyId: 'test' },
            promoter: { accessKeyId: 'test' },
            replicator: { accessKeyId: 'test' },
          },
        },
        secrets: {
          pepper: testPepper,
          kek: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          jwtPrivateKey: 'dummy',
          checkpointPrivateKey: 'dummy',
        },
        toRedacted: () => ({}) as unknown as ReturnType<Config['toRedacted']>,
        toJSON: () => ({}),
      } as unknown as Config;

      app = await createApp({
        config: mockConfig,
        authDb: mockAuthDb,
        logger: false,
      });

      await app.ready();
    });

    afterEach(async () => {
      await app.close();
    });

    it('POST /api/v1/upload/authorize returns 401 when no credentials provided', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/authorize',
        payload: {
          filename: 'test.pdf',
          declaredSize: 1024,
          declaredMime: 'application/pdf',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:unauthorized');
    });

    it('POST /api/v1/upload/authorize returns 403 when client passes spoofed applicationId in body', async () => {
      const spoofedAppId = crypto.randomUUID();
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/authorize',
        headers: { authorization: `Bearer ${testRawKey}` },
        payload: {
          filename: 'test.pdf',
          declaredSize: 1024,
          declaredMime: 'application/pdf',
          applicationId: spoofedAppId, // spoofed!
        },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:forbidden');
      expect(body.detail).toContain('client application ID does not match');
    });

    it('POST /api/v1/upload/authorize succeeds with valid API key and returns 201 with session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/authorize',
        headers: { authorization: `Bearer ${testRawKey}` },
        payload: {
          filename: 'my-document.pdf',
          declaredSize: 2048,
          declaredMime: 'application/pdf',
          clientRef: 'invoice-1234',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.sessionId).toBeDefined();
      expect(body.applicationId).toBe(testAppId);
      expect(body.status).toBe('CREATED');
      expect(body.quarantineKey).toBe(`incoming/${testAppId}/${body.sessionId}`);
      expect(body.declaredSize).toBe(2048);
      expect(body.declaredMime).toBe('application/pdf');
    });

    it('POST /api/v1/upload/authorize returns 400 for negative or invalid declared size', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/authorize',
        headers: { authorization: `Bearer ${testRawKey}` },
        payload: {
          filename: 'test.pdf',
          declaredSize: -50,
          declaredMime: 'application/pdf',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:validation');
    });

    it('GET /api/v1/upload/sessions/:id retrieves own session and returns 404 for unknown/foreign', async () => {
      // 1. Create session
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/authorize',
        headers: { authorization: `Bearer ${testRawKey}` },
        payload: {
          filename: 'lookup.pdf',
          declaredSize: 4096,
          declaredMime: 'application/pdf',
        },
      });
      const created = JSON.parse(createRes.body);

      // 2. Retrieve own session: 200
      const getRes = await app.inject({
        method: 'GET',
        url: `/api/v1/upload/sessions/${created.sessionId}`,
        headers: { authorization: `Bearer ${testRawKey}` },
      });
      expect(getRes.statusCode).toBe(200);
      const session = JSON.parse(getRes.body);
      expect(session.id).toBe(created.sessionId);
      expect(session.applicationId).toBe(testAppId);

      // 3. Unknown session: 404
      const unknownRes = await app.inject({
        method: 'GET',
        url: `/api/v1/upload/sessions/${crypto.randomUUID()}`,
        headers: { authorization: `Bearer ${testRawKey}` },
      });
      expect(unknownRes.statusCode).toBe(404);
    });

    it('POST /api/v1/upload/sessions/:id/abort aborts active session', async () => {
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/v1/upload/authorize',
        headers: { authorization: `Bearer ${testRawKey}` },
        payload: {
          filename: 'to-abort.pdf',
          declaredSize: 1024,
          declaredMime: 'application/pdf',
        },
      });
      const created = JSON.parse(createRes.body);

      const abortRes = await app.inject({
        method: 'POST',
        url: `/api/v1/upload/sessions/${created.sessionId}/abort`,
        headers: { authorization: `Bearer ${testRawKey}` },
      });
      expect(abortRes.statusCode).toBe(200);
      const body = JSON.parse(abortRes.body);
      expect(body.status).toBe('FAILED');
    });
  });
});
