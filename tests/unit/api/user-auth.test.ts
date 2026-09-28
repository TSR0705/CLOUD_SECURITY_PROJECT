import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import * as jose from 'jose';
import { createApp } from '../../../services/api/src/app.js';
import {
  hashPassword,
  verifyPassword,
  dummyVerifyPassword,
} from '../../../services/api/src/auth/password.js';
import {
  createDashboardToken,
  verifyDashboardToken,
  derivePublicKeyPem,
  JWT_AUDIENCE,
  JWT_ISSUER,
} from '../../../services/api/src/auth/jwt.js';
import { UserService } from '../../../services/api/src/auth/user-service.js';
import type {
  UserRecord,
  RefreshTokenRecord,
  SafeUser,
} from '../../../services/api/src/auth/user-types.js';
import type { ApiKeyDatabase } from '../../../services/api/src/auth/types.js';
import type { Config } from '@sug/shared/config';
import { REFRESH_COOKIE_NAME } from '../../../services/api/src/routes/user-auth.js';

describe('Phase P7: Users, JWT and RBAC (Unit Tests)', () => {
  let privateKeyPem: string;
  let publicKeyPem: string;

  beforeEach(() => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    privateKeyPem = privateKey;
    publicKeyPem = derivePublicKeyPem(privateKeyPem);
  });

  describe('1. Argon2id Password Security', () => {
    it('hashes passwords using Argon2id with OWASP parameters', async () => {
      const hash = await hashPassword('SuperSecretPassword123!');
      expect(hash).toMatch(/^\$argon2id\$v=19\$m=65536,p=4,t=3\$/);
      expect(hash).not.toContain('SuperSecretPassword123!');
    });

    it('verifies valid password against Argon2id hash', async () => {
      const hash = await hashPassword('CorrectPassword#2026');
      const isValid = await verifyPassword(hash, 'CorrectPassword#2026');
      expect(isValid).toBe(true);
    });

    it('rejects incorrect password against Argon2id hash', async () => {
      const hash = await hashPassword('CorrectPassword#2026');
      const isValid = await verifyPassword(hash, 'WrongPassword#999');
      expect(isValid).toBe(false);
    });

    it('handles empty or malformed hash and password safely', async () => {
      expect(await verifyPassword('', 'password')).toBe(false);
      expect(await verifyPassword('$argon2id$invalid', 'password')).toBe(false);
      expect(await verifyPassword('hash', '')).toBe(false);
    });

    it('executes dummy verify without throwing for nonexistent users', async () => {
      await expect(dummyVerifyPassword()).resolves.toBeUndefined();
    });
  });

  describe('2. EdDSA Dashboard JWT & RFC 8725 Validation (authz-04)', () => {
    const sampleUser: SafeUser = {
      id: crypto.randomUUID(),
      email: 'analyst@gateway.internal',
      role: 'analyst',
    };

    it('issues and verifies a valid EdDSA JWT access token', async () => {
      const token = await createDashboardToken(sampleUser, privateKeyPem, 900);
      expect(typeof token).toBe('string');

      const payload = await verifyDashboardToken(token, publicKeyPem);
      expect(payload.sub).toBe(sampleUser.id);
      expect(payload.email).toBe(sampleUser.email);
      expect(payload.role).toBe('analyst');
      expect(payload.aud).toBe(JWT_AUDIENCE);
      expect(payload.iss).toBe(JWT_ISSUER);
      expect(payload.typ).toBe('JWT');
    });

    it('authz-04: rejects JWT signed with algorithm "none"', async () => {
      // Unsigned token with alg: none
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(
        JSON.stringify({
          sub: sampleUser.id,
          email: sampleUser.email,
          role: 'admin',
          aud: JWT_AUDIENCE,
          iss: JWT_ISSUER,
          exp: Math.floor(Date.now() / 1000) + 900,
        }),
      ).toString('base64url');
      const noneToken = `${header}.${payload}.`;

      await expect(verifyDashboardToken(noneToken, publicKeyPem)).rejects.toThrow(
        /Algorithm 'none' is not permitted/,
      );
    });

    it('authz-04: rejects algorithm confusion attack (HS256 downgrade)', async () => {
      // HMAC signed token using public key as secret
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString(
        'base64url',
      );
      const payload = Buffer.from(
        JSON.stringify({
          sub: sampleUser.id,
          email: sampleUser.email,
          role: 'admin',
          aud: JWT_AUDIENCE,
          iss: JWT_ISSUER,
          exp: Math.floor(Date.now() / 1000) + 900,
        }),
      ).toString('base64url');
      const hmacSig = crypto
        .createHmac('sha256', publicKeyPem)
        .update(`${header}.${payload}`)
        .digest('base64url');
      const hs256Token = `${header}.${payload}.${hmacSig}`;

      await expect(verifyDashboardToken(hs256Token, publicKeyPem)).rejects.toThrow(
        /Algorithm 'HS256' is not permitted/,
      );
    });

    it('rejects token with wrong audience (e.g. "sug-upload" or "sug-api")', async () => {
      const wrongAudToken = await new jose.SignJWT({ role: 'admin', email: 'test@internal' })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
        .setIssuer(JWT_ISSUER)
        .setAudience('sug-upload') // Wrong audience!
        .setSubject(sampleUser.id)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(await jose.importPKCS8(privateKeyPem, 'EdDSA'));

      await expect(verifyDashboardToken(wrongAudToken, publicKeyPem)).rejects.toThrow(
        /unexpected "aud" claim value/,
      );
    });

    it('rejects token with wrong issuer', async () => {
      const wrongIssToken = await new jose.SignJWT({ role: 'admin', email: 'test@internal' })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
        .setIssuer('evil-issuer')
        .setAudience(JWT_AUDIENCE)
        .setSubject(sampleUser.id)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(await jose.importPKCS8(privateKeyPem, 'EdDSA'));

      await expect(verifyDashboardToken(wrongIssToken, publicKeyPem)).rejects.toThrow(
        /unexpected "iss" claim value/,
      );
    });

    it('rejects expired JWT token', async () => {
      const expiredToken = await new jose.SignJWT({ role: 'admin', email: 'test@internal' })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
        .setIssuer(JWT_ISSUER)
        .setAudience(JWT_AUDIENCE)
        .setSubject(sampleUser.id)
        .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
        .setExpirationTime(Math.floor(Date.now() / 1000) - 1800) // Expired 30 mins ago
        .sign(await jose.importPKCS8(privateKeyPem, 'EdDSA'));

      await expect(verifyDashboardToken(expiredToken, publicKeyPem)).rejects.toThrow(
        /"exp" claim timestamp check failed/,
      );
    });

    it('rejects forged JWT signed with an unrelated Ed25519 key', async () => {
      const { privateKey: attackerPrivateKey } = crypto.generateKeyPairSync('ed25519', {
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      const forgedToken = await createDashboardToken(sampleUser, attackerPrivateKey);

      await expect(verifyDashboardToken(forgedToken, publicKeyPem)).rejects.toThrow(
        /signature verification failed/,
      );
    });

    it('rejects token with unrecognized or tampered role claim', async () => {
      const tamperedRoleToken = await new jose.SignJWT({
        role: 'super_root',
        email: 'test@internal',
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
        .setIssuer(JWT_ISSUER)
        .setAudience(JWT_AUDIENCE)
        .setSubject(sampleUser.id)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(await jose.importPKCS8(privateKeyPem, 'EdDSA'));

      await expect(verifyDashboardToken(tamperedRoleToken, publicKeyPem)).rejects.toThrow(
        /not a recognized dashboard role/,
      );
    });
  });

  describe('3. UserService: Auth, 5-Attempt Lockout, and Refresh Rotation', () => {
    interface MockUserDb extends ApiKeyDatabase {
      users: Map<string, UserRecord>;
      refreshTokens: Map<string, RefreshTokenRecord>;
      auditEvents: Array<Record<string, unknown>>;
    }

    let mockDb: MockUserDb;
    let userService: UserService;
    const testUserId = crypto.randomUUID();
    const testPassword = 'Password123!';
    let validPasswordHash: string;

    beforeEach(async () => {
      validPasswordHash = await hashPassword(testPassword);
      const users = new Map<string, UserRecord>();
      const refreshTokens = new Map<string, RefreshTokenRecord>();
      const auditEvents: Array<Record<string, unknown>> = [];

      users.set('analyst@gateway.internal', {
        id: testUserId,
        email: 'analyst@gateway.internal',
        password_hash: validPasswordHash,
        role: 'analyst',
        is_active: true,
        failed_logins: 0,
        locked_until: null,
        created_at: new Date(),
        last_login_at: null,
      });

      mockDb = {
        users,
        refreshTokens,
        auditEvents,
        query: async <T = unknown>(
          sql: string,
          params: unknown[] = [],
        ): Promise<{ rows: T[]; rowCount?: number | null }> => {
          // SELECT users WHERE email = $1
          if (sql.includes('FROM users WHERE email = $1')) {
            const email = (params[0] as string).toLowerCase();
            const user = users.get(email);
            return { rows: (user ? [user] : []) as T[], rowCount: user ? 1 : 0 };
          }

          // SELECT users WHERE id = $1
          if (sql.includes('FROM users WHERE id = $1')) {
            const id = params[0] as string;
            const user = Array.from(users.values()).find((u) => u.id === id);
            return { rows: (user ? [user] : []) as T[], rowCount: user ? 1 : 0 };
          }

          // UPDATE users SET failed_logins = ...
          if (sql.includes('UPDATE users SET failed_logins = $1, locked_until')) {
            const fails = params[0] as number;
            const id = params[1] as string;
            const user = Array.from(users.values()).find((u) => u.id === id);
            if (user) {
              user.failed_logins = fails;
              user.locked_until = new Date(Date.now() + 15 * 60 * 1000);
            }
            return { rows: [], rowCount: 1 };
          }

          if (sql.includes('UPDATE users SET failed_logins = $1 WHERE id = $2')) {
            const fails = params[0] as number;
            const id = params[1] as string;
            const user = Array.from(users.values()).find((u) => u.id === id);
            if (user) {
              user.failed_logins = fails;
            }
            return { rows: [], rowCount: 1 };
          }

          // UPDATE users SET failed_logins = 0 (reset on success)
          if (sql.includes('UPDATE users SET failed_logins = 0')) {
            const id = params[0] as string;
            const user = Array.from(users.values()).find((u) => u.id === id);
            if (user) {
              user.failed_logins = 0;
              user.locked_until = null;
              user.last_login_at = new Date();
            }
            return { rows: [], rowCount: 1 };
          }

          // INSERT INTO refresh_tokens
          if (sql.includes('INSERT INTO refresh_tokens')) {
            const newId = crypto.randomUUID();
            const row: RefreshTokenRecord = {
              id: newId,
              user_id: params[0] as string,
              token_hash: params[1] as Buffer,
              expires_at: params[2] as Date,
              revoked_at: null,
              replaced_by: null,
            };
            refreshTokens.set(row.token_hash.toString('hex'), row);
            return { rows: [{ id: newId } as unknown as T], rowCount: 1 };
          }

          // SELECT refresh_tokens WHERE token_hash = $1
          if (sql.includes('FROM refresh_tokens WHERE token_hash = $1')) {
            const hash = (params[0] as Buffer).toString('hex');
            const row = refreshTokens.get(hash);
            return { rows: (row ? [row] : []) as T[], rowCount: row ? 1 : 0 };
          }

          // UPDATE refresh_tokens SET replaced_by = $1, revoked_at = now() WHERE id = $2
          if (sql.includes('SET replaced_by = $1, revoked_at = now()')) {
            const replacedBy = params[0] as string;
            const id = params[1] as string;
            const row = Array.from(refreshTokens.values()).find((r) => r.id === id);
            if (row) {
              row.replaced_by = replacedBy;
              row.revoked_at = new Date();
            }
            return { rows: [], rowCount: 1 };
          }

          // UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 (invalidate all on replay)
          if (sql.includes('UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1')) {
            const userId = params[0] as string;
            for (const r of refreshTokens.values()) {
              if (r.user_id === userId && !r.revoked_at) {
                r.revoked_at = new Date();
              }
            }
            return { rows: [], rowCount: 1 };
          }

          // UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 (logout)
          if (sql.includes('UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1')) {
            const hash = (params[0] as Buffer).toString('hex');
            const row = refreshTokens.get(hash);
            if (row) {
              row.revoked_at = new Date();
              return { rows: [row as unknown as T], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
          }

          // audit_append
          if (sql.includes('audit_append')) {
            auditEvents.push({
              actorType: params[0],
              actorId: params[1],
              action: params[2],
              refs: JSON.parse(params[3] as string),
              details: JSON.parse(params[4] as string),
            });
            return { rows: [{ seq: 1 } as unknown as T], rowCount: 1 };
          }

          return { rows: [], rowCount: 0 };
        },
      };

      userService = new UserService({ db: mockDb });
    });

    it('authenticates user with valid credentials and resets failed_logins', async () => {
      const res = await userService.authenticate('analyst@gateway.internal', testPassword);
      expect(res.success).toBe(true);
      expect(res.user?.id).toBe(testUserId);
      expect(res.user?.role).toBe('analyst');

      const user = mockDb.users.get('analyst@gateway.internal');
      expect(user?.failed_logins).toBe(0);
      expect(user?.locked_until).toBeNull();
      expect(user?.last_login_at).toBeDefined();

      const audit = mockDb.auditEvents.find((e) => e.action === 'user.login_success');
      expect(audit).toBeDefined();
    });

    it('rejects wrong password and increments failed_logins', async () => {
      const res = await userService.authenticate('analyst@gateway.internal', 'BadPassword');
      expect(res.success).toBe(false);
      expect(res.reason).toBe('INVALID_CREDENTIALS');

      const user = mockDb.users.get('analyst@gateway.internal');
      expect(user?.failed_logins).toBe(1);

      const audit = mockDb.auditEvents.find((e) => e.action === 'user.login_failure');
      expect(audit).toBeDefined();
    });

    it('five-attempt lockout: locks account on 5th consecutive failure', async () => {
      // 1st to 4th failures
      for (let i = 1; i <= 4; i++) {
        const attempt = await userService.authenticate('analyst@gateway.internal', 'WrongPass');
        expect(attempt.success).toBe(false);
        expect(attempt.locked).toBeFalsy();
      }

      // 5th failure: triggers account lockout
      const fifthAttempt = await userService.authenticate('analyst@gateway.internal', 'WrongPass');
      expect(fifthAttempt.success).toBe(false);
      expect(fifthAttempt.locked).toBe(true);
      expect(fifthAttempt.reason).toBe('ACCOUNT_LOCKED');

      const user = mockDb.users.get('analyst@gateway.internal');
      expect(user?.failed_logins).toBe(5);
      expect(user?.locked_until).toBeDefined();
      expect(new Date(user!.locked_until!).getTime()).toBeGreaterThan(Date.now());

      const lockAudit = mockDb.auditEvents.find((e) => e.action === 'user.locked_out');
      expect(lockAudit).toBeDefined();

      // Subsequent attempt while locked is rejected immediately
      const lockedAttempt = await userService.authenticate(
        'analyst@gateway.internal',
        testPassword,
      );
      expect(lockedAttempt.success).toBe(false);
      expect(lockedAttempt.locked).toBe(true);
      expect(lockedAttempt.reason).toBe('ACCOUNT_LOCKED');
    });

    it('returns generic failure for nonexistent user without enumeration leak', async () => {
      const res = await userService.authenticate('nonexistent@gateway.internal', 'SomePassword');
      expect(res.success).toBe(false);
      expect(res.reason).toBe('INVALID_CREDENTIALS');
    });

    it('rotates refresh token: creates new token and marks old token replaced', async () => {
      const { rawToken } = await userService.createRefreshToken(testUserId);
      expect(typeof rawToken).toBe('string');

      const rotateRes = await userService.rotateRefreshToken(rawToken);
      expect(rotateRes.success).toBe(true);
      expect(rotateRes.newRawToken).toBeDefined();
      expect(rotateRes.newRawToken).not.toBe(rawToken);
      expect(rotateRes.user?.id).toBe(testUserId);

      // Verify old token is now replaced and revoked
      const oldHash = crypto.createHash('sha256').update(rawToken).digest('hex');
      const oldToken = mockDb.refreshTokens.get(oldHash);
      expect(oldToken?.revoked_at).toBeDefined();
      expect(oldToken?.replaced_by).toBeDefined();
    });

    it('detects refresh token reuse and revokes all user sessions (token theft mitigation)', async () => {
      const { rawToken } = await userService.createRefreshToken(testUserId);

      // Legitimate rotation
      const rotateRes1 = await userService.rotateRefreshToken(rawToken);
      expect(rotateRes1.success).toBe(true);

      // Attacker attempts to replay the already-rotated token!
      const replayRes = await userService.rotateRefreshToken(rawToken);
      expect(replayRes.success).toBe(false);
      expect(replayRes.reuseDetected).toBe(true);
      expect(replayRes.reason).toBe('TOKEN_REUSE_DETECTED');

      // Verify theft mitigation audit event was logged
      const replayAudit = mockDb.auditEvents.find((e) => e.action === 'user.token_replay_detected');
      expect(replayAudit).toBeDefined();

      // Verify that even the legitimate rotated token is now revoked
      const newHash = crypto.createHash('sha256').update(rotateRes1.newRawToken!).digest('hex');
      const secondToken = mockDb.refreshTokens.get(newHash);
      expect(secondToken?.revoked_at).toBeDefined();
    });

    it('revokes refresh token upon logout', async () => {
      const { rawToken } = await userService.createRefreshToken(testUserId);
      const revoked = await userService.revokeRefreshToken(rawToken);
      expect(revoked).toBe(true);

      const hash = crypto.createHash('sha256').update(rawToken).digest('hex');
      const token = mockDb.refreshTokens.get(hash);
      expect(token?.revoked_at).toBeDefined();

      const logoutAudit = mockDb.auditEvents.find((e) => e.action === 'user.logout');
      expect(logoutAudit).toBeDefined();
    });
  });

  describe('4. Fastify Endpoints & RBAC Guards (authz-06)', () => {
    let app: FastifyInstance;
    let mockAuthDb: ApiKeyDatabase;
    const testAdminId = crypto.randomUUID();
    const testAnalystId = crypto.randomUUID();
    const testAuditorId = crypto.randomUUID();
    const defaultPassword = 'DashboardPassword2026!';
    let adminToken: string;
    let analystToken: string;
    let auditorToken: string;

    beforeEach(async () => {
      const passwordHash = await hashPassword(defaultPassword);
      const users = new Map<string, UserRecord>();
      const refreshTokens = new Map<string, RefreshTokenRecord>();

      users.set('admin@gateway.internal', {
        id: testAdminId,
        email: 'admin@gateway.internal',
        password_hash: passwordHash,
        role: 'admin',
        is_active: true,
        failed_logins: 0,
        locked_until: null,
        created_at: new Date(),
        last_login_at: null,
      });

      users.set('analyst@gateway.internal', {
        id: testAnalystId,
        email: 'analyst@gateway.internal',
        password_hash: passwordHash,
        role: 'analyst',
        is_active: true,
        failed_logins: 0,
        locked_until: null,
        created_at: new Date(),
        last_login_at: null,
      });

      users.set('auditor@gateway.internal', {
        id: testAuditorId,
        email: 'auditor@gateway.internal',
        password_hash: passwordHash,
        role: 'auditor',
        is_active: true,
        failed_logins: 0,
        locked_until: null,
        created_at: new Date(),
        last_login_at: null,
      });

      mockAuthDb = {
        query: async <T = unknown>(
          sql: string,
          params: unknown[] = [],
        ): Promise<{ rows: T[]; rowCount?: number | null }> => {
          if (sql.includes('FROM users WHERE email = $1')) {
            const email = (params[0] as string).toLowerCase();
            const user = users.get(email);
            return { rows: (user ? [user] : []) as T[], rowCount: user ? 1 : 0 };
          }
          if (sql.includes('FROM users WHERE id = $1')) {
            const id = params[0] as string;
            const user = Array.from(users.values()).find((u) => u.id === id);
            return { rows: (user ? [user] : []) as T[], rowCount: user ? 1 : 0 };
          }
          if (sql.includes('UPDATE users SET failed_logins = 0')) {
            return { rows: [], rowCount: 1 };
          }
          if (sql.includes('INSERT INTO refresh_tokens')) {
            const id = crypto.randomUUID();
            const row: RefreshTokenRecord = {
              id,
              user_id: params[0] as string,
              token_hash: params[1] as Buffer,
              expires_at: params[2] as Date,
              revoked_at: null,
              replaced_by: null,
            };
            refreshTokens.set(row.token_hash.toString('hex'), row);
            return { rows: [{ id } as unknown as T], rowCount: 1 };
          }
          if (sql.includes('FROM refresh_tokens WHERE token_hash = $1')) {
            const hash = (params[0] as Buffer).toString('hex');
            const row = refreshTokens.get(hash);
            return { rows: (row ? [row] : []) as T[], rowCount: row ? 1 : 0 };
          }
          if (sql.includes('SET replaced_by = $1, revoked_at = now()')) {
            const replacedBy = params[0] as string;
            const id = params[1] as string;
            const row = Array.from(refreshTokens.values()).find((r) => r.id === id);
            if (row) {
              row.replaced_by = replacedBy;
              row.revoked_at = new Date();
            }
            return { rows: [], rowCount: 1 };
          }
          if (sql.includes('UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1')) {
            const hash = (params[0] as Buffer).toString('hex');
            const row = refreshTokens.get(hash);
            if (row) {
              row.revoked_at = new Date();
              return { rows: [row as unknown as T], rowCount: 1 };
            }
            return { rows: [], rowCount: 0 };
          }
          if (sql.includes('audit_append')) {
            return { rows: [{ seq: 1 } as unknown as T], rowCount: 1 };
          }
          return { rows: [], rowCount: 0 };
        },
      };

      const mockConfig = {
        nodeEnv: 'test',
        logLevel: 'fatal',
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
            quarantineBucket: 'sug-quarantine',
            cleanBucket: 'sug-clean',
            accessKeyId: 'test',
          },
          gcs: {
            endpoint: 'http://localhost:4443',
            replicaBucket: 'sug-replica',
            projectId: 'sug-project',
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
          jwtPrivateKey: privateKeyPem,
          checkpointPrivateKey: privateKeyPem,
        },
        toRedacted: () => ({}),
        toJSON: () => ({}),
      } as unknown as Config;

      app = await createApp({
        config: mockConfig,
        authDb: mockAuthDb,
        logger: false,
      });
      await app.ready();

      adminToken = await createDashboardToken(
        { id: testAdminId, email: 'admin@gateway.internal', role: 'admin' },
        privateKeyPem,
      );
      analystToken = await createDashboardToken(
        { id: testAnalystId, email: 'analyst@gateway.internal', role: 'analyst' },
        privateKeyPem,
      );
      auditorToken = await createDashboardToken(
        { id: testAuditorId, email: 'auditor@gateway.internal', role: 'auditor' },
        privateKeyPem,
      );
    });

    afterEach(async () => {
      await app.close();
    });

    it('POST /api/v1/auth/login succeeds and sets HttpOnly cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: {
          email: 'admin@gateway.internal',
          password: defaultPassword,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.body);
      expect(json.accessToken).toBeDefined();
      expect(json.tokenType).toBe('Bearer');
      expect(json.expiresIn).toBe(900);
      expect(json.user.role).toBe('admin');

      // Verify HttpOnly cookie header
      const cookies = res.cookies;
      const refreshCookie = cookies.find((c) => c.name === REFRESH_COOKIE_NAME);
      expect(refreshCookie).toBeDefined();
      expect(refreshCookie?.httpOnly).toBe(true);
      expect(refreshCookie?.sameSite).toBe('Strict');
      expect(refreshCookie?.path).toBe('/api/v1/auth');

      // Invariant: refresh token MUST NOT be returned in JSON body
      expect(json.refreshToken).toBeUndefined();
    });

    it('POST /api/v1/auth/login returns 401 Problem Details for invalid credentials', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: {
          email: 'admin@gateway.internal',
          password: 'WrongPassword!',
        },
      });

      expect(res.statusCode).toBe(401);
      const json = JSON.parse(res.body);
      expect(json.type).toBe('urn:sug:error:unauthorized');
      expect(json.title).toBe('Unauthorized');
      expect(json.detail).toBe('Invalid credentials');
    });

    it('POST /api/v1/auth/refresh rotates cookie and returns new access token', async () => {
      // 1. Initial login to get cookie
      const loginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: {
          email: 'admin@gateway.internal',
          password: defaultPassword,
        },
      });
      const cookieHeader = loginRes.headers['set-cookie'];

      // 2. Call refresh endpoint with cookie
      const refreshRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: {
          cookie: Array.isArray(cookieHeader) ? cookieHeader.join('; ') : cookieHeader,
        },
      });

      expect(refreshRes.statusCode).toBe(200);
      const json = JSON.parse(refreshRes.body);
      expect(json.accessToken).toBeDefined();
      expect(json.expiresIn).toBe(900);

      // Verify cookie was rotated
      const newCookie = refreshRes.cookies.find((c) => c.name === REFRESH_COOKIE_NAME);
      expect(newCookie).toBeDefined();
      expect(newCookie?.value).not.toBe(loginRes.cookies[0]?.value);
    });

    it('GET /api/v1/auth/me returns current user context with valid Bearer token', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: {
          authorization: `Bearer ${analystToken}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.body);
      expect(json.user.id).toBe(testAnalystId);
      expect(json.user.role).toBe('analyst');
    });

    it('authz-06 (Role Denial): admin route allows admin, rejects analyst with 403', async () => {
      // Admin request to admin-only route -> 200 OK
      const adminRes = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/admin-only',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(adminRes.statusCode).toBe(200);

      // Analyst request to admin-only route -> 403 Forbidden
      const analystRes = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/admin-only',
        headers: { authorization: `Bearer ${analystToken}` },
      });
      expect(analystRes.statusCode).toBe(403);
      const json = JSON.parse(analystRes.body);
      expect(json.type).toBe('urn:sug:error:forbidden');
      expect(json.detail).toContain("role 'analyst' is not authorized");
    });

    it('authz-06 (Role Denial): auditor route allows auditor, rejects analyst with 403', async () => {
      // Auditor request to auditor-only route -> 200 OK
      const auditorRes = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/auditor-only',
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      expect(auditorRes.statusCode).toBe(200);

      // Analyst request to auditor-only route -> 403 Forbidden
      const analystRes = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/auditor-only',
        headers: { authorization: `Bearer ${analystToken}` },
      });
      expect(analystRes.statusCode).toBe(403);
    });

    it('rejects protected routes when Authorization header is missing', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
      });
      expect(res.statusCode).toBe(401);
      const json = JSON.parse(res.body);
      expect(json.type).toBe('urn:sug:error:unauthorized');
    });
  });
});
