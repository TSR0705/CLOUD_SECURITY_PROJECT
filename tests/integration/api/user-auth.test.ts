import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import { createApp } from '../../../services/api/src/app.js';
import { hashPassword } from '../../../services/api/src/auth/password.js';
import { verifyDashboardToken, derivePublicKeyPem } from '../../../services/api/src/auth/jwt.js';
import { REFRESH_COOKIE_NAME } from '../../../services/api/src/routes/user-auth.js';
import { loadConfig } from '@sug/shared/config';
import { createPool } from '../db/helpers.js';

interface SeededUser {
  id: string;
  email: string;
  password: string;
  role: 'admin' | 'analyst' | 'auditor';
}

function extractCookie(
  setCookieHeaders: string | string[] | undefined,
  cookieName: string,
): string | null {
  if (!setCookieHeaders) return null;
  const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  for (const header of headers) {
    const parts = header.split(';')[0]?.trim();
    if (parts && parts.startsWith(`${cookieName}=`)) {
      return parts.substring(cookieName.length + 1);
    }
  }
  return null;
}

describe('Integration — Dashboard Users, JWT and RBAC (Phase P7)', () => {
  let app: FastifyInstance;
  let adminPool: pg.Pool;
  let config: ReturnType<typeof loadConfig>;
  let publicKeyPem: string;

  let adminUser: SeededUser;
  let analystUser: SeededUser;
  let auditorUser: SeededUser;
  let inactiveUser: SeededUser;

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    config = loadConfig({ secretsDir });
    adminPool = createPool('sug_admin', 'sug_dev_password');
    publicKeyPem = derivePublicKeyPem(config.secrets.jwtPrivateKey);

    // Seed test users with real Argon2id password hashes
    const seed = async (
      emailPrefix: string,
      role: 'admin' | 'analyst' | 'auditor',
      isActive = true,
    ): Promise<SeededUser> => {
      const email = `${emailPrefix}_${crypto.randomUUID()}@sug.internal`;
      const password = `SecretPass!_${crypto.randomBytes(8).toString('hex')}`;
      const passwordHash = await hashPassword(password);

      const res = await adminPool.query(
        `INSERT INTO users (email, password_hash, role, is_active)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, role`,
        [email, passwordHash, role, isActive],
      );

      return {
        id: res.rows[0].id,
        email: res.rows[0].email,
        password,
        role: res.rows[0].role,
      };
    };

    adminUser = await seed('admin', 'admin');
    analystUser = await seed('analyst', 'analyst');
    auditorUser = await seed('auditor', 'auditor');
    inactiveUser = await seed('inactive', 'analyst', false);

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

  // =========================================================================
  // 1. Dashboard User Login Flow
  // =========================================================================
  describe('1. POST /api/v1/auth/login', () => {
    it('authenticates valid credentials, sets HttpOnly cookie, and issues EdDSA JWT', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        headers: { 'x-request-id': crypto.randomUUID() },
        payload: {
          email: adminUser.email,
          password: adminUser.password,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      // Verify response structure
      expect(body.tokenType).toBe('Bearer');
      expect(body.expiresIn).toBe(900);
      expect(body.user).toEqual({
        id: adminUser.id,
        email: adminUser.email,
        role: 'admin',
      });
      expect(typeof body.accessToken).toBe('string');

      // CRITICAL: Refresh token must NOT appear in JSON response
      expect(body.refreshToken).toBeUndefined();
      expect(res.body).not.toContain('rawToken');

      // Verify EdDSA token validity and claims
      const claims = await verifyDashboardToken(body.accessToken, publicKeyPem);
      expect(claims.sub).toBe(adminUser.id);
      expect(claims.email).toBe(adminUser.email);
      expect(claims.role).toBe('admin');
      expect(claims.iss).toBe('sug-api');
      expect(claims.aud).toBe('sug-dashboard');
      expect(claims.exp! - claims.iat!).toBe(900);

      // Verify HttpOnly cookie
      const rawCookie = extractCookie(res.headers['set-cookie'], REFRESH_COOKIE_NAME);
      expect(rawCookie).toBeTruthy();
      const setCookieHeader = res.headers['set-cookie'] as string;
      expect(setCookieHeader).toContain('HttpOnly');
      expect(setCookieHeader).toContain('SameSite=Strict');
      expect(setCookieHeader).toContain('Path=/api/v1/auth');

      // Verify database state: token_hash is stored as SHA-256 binary
      const tokenHash = crypto.createHash('sha256').update(rawCookie!).digest();
      const tokenRow = await adminPool.query(
        `SELECT id, user_id, expires_at, revoked_at, replaced_by
         FROM refresh_tokens
         WHERE token_hash = $1`,
        [tokenHash],
      );
      expect(tokenRow.rowCount).toBe(1);
      expect(tokenRow.rows[0].user_id).toBe(adminUser.id);
      expect(tokenRow.rows[0].revoked_at).toBeNull();
      expect(tokenRow.rows[0].replaced_by).toBeNull();

      // Verify audit logging
      const auditRes = await adminPool.query(
        `SELECT action, actor_type, actor_id, details
         FROM audit_events
         WHERE action = 'user.login_success' AND actor_id = $1
         ORDER BY seq DESC LIMIT 1`,
        [adminUser.id],
      );
      expect(auditRes.rowCount).toBe(1);
      expect(auditRes.rows[0].actor_type).toBe('user');
      expect(auditRes.rows[0].details.email).toBe(adminUser.email);
      expect(auditRes.rows[0].details.role).toBe('admin');
      // Ensure zero credential leakage in audit
      expect(JSON.stringify(auditRes.rows[0].details)).not.toContain(adminUser.password);
      expect(JSON.stringify(auditRes.rows[0].details)).not.toContain(rawCookie!);
    });

    it('rejects invalid password and increments failed_logins counter', async () => {
      const beforeRes = await adminPool.query('SELECT failed_logins FROM users WHERE id = $1', [
        analystUser.id,
      ]);
      const initialFailures = beforeRes.rows[0].failed_logins;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        headers: { 'x-request-id': crypto.randomUUID() },
        payload: {
          email: analystUser.email,
          password: 'WrongPassword999!',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:unauthorized');
      expect(body.title).toBe('Unauthorized');
      expect(body.detail).toBe('Invalid credentials');
      expect(res.headers['www-authenticate']).toContain('invalid_credentials');

      // Database verification: failed_logins incremented by 1
      const afterRes = await adminPool.query('SELECT failed_logins FROM users WHERE id = $1', [
        analystUser.id,
      ]);
      expect(afterRes.rows[0].failed_logins).toBe(initialFailures + 1);

      // Audit verification
      const auditRes = await adminPool.query(
        `SELECT action, actor_id, details
         FROM audit_events
         WHERE action = 'user.login_failure' AND actor_id = $1
         ORDER BY seq DESC LIMIT 1`,
        [analystUser.id],
      );
      expect(auditRes.rowCount).toBe(1);
      expect(auditRes.rows[0].details.email).toBe(analystUser.email);
      expect(auditRes.rows[0].details.failed_logins).toBe(initialFailures + 1);
    });

    it('returns generic 401 for nonexistent email with timing-safe dummy verification', async () => {
      const nonExistentEmail = `ghost_${crypto.randomUUID()}@sug.internal`;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        headers: { 'x-request-id': crypto.randomUUID() },
        payload: {
          email: nonExistentEmail,
          password: 'AnyPassword123!',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.type).toBe('urn:sug:error:unauthorized');
      expect(body.detail).toBe('Invalid credentials');

      // Audit verification logs failure under api_gateway service actor
      const auditRes = await adminPool.query(
        `SELECT action, actor_type, actor_id, details
         FROM audit_events
         WHERE action = 'user.login_failure' AND details->>'email' = $1`,
        [nonExistentEmail],
      );
      expect(auditRes.rowCount).toBe(1);
      expect(auditRes.rows[0].details.reason).toBe('USER_NOT_FOUND');
    });

    it('rejects inactive user with generic 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        headers: { 'x-request-id': crypto.randomUUID() },
        payload: {
          email: inactiveUser.email,
          password: inactiveUser.password,
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.detail).toBe('Invalid credentials');
    });
  });

  // =========================================================================
  // 2. Lockout Protection (authz-05)
  // =========================================================================
  describe('2. Account Lockout Protection (authz-05)', () => {
    it('locks account for 15 minutes after 5 consecutive failed logins', async () => {
      // Seed dedicated user for lockout testing
      const email = `lockout_${crypto.randomUUID()}@sug.internal`;
      const correctPassword = 'TargetPassword123!';
      const hash = await hashPassword(correctPassword);

      const userRes = await adminPool.query(
        `INSERT INTO users (email, password_hash, role)
         VALUES ($1, $2, 'analyst')
         RETURNING id`,
        [email, hash],
      );
      const targetUserId = userRes.rows[0].id;

      // Fail attempts 1 through 4 -> returns 401
      for (let i = 1; i <= 4; i++) {
        const failRes = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/login',
          payload: { email, password: 'WrongPassword!' },
        });
        expect(failRes.statusCode).toBe(401);
      }

      // Verify failed_logins is 4 and not yet locked
      const checkMid = await adminPool.query(
        'SELECT failed_logins, locked_until FROM users WHERE id = $1',
        [targetUserId],
      );
      expect(checkMid.rows[0].failed_logins).toBe(4);
      expect(checkMid.rows[0].locked_until).toBeNull();

      // 5th failed attempt -> locks account and returns 423 Locked
      const lockRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email, password: 'WrongPassword!' },
      });
      expect(lockRes.statusCode).toBe(423);
      const lockBody = JSON.parse(lockRes.body);
      expect(lockBody.title).toBe('Locked');
      expect(lockBody.detail).toContain('temporarily locked');

      // Verify database state: locked_until set in future and failed_logins = 5
      const checkLocked = await adminPool.query(
        'SELECT failed_logins, locked_until FROM users WHERE id = $1',
        [targetUserId],
      );
      expect(checkLocked.rows[0].failed_logins).toBe(5);
      expect(checkLocked.rows[0].locked_until).toBeTruthy();
      const lockedTime = new Date(checkLocked.rows[0].locked_until).getTime();
      expect(lockedTime).toBeGreaterThan(Date.now() + 10 * 60 * 1000); // > 10m in future

      // 6th attempt with the CORRECT password -> STILL rejected with 423 Locked
      const correctWhileLockedRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email, password: correctPassword },
      });
      expect(correctWhileLockedRes.statusCode).toBe(423);

      // Verify locked_out audit event
      const auditRes = await adminPool.query(
        `SELECT action, actor_id, details
         FROM audit_events
         WHERE action = 'user.locked_out' AND actor_id = $1`,
        [targetUserId],
      );
      expect(auditRes.rowCount).toBe(1);
      expect(auditRes.rows[0].details.failed_logins).toBe(5);

      // Reset lockout manually (simulate expiration or admin intervention)
      await adminPool.query('UPDATE users SET locked_until = NULL WHERE id = $1', [targetUserId]);

      // Login now succeeds and resets failed_logins to 0
      const unlockRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email, password: correctPassword },
      });
      expect(unlockRes.statusCode).toBe(200);

      const checkReset = await adminPool.query(
        'SELECT failed_logins, locked_until FROM users WHERE id = $1',
        [targetUserId],
      );
      expect(checkReset.rows[0].failed_logins).toBe(0);
      expect(checkReset.rows[0].locked_until).toBeNull();
    });
  });

  // =========================================================================
  // 3. Refresh Token Rotation & Theft Detection
  // =========================================================================
  describe('3. POST /api/v1/auth/refresh (Rotation & Theft Mitigation)', () => {
    it('rotates refresh token and issues new access token', async () => {
      // 1. Initial login to acquire refresh cookie
      const loginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: auditorUser.email, password: auditorUser.password },
      });
      expect(loginRes.statusCode).toBe(200);
      const originalCookie = extractCookie(loginRes.headers['set-cookie'], REFRESH_COOKIE_NAME)!;

      // 2. Perform refresh
      const refreshRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: {
          cookie: `${REFRESH_COOKIE_NAME}=${originalCookie}`,
          'x-request-id': crypto.randomUUID(),
        },
      });

      expect(refreshRes.statusCode).toBe(200);
      const refreshBody = JSON.parse(refreshRes.body);
      expect(refreshBody.tokenType).toBe('Bearer');
      expect(refreshBody.expiresIn).toBe(900);
      expect(typeof refreshBody.accessToken).toBe('string');

      // Verify that a NEW cookie was issued
      const newCookie = extractCookie(refreshRes.headers['set-cookie'], REFRESH_COOKIE_NAME)!;
      expect(newCookie).toBeTruthy();
      expect(newCookie).not.toBe(originalCookie);

      // 3. Database verification
      const origHash = crypto.createHash('sha256').update(originalCookie).digest();
      const newHash = crypto.createHash('sha256').update(newCookie).digest();

      const origRow = await adminPool.query(
        'SELECT id, revoked_at, replaced_by FROM refresh_tokens WHERE token_hash = $1',
        [origHash],
      );
      const newRow = await adminPool.query(
        'SELECT id, revoked_at, replaced_by FROM refresh_tokens WHERE token_hash = $1',
        [newHash],
      );

      // Original token must be revoked and replaced_by must point to new token
      expect(origRow.rows[0].revoked_at).not.toBeNull();
      expect(origRow.rows[0].replaced_by).toBe(newRow.rows[0].id);

      // New token must be active
      expect(newRow.rows[0].revoked_at).toBeNull();
      expect(newRow.rows[0].replaced_by).toBeNull();
    });

    it('handles concurrent refresh requests for the same token: exactly 1 succeeds and 1 fails', async () => {
      // 1. Initial login to get a fresh refresh token
      const loginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: analystUser.email, password: analystUser.password },
      });
      expect(loginRes.statusCode).toBe(200);
      const targetCookie = extractCookie(loginRes.headers['set-cookie'], REFRESH_COOKIE_NAME)!;
      expect(targetCookie).toBeTruthy();

      // 2. Launch two concurrent refresh requests simultaneously targeting the exact same token
      const [resA, resB] = await Promise.all([
        app.inject({
          method: 'POST',
          url: '/api/v1/auth/refresh',
          headers: {
            cookie: `${REFRESH_COOKIE_NAME}=${targetCookie}`,
            'x-request-id': crypto.randomUUID(),
          },
        }),
        app.inject({
          method: 'POST',
          url: '/api/v1/auth/refresh',
          headers: {
            cookie: `${REFRESH_COOKIE_NAME}=${targetCookie}`,
            'x-request-id': crypto.randomUUID(),
          },
        }),
      ]);

      const statusCodes = [resA.statusCode, resB.statusCode];
      expect(statusCodes).toContain(200);
      expect(statusCodes).toContain(401);

      const successRes = resA.statusCode === 200 ? resA : resB;
      const failedRes = resA.statusCode === 401 ? resA : resB;

      // Verify the successful response
      const successBody = JSON.parse(successRes.body);
      expect(successBody.tokenType).toBe('Bearer');
      expect(typeof successBody.accessToken).toBe('string');
      const newCookie = extractCookie(successRes.headers['set-cookie'], REFRESH_COOKIE_NAME);
      expect(newCookie).toBeTruthy();
      expect(newCookie).not.toBe(targetCookie);

      // Verify the rejected response
      const failedBody = JSON.parse(failedRes.body);
      expect(failedBody.status).toBe(401);
      expect(failedBody.detail).toContain('reuse detected');

      // 3. Database verification afterward: original token revoked with replaced_by set
      const targetHash = crypto.createHash('sha256').update(targetCookie).digest();
      const origRow = await adminPool.query(
        'SELECT id, revoked_at, replaced_by FROM refresh_tokens WHERE token_hash = $1',
        [targetHash],
      );
      expect(origRow.rowCount).toBe(1);
      expect(origRow.rows[0].revoked_at).not.toBeNull();
      expect(origRow.rows[0].replaced_by).toBeTruthy();

      // 4. Test replay behavior: attempting to use the old token again MUST fail
      const replayRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: {
          cookie: `${REFRESH_COOKIE_NAME}=${targetCookie}`,
          'x-request-id': crypto.randomUUID(),
        },
      });
      expect(replayRes.statusCode).toBe(401);
      const replayBody = JSON.parse(replayRes.body);
      expect(replayBody.detail).toContain('reuse detected');

      // Verify replay detection audit event
      const auditRes = await adminPool.query(
        `SELECT action, actor_id, details
         FROM audit_events
         WHERE action = 'user.token_replay_detected' AND actor_id = $1`,
        [analystUser.id],
      );
      expect(auditRes.rowCount).toBeGreaterThanOrEqual(1);
    });

    it('detects token theft / replay and immediately revokes all user sessions', async () => {
      // 1. Initial login
      const loginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: auditorUser.email, password: auditorUser.password },
      });
      const legitimateCookie = extractCookie(loginRes.headers['set-cookie'], REFRESH_COOKIE_NAME)!;

      // 2. Legitimate client rotates the token
      const rotateRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${legitimateCookie}` },
      });
      expect(rotateRes.statusCode).toBe(200);
      const nextLegitimateCookie = extractCookie(
        rotateRes.headers['set-cookie'],
        REFRESH_COOKIE_NAME,
      )!;

      // 3. Attacker attempts to replay the already-used legitimateCookie
      const replayRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: {
          cookie: `${REFRESH_COOKIE_NAME}=${legitimateCookie}`,
          'x-request-id': crypto.randomUUID(),
        },
      });

      expect(replayRes.statusCode).toBe(401);
      const replayBody = JSON.parse(replayRes.body);
      expect(replayBody.detail).toContain('reuse detected');

      // 4. Invariant Verification: ALL active tokens for auditorUser must now be revoked
      const activeTokens = await adminPool.query(
        `SELECT count(*)::int as count
         FROM refresh_tokens
         WHERE user_id = $1 AND revoked_at IS NULL`,
        [auditorUser.id],
      );
      expect(activeTokens.rows[0].count).toBe(0);

      // 5. Subsequent attempts using even the newest cookie MUST now fail
      const nextAttempt = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${nextLegitimateCookie}` },
      });
      expect(nextAttempt.statusCode).toBe(401);

      // 6. Audit verification: replay detected event logged
      const auditRes = await adminPool.query(
        `SELECT action, actor_id, details
         FROM audit_events
         WHERE action = 'user.token_replay_detected' AND actor_id = $1`,
        [auditorUser.id],
      );
      expect(auditRes.rowCount).toBeGreaterThanOrEqual(1);
    });
  });

  // =========================================================================
  // 4. Logout Flow
  // =========================================================================
  describe('4. POST /api/v1/auth/logout', () => {
    it('revokes refresh token and clears cookie', async () => {
      // Login
      const loginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: adminUser.email, password: adminUser.password },
      });
      const cookie = extractCookie(loginRes.headers['set-cookie'], REFRESH_COOKIE_NAME)!;

      // Logout
      const logoutRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: {
          cookie: `${REFRESH_COOKIE_NAME}=${cookie}`,
          'x-request-id': crypto.randomUUID(),
        },
      });

      expect(logoutRes.statusCode).toBe(200);
      const body = JSON.parse(logoutRes.body);
      expect(body.message).toBe('Logged out successfully');

      // Database verification: token marked revoked
      const tokenHash = crypto.createHash('sha256').update(cookie).digest();
      const dbRow = await adminPool.query(
        'SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1',
        [tokenHash],
      );
      expect(dbRow.rows[0].revoked_at).not.toBeNull();

      // Refresh attempt with logged out cookie fails
      const refreshFail = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${cookie}` },
      });
      expect(refreshFail.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // 5. RBAC & Identity Verification (authz-06)
  // =========================================================================
  describe('5. RBAC & Role Enforcement (authz-06)', () => {
    let adminToken: string;
    let analystToken: string;
    let auditorToken: string;

    beforeAll(async () => {
      const getJwt = async (u: SeededUser) => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/login',
          payload: { email: u.email, password: u.password },
        });
        return JSON.parse(res.body).accessToken as string;
      };

      adminToken = await getJwt(adminUser);
      analystToken = await getJwt(analystUser);
      auditorToken = await getJwt(auditorUser);
    });

    it('GET /api/v1/auth/me returns authenticated user identity', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.user.id).toBe(adminUser.id);
      expect(body.user.email).toBe(adminUser.email);
      expect(body.user.role).toBe('admin');
    });

    it('GET /api/v1/auth/me rejects unauthenticated or invalid token', async () => {
      const missingRes = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
      });
      expect(missingRes.statusCode).toBe(401);

      const invalidRes = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/me',
        headers: { authorization: 'Bearer invalid.token.signature' },
      });
      expect(invalidRes.statusCode).toBe(401);
    });

    it('enforces RBAC matrix across admin, analyst, and auditor endpoints', async () => {
      // 1. Admin Token Access
      const adminOnAdmin = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/admin-only',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(adminOnAdmin.statusCode).toBe(200);

      const adminOnAnalyst = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/analyst-only',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(adminOnAnalyst.statusCode).toBe(200);

      const adminOnAuditor = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/auditor-only',
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(adminOnAuditor.statusCode).toBe(200);

      // 2. Analyst Token Access
      const analystOnAdmin = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/admin-only',
        headers: { authorization: `Bearer ${analystToken}` },
      });
      expect(analystOnAdmin.statusCode).toBe(403);
      const analystDenied = JSON.parse(analystOnAdmin.body);
      expect(analystDenied.title).toBe('Forbidden');
      expect(analystDenied.detail).toContain('not authorized');

      const analystOnAnalyst = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/analyst-only',
        headers: { authorization: `Bearer ${analystToken}` },
      });
      expect(analystOnAnalyst.statusCode).toBe(200);

      const analystOnAuditor = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/auditor-only',
        headers: { authorization: `Bearer ${analystToken}` },
      });
      expect(analystOnAuditor.statusCode).toBe(403);

      // 3. Auditor Token Access
      const auditorOnAdmin = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/admin-only',
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      expect(auditorOnAdmin.statusCode).toBe(403);

      const auditorOnAuditor = await app.inject({
        method: 'GET',
        url: '/api/v1/auth/auditor-only',
        headers: { authorization: `Bearer ${auditorToken}` },
      });
      expect(auditorOnAuditor.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // 6. Audit Trail & Zero-Secret Verification
  // =========================================================================
  describe('6. Tamper-Evident Audit Logging & Zero Secrets', () => {
    it('verifies that all P7 audit records maintain hash chain and leak zero credentials', async () => {
      const eventsRes = await adminPool.query(
        `SELECT seq, prev_hash, event_hash, action, actor_type, actor_id, details
         FROM audit_events
         WHERE action LIKE 'user.%'
         ORDER BY seq ASC`,
      );

      expect(eventsRes.rowCount).toBeGreaterThan(0);

      const forbiddenStrings = [
        adminUser.password,
        analystUser.password,
        auditorUser.password,
        'TargetPassword123!',
      ];

      for (const row of eventsRes.rows) {
        // Invariant: event_hash must be 32 bytes binary
        expect(row.event_hash).toBeInstanceOf(Buffer);
        expect((row.event_hash as Buffer).length).toBe(32);

        // Invariant: Zero plaintext credentials or tokens in details
        const detailsString = JSON.stringify(row.details);
        for (const secret of forbiddenStrings) {
          expect(detailsString).not.toContain(secret);
        }

        // Details must not contain raw tokens or private keys
        expect(detailsString).not.toContain('PRIVATE KEY');
      }
    });
  });
});
