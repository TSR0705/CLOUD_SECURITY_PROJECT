import crypto from 'node:crypto';
import type { ApiKeyDatabase } from './types.js';
import type {
  UserRecord,
  SafeUser,
  RefreshTokenRecord,
  LoginResult,
  RotateResult,
} from './user-types.js';
import { verifyPassword, dummyVerifyPassword } from './password.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function toSafeUuid(val: unknown): string | null {
  if (typeof val === 'string' && UUID_REGEX.test(val.trim())) {
    return val.trim().toLowerCase();
  }
  return null;
}

export class UserService {
  private readonly db: ApiKeyDatabase;

  constructor({ db }: { db: ApiKeyDatabase }) {
    this.db = db;
  }

  /**
   * Helper to safely record audit events via audit_append() without crashing on cast errors.
   * Zero secrets or plaintext credentials are ever passed to this function.
   */
  private async safeAuditAppend(
    actorType: 'user' | 'service',
    actorId: string,
    action: string,
    refs: Record<string, unknown>,
    details: Record<string, unknown>,
  ): Promise<void> {
    try {
      const sanitizedRefs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(refs)) {
        if (v !== undefined && v !== null) {
          if (k === 'request_id') {
            const validUuid = toSafeUuid(v);
            if (validUuid) {
              sanitizedRefs[k] = validUuid;
            }
          } else {
            sanitizedRefs[k] = v;
          }
        }
      }

      await this.db.query(`SELECT audit_append($1, $2, $3, $4::jsonb, $5::jsonb)`, [
        actorType,
        actorId,
        action,
        JSON.stringify(sanitizedRefs),
        JSON.stringify(details),
      ]);
    } catch {
      // Audit append should fail closed in production, but avoid uncaught promise rejections
    }
  }

  /**
   * Authenticates a dashboard user using Argon2id with 5-attempt lockout enforcement.
   */
  async authenticate(
    email: string,
    password: string,
    clientIp?: string,
    requestId?: string,
  ): Promise<LoginResult> {
    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      await dummyVerifyPassword();
      return { success: false, reason: 'INVALID_CREDENTIALS' };
    }

    const trimmedEmail = email.trim().toLowerCase();

    // 1. Locate user by email
    const res = await this.db.query<UserRecord>(
      `SELECT id, email, password_hash, role, is_active, failed_logins, locked_until, created_at, last_login_at
       FROM users WHERE email = $1`,
      [trimmedEmail],
    );

    const user = res.rows[0];

    // User not found: run dummy Argon2 verify to mitigate timing attacks
    if (!user) {
      await dummyVerifyPassword();
      await this.safeAuditAppend(
        'service',
        'api_gateway',
        'user.login_failure',
        { request_id: requestId, client_ip: clientIp },
        { email: trimmedEmail, reason: 'USER_NOT_FOUND' },
      );
      return { success: false, reason: 'INVALID_CREDENTIALS' };
    }

    // 2. Check account lockout state
    if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
      await this.safeAuditAppend(
        'user',
        user.id,
        'user.login_failure',
        { request_id: requestId, client_ip: clientIp },
        { email: user.email, reason: 'ACCOUNT_LOCKED', locked_until: user.locked_until },
      );
      return { success: false, locked: true, reason: 'ACCOUNT_LOCKED' };
    }

    // 3. Check active status
    if (!user.is_active) {
      await dummyVerifyPassword();
      await this.safeAuditAppend(
        'user',
        user.id,
        'user.login_failure',
        { request_id: requestId, client_ip: clientIp },
        { email: user.email, reason: 'USER_INACTIVE' },
      );
      return { success: false, reason: 'INVALID_CREDENTIALS' };
    }

    // 4. Verify password with Argon2id
    const isPasswordValid = await verifyPassword(user.password_hash, password);

    if (!isPasswordValid) {
      const newFailures = (user.failed_logins || 0) + 1;

      if (newFailures >= 5) {
        // Lock account for 15 minutes after 5 failed attempts
        await this.db.query(
          `UPDATE users SET failed_logins = $1, locked_until = now() + interval '15 minutes' WHERE id = $2`,
          [newFailures, user.id],
        );

        await this.safeAuditAppend(
          'user',
          user.id,
          'user.locked_out',
          { request_id: requestId, client_ip: clientIp },
          { email: user.email, failed_logins: newFailures },
        );

        return { success: false, locked: true, reason: 'ACCOUNT_LOCKED' };
      }

      // Increment failure count
      await this.db.query(`UPDATE users SET failed_logins = $1 WHERE id = $2`, [
        newFailures,
        user.id,
      ]);

      await this.safeAuditAppend(
        'user',
        user.id,
        'user.login_failure',
        { request_id: requestId, client_ip: clientIp },
        { email: user.email, failed_logins: newFailures },
      );

      return { success: false, reason: 'INVALID_CREDENTIALS' };
    }

    // 5. Successful authentication: reset failed logins and clear lockout
    await this.db.query(
      `UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = $1`,
      [user.id],
    );

    const safeUser: SafeUser = {
      id: user.id,
      email: user.email,
      role: user.role,
    };

    await this.safeAuditAppend(
      'user',
      user.id,
      'user.login_success',
      { request_id: requestId, client_ip: clientIp },
      { email: user.email, role: user.role },
    );

    return { success: true, user: safeUser };
  }

  /**
   * Generates a high-entropy cryptographically random refresh token.
   * Stores only the SHA-256 hash in the database, returning the raw token to set in HttpOnly cookie.
   */
  async createRefreshToken(userId: string): Promise<{ rawToken: string; expiresAt: Date }> {
    const rawToken = crypto.randomBytes(32).toString('base64url');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await this.db.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [userId, tokenHash, expiresAt],
    );

    return { rawToken, expiresAt };
  }

  /**
   * Rotates a refresh token with automatic reuse detection (theft mitigation).
   */
  async rotateRefreshToken(rawToken: string, requestId?: string): Promise<RotateResult> {
    if (!rawToken || typeof rawToken !== 'string') {
      return { success: false, reason: 'INVALID_REFRESH_TOKEN' };
    }

    const tokenHash = crypto.createHash('sha256').update(rawToken).digest();

    const res = await this.db.query<RefreshTokenRecord>(
      `SELECT id, user_id, token_hash, expires_at, revoked_at, replaced_by
       FROM refresh_tokens WHERE token_hash = $1`,
      [tokenHash],
    );

    const token = res.rows[0];
    if (!token) {
      return { success: false, reason: 'INVALID_REFRESH_TOKEN' };
    }

    // Reuse detection: token already revoked or replaced!
    if (token.revoked_at !== null || token.replaced_by !== null) {
      // Invalidate ALL active refresh tokens for this user family (token theft defense)
      await this.db.query(
        `UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
        [token.user_id],
      );

      await this.safeAuditAppend(
        'user',
        token.user_id,
        'user.token_replay_detected',
        { request_id: requestId },
        { compromised_token_id: token.id },
      );

      return { success: false, reuseDetected: true, reason: 'TOKEN_REUSE_DETECTED' };
    }

    // Check expiration
    if (new Date(token.expires_at).getTime() < Date.now()) {
      return { success: false, reason: 'TOKEN_EXPIRED' };
    }

    // Check user active status
    const userRes = await this.db.query<UserRecord>(
      `SELECT id, email, role, is_active, locked_until FROM users WHERE id = $1`,
      [token.user_id],
    );
    const user = userRes.rows[0];

    if (
      !user ||
      !user.is_active ||
      (user.locked_until && new Date(user.locked_until).getTime() > Date.now())
    ) {
      return { success: false, reason: 'USER_INACTIVE' };
    }

    // Atomically rotate: create new token and mark previous token replaced
    const newRawToken = crypto.randomBytes(32).toString('base64url');
    const newTokenHash = crypto.createHash('sha256').update(newRawToken).digest();
    const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const insertRes = await this.db.query<{ id: string }>(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [token.user_id, newTokenHash, newExpiresAt],
    );
    const newId = insertRes.rows[0]?.id;

    await this.db.query(
      `UPDATE refresh_tokens SET replaced_by = $1, revoked_at = now() WHERE id = $2`,
      [newId, token.id],
    );

    const safeUser: SafeUser = {
      id: user.id,
      email: user.email,
      role: user.role,
    };

    await this.safeAuditAppend(
      'user',
      user.id,
      'user.token_refreshed',
      { request_id: requestId },
      { old_token_id: token.id, new_token_id: newId },
    );

    return {
      success: true,
      user: safeUser,
      newRawToken,
    };
  }

  /**
   * Revokes a refresh token upon user logout.
   */
  async revokeRefreshToken(rawToken: string, requestId?: string): Promise<boolean> {
    if (!rawToken || typeof rawToken !== 'string') {
      return false;
    }

    const tokenHash = crypto.createHash('sha256').update(rawToken).digest();

    const res = await this.db.query<RefreshTokenRecord>(
      `UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL RETURNING id, user_id`,
      [tokenHash],
    );

    const row = res.rows[0];
    if (row) {
      await this.safeAuditAppend(
        'user',
        row.user_id,
        'user.logout',
        { request_id: requestId },
        { token_id: row.id },
      );
      return true;
    }

    return false;
  }
}
