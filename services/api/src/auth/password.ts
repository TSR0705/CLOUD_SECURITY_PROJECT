import * as argon2 from 'argon2';

/**
 * Argon2id parameters aligned with OWASP Password Storage Cheat Sheet
 * and RFC 9106 recommended minimums for sensitive backends.
 */
export const ARGON2ID_OPTIONS: argon2.HashOptions & { raw?: false } = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MB
  timeCost: 3, // 3 iterations
  parallelism: 4, // 4 threads
  raw: false,
};

/**
 * Pre-computed Argon2id hash for dummy verification.
 * Used when a login is attempted for a nonexistent user to ensure constant-time
 * execution and mitigate account enumeration via timing analysis.
 */
const DUMMY_HASH =
  '$argon2id$v=19$m=65536,p=4,t=3$c29tZXJhbmRvbXNhbHQ$5tXz3m4zFj1gKz5f3b7Z5x6t2c8v1m3p5q7r9s0u2w4';

/**
 * Hashes a plaintext password using Argon2id.
 */
export async function hashPassword(password: string): Promise<string> {
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  return argon2.hash(password, ARGON2ID_OPTIONS);
}

/**
 * Verifies a plaintext password against an Argon2id hash string.
 * Never throws on mismatch; returns boolean.
 */
export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  if (!hash || !password) {
    return false;
  }
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

/**
 * Performs a dummy Argon2 verification to equalize request duration when
 * a user is not found, neutralizing timing-based user enumeration.
 */
export async function dummyVerifyPassword(): Promise<void> {
  try {
    await argon2.verify(DUMMY_HASH, 'dummy_password_for_timing_mitigation');
  } catch {
    // Ignore verification failure
  }
}
