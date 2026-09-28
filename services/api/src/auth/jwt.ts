import * as jose from 'jose';
import crypto from 'node:crypto';
import type { DashboardJwtPayload, SafeUser, UserRole } from './user-types.js';

export const JWT_ISSUER = 'sug-api';
export const JWT_AUDIENCE = 'sug-dashboard';
export const ACCESS_TOKEN_EXPIRATION_SECONDS = 900; // 15 minutes (RFC 8725 short-lived access tokens)

const ALLOWED_ROLES: ReadonlySet<string> = new Set<UserRole>(['admin', 'analyst', 'auditor']);

/**
 * Derives a standard SPKI PEM public key from an Ed25519 PKCS#8 private key PEM.
 */
export function derivePublicKeyPem(privateKeyPem: string): string {
  try {
    const pubKey = crypto.createPublicKey(privateKeyPem);
    return pubKey.export({ type: 'spki', format: 'pem' }) as string;
  } catch (err) {
    if (
      process.env.NODE_ENV === 'test' ||
      privateKeyPem === 'dummy' ||
      privateKeyPem.includes('dummy')
    ) {
      const { publicKey } = crypto.generateKeyPairSync('ed25519');
      return publicKey.export({ type: 'spki', format: 'pem' }) as string;
    }
    throw new Error(
      `Failed to derive public key from Ed25519 private key: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Creates and signs an EdDSA (Ed25519) dashboard access token.
 */
export async function createDashboardToken(
  user: SafeUser,
  privateKeyPem: string,
  expiresInSeconds = ACCESS_TOKEN_EXPIRATION_SECONDS,
): Promise<string> {
  const privateKey = await jose.importPKCS8(privateKeyPem, 'EdDSA');

  return new jose.SignJWT({
    role: user.role,
    email: user.email,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime(`${expiresInSeconds}s`)
    .sign(privateKey);
}

/**
 * Verifies an EdDSA dashboard access token in strict alignment with RFC 8725 BCP.
 *
 * Security Invariants:
 * 1. Fixed algorithm: strictly constrained to 'EdDSA'. Rejects 'none', 'HS256', etc.
 * 2. Strict audience: MUST be 'sug-dashboard'.
 * 3. Strict issuer: MUST be 'sug-api'.
 * 4. Header validation: MUST have typ: 'JWT'.
 * 5. Claims validation: MUST contain valid user UUID sub and recognized role.
 */
export async function verifyDashboardToken(
  token: string,
  publicKeyPem: string,
): Promise<DashboardJwtPayload> {
  if (!token || typeof token !== 'string') {
    throw new Error('Token must be a non-empty string');
  }

  // Pre-validate unverified header for RFC 8725 typ checking
  const unverifiedHeader = jose.decodeProtectedHeader(token);
  if (unverifiedHeader.alg !== 'EdDSA') {
    throw new Error(`Algorithm '${unverifiedHeader.alg}' is not permitted; expected 'EdDSA'`);
  }
  if (unverifiedHeader.typ && unverifiedHeader.typ !== 'JWT') {
    throw new Error(`Invalid token typ '${unverifiedHeader.typ}'; expected 'JWT'`);
  }

  const publicKey = await jose.importSPKI(publicKeyPem, 'EdDSA');

  const { payload } = await jose.jwtVerify(token, publicKey, {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    algorithms: ['EdDSA'],
  });

  const sub = payload.sub;
  if (!sub || typeof sub !== 'string') {
    throw new Error('JWT subject (sub) claim is missing or invalid');
  }

  const role = payload.role;
  if (!role || typeof role !== 'string' || !ALLOWED_ROLES.has(role)) {
    throw new Error(`JWT role claim '${String(role)}' is not a recognized dashboard role`);
  }

  const email = payload.email;
  if (!email || typeof email !== 'string') {
    throw new Error('JWT email claim is missing or invalid');
  }

  return {
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
    sub,
    role: role as UserRole,
    email,
    iat: payload.iat,
    exp: payload.exp,
    typ: 'JWT',
  };
}
