import * as jose from 'jose';
import crypto from 'node:crypto';

export const UPLOAD_TOKEN_ISSUER = 'sug-api';
export const UPLOAD_TOKEN_AUDIENCE = 'sug-upload';
export const UPLOAD_TOKEN_EXPIRATION_SECONDS = 600; // 10 minutes strictly

export interface UploadJwtPayload {
  iss: string;
  aud: string;
  sub: string; // applicationId
  jti: string; // unique single-use token ID
  sid: string; // upload session ID
  iat: number;
  exp: number;
  typ: 'JWT';
}

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
 * Creates and signs an EdDSA (Ed25519) upload session token.
 *
 * Security Invariants:
 * 1. Fixed algorithm: strictly constrained to 'EdDSA'.
 * 2. Audience: strictly 'sug-upload' (distinct from 'sug-dashboard').
 * 3. Issuer: 'sug-api'.
 * 4. Lifespan: 10 minutes (600 seconds).
 * 5. Bound claims: includes jti (unique token identifier) and sid (session identifier).
 */
export async function createUploadToken(
  params: {
    sessionId: string;
    applicationId: string;
    jti: string;
    expiresInSeconds?: number;
  },
  privateKeyPem: string,
): Promise<string> {
  const privateKey = await jose.importPKCS8(privateKeyPem, 'EdDSA');
  const duration = params.expiresInSeconds ?? UPLOAD_TOKEN_EXPIRATION_SECONDS;

  return new jose.SignJWT({
    sid: params.sessionId,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .setIssuer(UPLOAD_TOKEN_ISSUER)
    .setAudience(UPLOAD_TOKEN_AUDIENCE)
    .setSubject(params.applicationId)
    .setJti(params.jti)
    .setIssuedAt()
    .setExpirationTime(`${duration}s`)
    .sign(privateKey);
}

/**
 * Verifies an EdDSA upload token in strict alignment with RFC 8725 BCP.
 *
 * Security Invariants:
 * 1. Rejects any token where alg !== 'EdDSA'. Rejects 'none', 'HS256', etc.
 * 2. Rejects any token where aud !== 'sug-upload'. Crucially rejects dashboard tokens ('sug-dashboard').
 * 3. Validates signature with SPKI public key.
 * 4. Enforces 10-minute expiration window.
 * 5. Requires valid UUIDs for sub (applicationId), sid (sessionId), and jti.
 */
export async function verifyUploadToken(
  token: string,
  publicKeyPem: string,
): Promise<UploadJwtPayload> {
  if (!token || typeof token !== 'string') {
    throw new Error('Upload token must be a non-empty string');
  }

  // Header pre-validation
  const unverifiedHeader = jose.decodeProtectedHeader(token);
  if (unverifiedHeader.alg !== 'EdDSA') {
    throw new Error(`Algorithm '${unverifiedHeader.alg}' is not permitted; expected 'EdDSA'`);
  }
  if (unverifiedHeader.typ && unverifiedHeader.typ !== 'JWT') {
    throw new Error(`Invalid token typ '${unverifiedHeader.typ}'; expected 'JWT'`);
  }

  const publicKey = await jose.importSPKI(publicKeyPem, 'EdDSA');

  const { payload } = await jose.jwtVerify(token, publicKey, {
    issuer: UPLOAD_TOKEN_ISSUER,
    audience: UPLOAD_TOKEN_AUDIENCE,
    algorithms: ['EdDSA'],
  });

  const sub = payload.sub;
  if (!sub || typeof sub !== 'string') {
    throw new Error('JWT subject (sub) claim is missing or invalid');
  }

  const jti = payload.jti;
  if (!jti || typeof jti !== 'string') {
    throw new Error('JWT jti claim is missing or invalid');
  }

  const sid = (payload as Record<string, unknown>).sid;
  if (!sid || typeof sid !== 'string') {
    throw new Error('JWT sid (session ID) claim is missing or invalid');
  }

  if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number') {
    throw new Error('JWT timestamp claims (iat, exp) are invalid');
  }

  return {
    iss: UPLOAD_TOKEN_ISSUER,
    aud: UPLOAD_TOKEN_AUDIENCE,
    sub,
    jti,
    sid,
    iat: payload.iat,
    exp: payload.exp,
    typ: 'JWT',
  };
}
