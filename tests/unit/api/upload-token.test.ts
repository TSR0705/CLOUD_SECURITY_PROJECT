import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import * as jose from 'jose';
import {
  createUploadToken,
  verifyUploadToken,
  UPLOAD_TOKEN_AUDIENCE,
  UPLOAD_TOKEN_ISSUER,
  UPLOAD_TOKEN_EXPIRATION_SECONDS,
} from '../../../services/api/src/upload/upload-token.js';
import { createDashboardToken, verifyDashboardToken } from '../../../services/api/src/auth/jwt.js';

describe('EdDSA Upload Token Security & Separation (P8)', () => {
  let privateKeyPem: string;
  let publicKeyPem: string;

  beforeAll(() => {
    const pair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    privateKeyPem = pair.privateKey;
    publicKeyPem = pair.publicKey;
  });

  it('signs and verifies a valid EdDSA upload token with aud=sug-upload and 10-min expiry', async () => {
    const sessionId = crypto.randomUUID();
    const applicationId = crypto.randomUUID();
    const jti = crypto.randomUUID();

    const token = await createUploadToken(
      {
        sessionId,
        applicationId,
        jti,
        expiresInSeconds: UPLOAD_TOKEN_EXPIRATION_SECONDS,
      },
      privateKeyPem,
    );

    expect(typeof token).toBe('string');

    const verified = await verifyUploadToken(token, publicKeyPem);
    expect(verified.aud).toBe(UPLOAD_TOKEN_AUDIENCE);
    expect(verified.iss).toBe(UPLOAD_TOKEN_ISSUER);
    expect(verified.sub).toBe(applicationId);
    expect(verified.sid).toBe(sessionId);
    expect(verified.jti).toBe(jti);
    expect(verified.exp - verified.iat).toBe(UPLOAD_TOKEN_EXPIRATION_SECONDS);
  });

  it('SEPARATION: upload verifier strictly rejects dashboard tokens (aud=sug-dashboard)', async () => {
    const dashboardToken = await createDashboardToken(
      {
        id: crypto.randomUUID(),
        email: 'analyst@example.com',
        role: 'analyst',
      },
      privateKeyPem,
    );

    await expect(verifyUploadToken(dashboardToken, publicKeyPem)).rejects.toThrow(
      /unexpected "aud" claim value/i,
    );
  });

  it('SEPARATION: dashboard verifier strictly rejects upload tokens (aud=sug-upload)', async () => {
    const uploadToken = await createUploadToken(
      {
        sessionId: crypto.randomUUID(),
        applicationId: crypto.randomUUID(),
        jti: crypto.randomUUID(),
      },
      privateKeyPem,
    );

    await expect(verifyDashboardToken(uploadToken, publicKeyPem)).rejects.toThrow(
      /unexpected "aud" claim value/i,
    );
  });

  it('rejects expired upload tokens', async () => {
    const token = await createUploadToken(
      {
        sessionId: crypto.randomUUID(),
        applicationId: crypto.randomUUID(),
        jti: crypto.randomUUID(),
        expiresInSeconds: -10, // already expired
      },
      privateKeyPem,
    );

    await expect(verifyUploadToken(token, publicKeyPem)).rejects.toThrow(
      /"exp" claim timestamp check failed/i,
    );
  });

  it('rejects upload tokens with invalid algorithm (e.g. alg=none or HS256)', async () => {
    // 1. Unsigned alg=none
    const unsignedHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString(
      'base64url',
    );
    const unsignedPayload = Buffer.from(
      JSON.stringify({
        iss: UPLOAD_TOKEN_ISSUER,
        aud: UPLOAD_TOKEN_AUDIENCE,
        sub: crypto.randomUUID(),
        jti: crypto.randomUUID(),
        sid: crypto.randomUUID(),
        exp: Math.floor(Date.now() / 1000) + 600,
      }),
    ).toString('base64url');
    const algNoneToken = `${unsignedHeader}.${unsignedPayload}.`;

    await expect(verifyUploadToken(algNoneToken, publicKeyPem)).rejects.toThrow(
      /Algorithm 'none' is not permitted/i,
    );

    // 2. Symmetric HS256
    const symmetricSecret = crypto.randomBytes(32);
    const hs256Token = await new jose.SignJWT({ sid: crypto.randomUUID() })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuer(UPLOAD_TOKEN_ISSUER)
      .setAudience(UPLOAD_TOKEN_AUDIENCE)
      .setSubject(crypto.randomUUID())
      .setJti(crypto.randomUUID())
      .setExpirationTime('10m')
      .sign(symmetricSecret);

    await expect(verifyUploadToken(hs256Token, publicKeyPem)).rejects.toThrow(
      /Algorithm 'HS256' is not permitted/i,
    );
  });

  it('rejects upload tokens with forged or corrupted signatures', async () => {
    const validToken = await createUploadToken(
      {
        sessionId: crypto.randomUUID(),
        applicationId: crypto.randomUUID(),
        jti: crypto.randomUUID(),
      },
      privateKeyPem,
    );

    const parts = validToken.split('.');
    const corruptedSig = parts[2]!.substring(0, parts[2]!.length - 4) + 'AAAA';
    const forgedToken = `${parts[0]}.${parts[1]}.${corruptedSig}`;

    await expect(verifyUploadToken(forgedToken, publicKeyPem)).rejects.toThrow(
      /signature verification failed/i,
    );
  });

  it('rejects tokens missing required sid or jti claims', async () => {
    const privateKey = await jose.importPKCS8(privateKeyPem, 'EdDSA');

    // Missing sid
    const noSidToken = await new jose.SignJWT({})
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuer(UPLOAD_TOKEN_ISSUER)
      .setAudience(UPLOAD_TOKEN_AUDIENCE)
      .setSubject(crypto.randomUUID())
      .setJti(crypto.randomUUID())
      .setExpirationTime('10m')
      .sign(privateKey);

    await expect(verifyUploadToken(noSidToken, publicKeyPem)).rejects.toThrow(
      /JWT sid \(session ID\) claim is missing/i,
    );

    // Missing jti
    const noJtiToken = await new jose.SignJWT({ sid: crypto.randomUUID() })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
      .setIssuer(UPLOAD_TOKEN_ISSUER)
      .setAudience(UPLOAD_TOKEN_AUDIENCE)
      .setSubject(crypto.randomUUID())
      .setExpirationTime('10m')
      .sign(privateKey);

    await expect(verifyUploadToken(noJtiToken, publicKeyPem)).rejects.toThrow(
      /JWT jti claim is missing/i,
    );
  });
});
