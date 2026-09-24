import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;

export const defaultPort = process.env.POSTGRES_PORT || (process.env.CI ? '5432' : '5433');
export const host = process.env.POSTGRES_HOST || '127.0.0.1';

export function getDbUrl(user = 'sug_admin', password = 'sug_dev_password', db = 'sug'): string {
  if (process.env.DATABASE_URL && user === 'sug_admin') {
    return process.env.DATABASE_URL;
  }
  return `postgres://${user}:${password}@${host}:${defaultPort}/${db}`;
}

export function createPool(user = 'sug_admin', password = 'sug_dev_password', max = 10): pg.Pool {
  return new Pool({
    connectionString: getDbUrl(user, password),
    max,
  });
}

export interface FixtureContext {
  userId: string;
  appId: string;
  apiKeyId: string;
  policyId: string;
  sessionId: string;
  fileId: string;
  fileVersionId: string;
}

export async function createBaseFixtures(pool: pg.Pool): Promise<FixtureContext> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. User
    const userRes = await client.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, 'admin')
       RETURNING id`,
      [`admin_${crypto.randomUUID()}@gateway.internal`, 'argon2id$placeholder'],
    );
    const userId = userRes.rows[0].id;

    // 2. Application
    const appRes = await client.query(
      `INSERT INTO applications (name, owner_user_id)
       VALUES ($1, $2)
       RETURNING id`,
      [`app_${crypto.randomUUID().slice(0, 16)}`, userId],
    );
    const appId = appRes.rows[0].id;

    // 3. API Key
    const keyPrefix = crypto.randomBytes(4).toString('hex');
    const keyHmac = crypto.createHash('sha256').update(`key_${keyPrefix}`).digest();
    const keyRes = await client.query(
      `INSERT INTO api_keys (application_id, key_prefix, key_hmac, created_by)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [appId, keyPrefix, keyHmac, userId],
    );
    const apiKeyId = keyRes.rows[0].id;

    // 4. Security Policy
    const doc = { allowedExtensions: ['.pdf'], maxFileSize: 10485760 };
    const docSha = crypto.createHash('sha256').update(JSON.stringify(doc)).digest();
    const policyRes = await client.query(
      `INSERT INTO security_policies (application_id, version, document, document_sha256, created_by)
       VALUES ($1, 1, $2, $3, $4)
       RETURNING id`,
      [appId, JSON.stringify(doc), docSha, userId],
    );
    const policyId = policyRes.rows[0].id;

    await client.query(`UPDATE applications SET active_policy_id = $1 WHERE id = $2`, [
      policyId,
      appId,
    ]);

    // 5. Upload Session
    const jti = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 600000);
    const sessionRes = await client.query(
      `INSERT INTO upload_sessions (
         application_id, api_key_id, policy_id, original_filename, declared_mime,
         declared_size, token_jti, expires_at
       )
       VALUES ($1, $2, $3, 'document.pdf', 'application/pdf', 1024, $4, $5)
       RETURNING id`,
      [appId, apiKeyId, policyId, jti, expiresAt],
    );
    const sessionId = sessionRes.rows[0].id;

    // 6. File
    const fileRes = await client.query(
      `INSERT INTO files (application_id, upload_session_id, display_filename)
       VALUES ($1, $2, 'document.pdf')
       RETURNING id`,
      [appId, sessionId],
    );
    const fileId = fileRes.rows[0].id;

    // 7. File Version
    const ingestSha = crypto.createHash('sha256').update('sample content').digest();
    const uniqueKey = `incoming/${crypto.randomUUID()}`;
    const uniqueVersion = `v-${crypto.randomUUID()}`;
    const fvRes = await client.query(
      `INSERT INTO file_versions (
         file_id, version_no, provider, bucket, object_key, storage_version_id, size_bytes, sha256_ingest
       )
       VALUES ($1, 1, 'aws', 'sug-quarantine', $2, $3, 1024, $4)
       RETURNING id`,
      [fileId, uniqueKey, uniqueVersion, ingestSha],
    );
    const fileVersionId = fvRes.rows[0].id;

    await client.query(`UPDATE files SET current_version_id = $1 WHERE id = $2`, [
      fileVersionId,
      fileId,
    ]);

    await client.query('COMMIT');

    return {
      userId,
      appId,
      apiKeyId,
      policyId,
      sessionId,
      fileId,
      fileVersionId,
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}
