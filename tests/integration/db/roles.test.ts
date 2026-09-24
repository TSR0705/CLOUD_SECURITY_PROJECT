import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import type pg from 'pg';
import { createPool, createBaseFixtures, type FixtureContext } from './helpers.js';

describe('Database Roles & Least Privilege Authorization (DB-23 to DB-28, RLS)', () => {
  let adminPool: pg.Pool;
  let apiPool: pg.Pool;
  let scannerPool: pg.Pool;
  let promoterPool: pg.Pool;
  let replicatorPool: pg.Pool;
  let auditorPool: pg.Pool;

  let fixtures: FixtureContext;

  beforeAll(async () => {
    adminPool = createPool('sug_admin', 'sug_dev_password');
    apiPool = createPool('sug_api', 'sug_api_dev_password');
    scannerPool = createPool('sug_scanner', 'sug_scanner_dev_password');
    promoterPool = createPool('sug_promoter', 'sug_promoter_dev_password');
    replicatorPool = createPool('sug_replicator', 'sug_replicator_dev_password');
    auditorPool = createPool('sug_auditor', 'sug_auditor_dev_password');

    fixtures = await createBaseFixtures(adminPool);
  });

  afterAll(async () => {
    await adminPool.end();
    await apiPool.end();
    await scannerPool.end();
    await promoterPool.end();
    await replicatorPool.end();
    await auditorPool.end();
  });

  it('DB-23: sug_api cannot write security_decisions', async () => {
    const boundSha = crypto.createHash('sha256').update('bound').digest();
    await expect(
      apiPool.query(
        `INSERT INTO security_decisions (
           file_version_id, policy_id, decision, primary_reason, severity,
           confidence, risk_score, policy_result, scanner_result, integrity_result,
           authorization_result, bound_bucket, bound_key, bound_storage_version_id,
           bound_sha256, bound_size, record, engine_version, decided_by
         )
         VALUES ($1, $2, 'ALLOW', 'CLEAN', 'INFO', 'CONFIRMED', 0, 'PASS', 'PASS', 'PASS', 'PASS', 'bucket', 'key', 'v1', $3, 1024, '{}'::jsonb, '1.0', 'malicious_api')`,
        [fixtures.fileVersionId, fixtures.policyId, boundSha],
      ),
    ).rejects.toThrow(/permission denied for table security_decisions/);
  });

  it('DB-24: sug_scanner cannot write security_decisions', async () => {
    const boundSha = crypto.createHash('sha256').update('bound').digest();
    await expect(
      scannerPool.query(
        `INSERT INTO security_decisions (
           file_version_id, policy_id, decision, primary_reason, severity,
           confidence, risk_score, policy_result, scanner_result, integrity_result,
           authorization_result, bound_bucket, bound_key, bound_storage_version_id,
           bound_sha256, bound_size, record, engine_version, decided_by
         )
         VALUES ($1, $2, 'ALLOW', 'CLEAN', 'INFO', 'CONFIRMED', 0, 'PASS', 'PASS', 'PASS', 'PASS', 'bucket', 'key', 'v1', $3, 1024, '{}'::jsonb, '1.0', 'scanner_override')`,
        [fixtures.fileVersionId, fixtures.policyId, boundSha],
      ),
    ).rejects.toThrow(/permission denied for table security_decisions/);
  });

  it('DB-25: sug_scanner cannot write promotion_jobs', async () => {
    await expect(
      scannerPool.query(
        `INSERT INTO promotion_jobs (decision_id)
         VALUES ($1)`,
        [crypto.randomUUID()],
      ),
    ).rejects.toThrow(/permission denied for table promotion_jobs/);

    await expect(scannerPool.query(`UPDATE promotion_jobs SET status = 'RUNNING'`)).rejects.toThrow(
      /permission denied for table promotion_jobs/,
    );
  });

  it('DB-26: sug_replicator cannot write security_decisions', async () => {
    const boundSha = crypto.createHash('sha256').update('bound').digest();
    await expect(
      replicatorPool.query(
        `INSERT INTO security_decisions (
           file_version_id, policy_id, decision, primary_reason, severity,
           confidence, risk_score, policy_result, scanner_result, integrity_result,
           authorization_result, bound_bucket, bound_key, bound_storage_version_id,
           bound_sha256, bound_size, record, engine_version, decided_by
         )
         VALUES ($1, $2, 'ALLOW', 'CLEAN', 'INFO', 'CONFIRMED', 0, 'PASS', 'PASS', 'PASS', 'PASS', 'bucket', 'key', 'v1', $3, 1024, '{}'::jsonb, '1.0', 'replicator_override')`,
        [fixtures.fileVersionId, fixtures.policyId, boundSha],
      ),
    ).rejects.toThrow(/permission denied for table security_decisions/);
  });

  it('DB-27: sug_replicator cannot write scan_results', async () => {
    const scannedSha = crypto.createHash('sha256').update('scanned').digest();
    await expect(
      replicatorPool.query(
        `INSERT INTO scan_results (
           scan_job_id, file_version_id, check_id, engine, outcome,
           severity, confidence, scanned_storage_version_id, scanned_sha256, scanned_size
         )
         VALUES ($1, $2, 'check-1', 'fake_engine', 'PASS', 'INFO', 'CONFIRMED', 'v1', $3, 1024)`,
        [crypto.randomUUID(), fixtures.fileVersionId, scannedSha],
      ),
    ).rejects.toThrow(/permission denied for table scan_results/);
  });

  describe('DB-28: sug_auditor read-only and column-level security restrictions', () => {
    it('rejects all write attempts by sug_auditor', async () => {
      await expect(
        auditorPool.query(
          `INSERT INTO files (application_id, upload_session_id, display_filename)
           VALUES ($1, $2, 'audit_hack.pdf')`,
          [fixtures.appId, fixtures.sessionId],
        ),
      ).rejects.toThrow(/permission denied for table files/);

      await expect(
        auditorPool.query(`UPDATE files SET display_filename = 'hacked.pdf' WHERE id = $1`, [
          fixtures.fileId,
        ]),
      ).rejects.toThrow(/permission denied for table files/);

      await expect(
        auditorPool.query(`DELETE FROM files WHERE id = $1`, [fixtures.fileId]),
      ).rejects.toThrow(/permission denied for table files/);
    });

    it('denies access to sensitive columns (password_hash, key_hmac) and refresh_tokens', async () => {
      // Deny password_hash column on users
      await expect(
        auditorPool.query(`SELECT password_hash FROM users WHERE id = $1`, [fixtures.userId]),
      ).rejects.toThrow(
        /permission denied for table users|permission denied for column password_hash/,
      );

      // Deny SELECT * from users (because password_hash is not granted)
      await expect(
        auditorPool.query(`SELECT * FROM users WHERE id = $1`, [fixtures.userId]),
      ).rejects.toThrow(
        /permission denied for table users|permission denied for column password_hash/,
      );

      // Deny key_hmac column on api_keys
      await expect(
        auditorPool.query(`SELECT key_hmac FROM api_keys WHERE id = $1`, [fixtures.apiKeyId]),
      ).rejects.toThrow(
        /permission denied for table api_keys|permission denied for column key_hmac/,
      );

      // Deny access to refresh_tokens table completely
      await expect(auditorPool.query(`SELECT * FROM refresh_tokens`)).rejects.toThrow(
        /permission denied for table refresh_tokens/,
      );
    });

    it('allows access to non-sensitive columns and audit records', async () => {
      const userRes = await auditorPool.query(
        `SELECT id, email, role, is_active FROM users WHERE id = $1`,
        [fixtures.userId],
      );
      expect(userRes.rows.length).toBe(1);
      expect(userRes.rows[0].email).toBeTruthy();

      const keyRes = await auditorPool.query(
        `SELECT id, application_id, key_prefix FROM api_keys WHERE id = $1`,
        [fixtures.apiKeyId],
      );
      expect(keyRes.rows.length).toBe(1);
      expect(keyRes.rows[0].key_prefix).toBeTruthy();

      const auditRes = await auditorPool.query(
        `SELECT seq, action, actor_type FROM audit_events LIMIT 5`,
      );
      expect(Array.isArray(auditRes.rows)).toBe(true);
    });
  });

  describe('Row Level Security (RLS) on cloud_objects', () => {
    it('sug_replicator can insert into zone = replica', async () => {
      const objSha = crypto.createHash('sha256').update('replica-obj').digest();
      const res = await replicatorPool.query(
        `INSERT INTO cloud_objects (
           file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes, sha256_plain
         )
         VALUES ($1, 'replica', 'gcp', 'sug-replica-bucket', $2, 'v-rep-1', 512, $3)
         RETURNING id, zone`,
        [fixtures.fileVersionId, `replica/${crypto.randomUUID()}`, objSha],
      );
      expect(res.rows[0].id).toBeTruthy();
      expect(res.rows[0].zone).toBe('replica');
    });

    it('sug_replicator is BLOCKED by RLS when inserting into zone = clean', async () => {
      const objSha = crypto.createHash('sha256').update('clean-obj').digest();
      await expect(
        replicatorPool.query(
          `INSERT INTO cloud_objects (
             file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes, sha256_plain
           )
           VALUES ($1, 'clean', 'aws', 'sug-clean-bucket', $2, 'v-clean-1', 512, $3)`,
          [fixtures.fileVersionId, `clean/${crypto.randomUUID()}`, objSha],
        ),
      ).rejects.toThrow(/new row violates row-level security policy for table "cloud_objects"/);
    });

    it('sug_promoter can insert into zone = clean', async () => {
      const objSha = crypto.createHash('sha256').update('clean-promoter-obj').digest();
      const res = await promoterPool.query(
        `INSERT INTO cloud_objects (
           file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes, sha256_plain
         )
         VALUES ($1, 'clean', 'aws', 'sug-clean-bucket', $2, 'v-clean-promoter-1', 512, $3)
         RETURNING id, zone`,
        [fixtures.fileVersionId, `clean/${crypto.randomUUID()}`, objSha],
      );
      expect(res.rows[0].id).toBeTruthy();
      expect(res.rows[0].zone).toBe('clean');
    });
  });
});
