import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import pg from 'pg';
import { createPool, createBaseFixtures, getDbUrl } from './helpers.js';
import { runner } from 'node-pg-migrate';
import { resolve } from 'node:path';

describe('PostgreSQL Schema & Security Invariants (DB-01 to DB-30)', () => {
  let pool: pg.Pool;

  beforeAll(async () => {
    pool = createPool('sug_admin');
  });

  afterAll(async () => {
    await pool.end();
  });

  it('DB-01: Migration succeeds from an empty database and records pgmigrations', async () => {
    const res = await pool.query('SELECT count(*)::int as count FROM pgmigrations');
    expect(res.rows[0].count).toBe(9);
  });

  it('DB-02: All 16 required tables exist', async () => {
    const requiredTables = [
      'users',
      'applications',
      'api_keys',
      'security_policies',
      'refresh_tokens',
      'upload_sessions',
      'files',
      'file_versions',
      'cloud_objects',
      'scan_jobs',
      'scan_results',
      'security_decisions',
      'promotion_jobs',
      'replication_jobs',
      'audit_events',
      'audit_checkpoints',
    ];

    const res = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
    `);
    const existing = res.rows.map((r: { table_name: string }) => r.table_name);

    for (const table of requiredTables) {
      expect(existing).toContain(table);
    }
  });

  it('DB-03: Required extensions, functions and types exist', async () => {
    // Extensions
    const extRes = await pool.query('SELECT extname FROM pg_extension');
    const extensions = extRes.rows.map((r: { extname: string }) => r.extname);
    expect(extensions).toContain('pgcrypto');
    expect(extensions).toContain('citext');

    // Functions
    const fnRes = await pool.query(`
      SELECT routine_name
      FROM information_schema.routines
      WHERE routine_schema = 'public'
    `);
    const routines = fnRes.rows.map((r: { routine_name: string }) => r.routine_name);
    expect(routines).toContain('audit_append');
    expect(routines).toContain('forbid_mutation');

    // Types
    const typeRes = await pool.query(`
      SELECT typname FROM pg_type WHERE typnamespace = 'public'::regnamespace
    `);
    const types = typeRes.rows.map((r: { typname: string }) => r.typname);
    const expectedTypes = [
      'user_role',
      'session_status',
      'file_status',
      'job_status',
      'decision_type',
      'finding_outcome',
      'severity_level',
      'confidence_level',
      'cloud_provider',
      'storage_zone',
    ];
    for (const t of expectedTypes) {
      expect(types).toContain(t);
    }
  });

  it('DB-04: UUIDv7 defaults actually generate valid UUIDv7 values', async () => {
    const res = await pool.query('SELECT uuidv7() as val');
    const val: string = res.rows[0].val;

    // UUID regex format: 8-4-4-4-12
    expect(val).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);

    // Extract timestamp from most significant 48 bits (first 8 hex chars + 4 hex chars)
    const timeHex = val.substring(0, 8) + val.substring(9, 13);
    const timeMs = parseInt(timeHex, 16);
    const nowMs = Date.now();

    // Verify generated timestamp is within 60 seconds of current time
    expect(Math.abs(nowMs - timeMs)).toBeLessThan(60000);
  });

  it("DB-05: storage_version_id = '' is rejected by CHECK constraint", async () => {
    const fix = await createBaseFixtures(pool);
    const ingestSha = crypto.createHash('sha256').update('sample').digest();

    await expect(
      pool.query(
        `INSERT INTO file_versions (
           file_id, version_no, provider, bucket, object_key, storage_version_id, size_bytes, sha256_ingest
         )
         VALUES ($1, 2, 'aws', 'sug-quarantine', 'key2', '', 1024, $2)`,
        [fix.fileId, ingestSha],
      ),
    ).rejects.toThrow();
  });

  it("DB-06: storage_version_id = 'null' is rejected by CHECK constraint", async () => {
    const fix = await createBaseFixtures(pool);
    const ingestSha = crypto.createHash('sha256').update('sample').digest();

    await expect(
      pool.query(
        `INSERT INTO file_versions (
           file_id, version_no, provider, bucket, object_key, storage_version_id, size_bytes, sha256_ingest
         )
         VALUES ($1, 2, 'aws', 'sug-quarantine', 'key2', 'null', 1024, $2)`,
        [fix.fileId, ingestSha],
      ),
    ).rejects.toThrow();
  });

  it('DB-07: Valid storage_version_id succeeds', async () => {
    const fix = await createBaseFixtures(pool);
    const ingestSha = crypto.createHash('sha256').update('sample').digest();

    const dynamicKey = `incoming/${crypto.randomUUID()}`;
    const res = await pool.query(
      `INSERT INTO file_versions (
         file_id, version_no, provider, bucket, object_key, storage_version_id, size_bytes, sha256_ingest
       )
       VALUES ($1, 2, 'aws', 'sug-quarantine', $2, 'valid-v1.0.1', 1024, $3)
       RETURNING id, storage_version_id`,
      [fix.fileId, dynamicKey, ingestSha],
    );
    expect(res.rows[0].storage_version_id).toBe('valid-v1.0.1');
    expect(res.rows[0].id).toBeTruthy();
  });

  it('DB-11 & DB-12: UPDATE and DELETE on audit_events fail via forbid_mutation', async () => {
    const seq = await pool.query(
      `SELECT audit_append('service', 'test-svc', 'TEST_EVENT', '{}'::jsonb, '{"foo":"bar"}'::jsonb) as seq`,
    );
    const insertedSeq = seq.rows[0].seq;

    await expect(
      pool.query('UPDATE audit_events SET action = $1 WHERE seq = $2', ['MUTATED', insertedSeq]),
    ).rejects.toThrow(/audit_events is append-only/);

    await expect(
      pool.query('DELETE FROM audit_events WHERE seq = $1', [insertedSeq]),
    ).rejects.toThrow(/audit_events is append-only/);
  });

  it('DB-13 & DB-14: UPDATE and DELETE on scan_results fail via forbid_mutation', async () => {
    const fix = await createBaseFixtures(pool);
    const jobRes = await pool.query(
      `INSERT INTO scan_jobs (file_version_id) VALUES ($1) RETURNING id`,
      [fix.fileVersionId],
    );
    const jobId = jobRes.rows[0].id;
    const sha = crypto.createHash('sha256').update('sample').digest();

    const srRes = await pool.query(
      `INSERT INTO scan_results (
         scan_job_id, file_version_id, check_id, engine, outcome, scanned_storage_version_id, scanned_sha256, scanned_size
       )
       VALUES ($1, $2, 'magic.detect', 'file-type', 'PASS', 'v-12345', $3, 1024)
       RETURNING id`,
      [jobId, fix.fileVersionId, sha],
    );
    const resultId = srRes.rows[0].id;

    await expect(
      pool.query('UPDATE scan_results SET outcome = $1 WHERE id = $2', ['FAIL', resultId]),
    ).rejects.toThrow(/scan_results is append-only/);

    await expect(pool.query('DELETE FROM scan_results WHERE id = $1', [resultId])).rejects.toThrow(
      /scan_results is append-only/,
    );
  });

  it('DB-15 & DB-16: UPDATE and DELETE on security_decisions fail via forbid_mutation', async () => {
    const fix = await createBaseFixtures(pool);
    const boundSha = crypto.createHash('sha256').update('sample').digest();

    const decRes = await pool.query(
      `INSERT INTO security_decisions (
         file_version_id, policy_id, decision, primary_reason, severity, confidence,
         risk_score, policy_result, scanner_result, integrity_result, authorization_result,
         bound_bucket, bound_key, bound_storage_version_id, bound_sha256, bound_size,
         record, engine_version, decided_by
       )
       VALUES (
         $1, $2, 'ALLOW', 'Clean file', 'INFO', 'CONFIRMED',
         0, 'PASS', 'PASS', 'MATCH', 'AUTHORIZED',
         'sug-quarantine', 'key', 'v-12345', $3, 1024,
         '{}', '1.0.0', 'engine'
       )
       RETURNING id`,
      [fix.fileVersionId, fix.policyId, boundSha],
    );
    const decisionId = decRes.rows[0].id;

    await expect(
      pool.query('UPDATE security_decisions SET decision = $1 WHERE id = $2', [
        'BLOCK',
        decisionId,
      ]),
    ).rejects.toThrow(/security_decisions is append-only/);

    await expect(
      pool.query('DELETE FROM security_decisions WHERE id = $1', [decisionId]),
    ).rejects.toThrow(/security_decisions is append-only/);
  });

  it('DB-17 & DB-18: UPDATE and DELETE on file_versions fail via forbid_mutation', async () => {
    const fix = await createBaseFixtures(pool);

    await expect(
      pool.query('UPDATE file_versions SET size_bytes = 2048 WHERE id = $1', [fix.fileVersionId]),
    ).rejects.toThrow(/file_versions is append-only/);

    await expect(
      pool.query('DELETE FROM file_versions WHERE id = $1', [fix.fileVersionId]),
    ).rejects.toThrow(/file_versions is append-only/);
  });

  it('DB-19 & DB-20: UPDATE and DELETE on security_policies fail via forbid_mutation', async () => {
    const fix = await createBaseFixtures(pool);

    await expect(
      pool.query('UPDATE security_policies SET version = 2 WHERE id = $1', [fix.policyId]),
    ).rejects.toThrow(/security_policies is append-only/);

    await expect(
      pool.query('DELETE FROM security_policies WHERE id = $1', [fix.policyId]),
    ).rejects.toThrow(/security_policies is append-only/);
  });

  it('DB-21 & DB-22: UPDATE and DELETE on audit_checkpoints fail via forbid_mutation', async () => {
    const hash = crypto.createHash('sha256').update('chk').digest();
    const sig = crypto.createHash('sha256').update('sig').digest();

    const lastSeq = Date.now() + Math.floor(Math.random() * 100000);
    const chkRes = await pool.query(
      `INSERT INTO audit_checkpoints (last_seq, chain_hash, signature)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [lastSeq, hash, sig],
    );
    const chkId = chkRes.rows[0].id;

    await expect(
      pool.query('UPDATE audit_checkpoints SET last_seq = 888888 WHERE id = $1', [chkId]),
    ).rejects.toThrow(/audit_checkpoints is append-only/);

    await expect(
      pool.query('DELETE FROM audit_checkpoints WHERE id = $1', [chkId]),
    ).rejects.toThrow(/audit_checkpoints is append-only/);
  });

  it('DB-29: promotion_jobs rejects duplicate decision_id', async () => {
    const fix = await createBaseFixtures(pool);
    const boundSha = crypto.createHash('sha256').update('sample').digest();

    const decRes = await pool.query(
      `INSERT INTO security_decisions (
         file_version_id, policy_id, decision, primary_reason, severity, confidence,
         risk_score, policy_result, scanner_result, integrity_result, authorization_result,
         bound_bucket, bound_key, bound_storage_version_id, bound_sha256, bound_size,
         record, engine_version, decided_by
       )
       VALUES (
         $1, $2, 'ALLOW', 'Clean file', 'INFO', 'CONFIRMED',
         0, 'PASS', 'PASS', 'MATCH', 'AUTHORIZED',
         'sug-quarantine', 'key', 'v-12345', $3, 1024,
         '{}', '1.0.0', 'engine'
       )
       RETURNING id`,
      [fix.fileVersionId, fix.policyId, boundSha],
    );
    const decisionId = decRes.rows[0].id;

    // First promotion job succeeds
    const jobRes = await pool.query(
      `INSERT INTO promotion_jobs (decision_id) VALUES ($1) RETURNING id`,
      [decisionId],
    );
    expect(jobRes.rows[0].id).toBeTruthy();

    // Second promotion job with same decision_id must fail unique constraint
    await expect(
      pool.query(`INSERT INTO promotion_jobs (decision_id) VALUES ($1)`, [decisionId]),
    ).rejects.toThrow();
  });

  it('DB-30: Migration can be recreated from empty (reproducibility)', async () => {
    const testDb = `sug_test_${Date.now()}`;
    const client = await pool.connect();
    try {
      await client.query(`CREATE DATABASE ${testDb}`);
      const testDbUrl = getDbUrl('sug_admin', 'sug_dev_password', testDb);

      // Run migrations up on fresh database
      await runner({
        databaseUrl: testDbUrl,
        dir: resolve(process.cwd(), 'migrations'),
        direction: 'up',
        migrationsTable: 'pgmigrations',
        verbose: false,
        singleTransaction: true,
        schema: 'public',
      });

      // Verify tables in fresh database
      const testPool = new pg.Pool({ connectionString: testDbUrl });
      const tblRes = await testPool.query(`
        SELECT count(*)::int as count FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
      `);
      // 16 tables + 1 pgmigrations
      expect(tblRes.rows[0].count).toBe(17);
      await testPool.end();
    } finally {
      await client.query(`DROP DATABASE IF EXISTS ${testDb}`);
      client.release();
    }
  });
});
