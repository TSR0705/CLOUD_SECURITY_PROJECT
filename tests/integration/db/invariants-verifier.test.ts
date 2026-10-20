import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import type pg from 'pg';
import { createPool, createBaseFixtures, type FixtureContext } from './helpers.js';
import { verifyInvariants } from '../../../scripts/run-invariants.js';

describe('Canonical SQL Invariants Verifier (invariants.sql)', () => {
  let pool: pg.Pool;
  let fix: FixtureContext;

  beforeAll(async () => {
    pool = createPool('sug_admin');
    fix = await createBaseFixtures(pool);
  });

  afterAll(async () => {
    await pool.end();
  });

  it('passes all 16 canonical security and consistency invariants against current database', async () => {
    const report = await verifyInvariants(pool);
    expect(report.ok).toBe(true);
    expect(report.totalViolations).toBe(0);
    expect(report.totalChecks).toBe(16);

    for (const check of report.checks) {
      expect(check.violations).toBe(0);
    }
  });

  it('detects and flags deliberate orphan clean object violation (INV-01A)', async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Insert an unapproved clean object with no ALLOW decision
      const fakeSha = crypto.createHash('sha256').update('unapproved').digest();
      await client.query(
        `INSERT INTO cloud_objects (
           file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes, sha256_plain
         )
         VALUES ($1, 'clean', 'aws', 'sug-clean-local', 'clean/unapproved-test', 'v-orphan-test', 100, $2)`,
        [fix.fileVersionId, fakeSha],
      );

      // Invariants verifier must catch the orphan clean object
      const report = await verifyInvariants(client as unknown as pg.Pool);
      expect(report.ok).toBe(false);
      expect(report.totalViolations).toBeGreaterThan(0);

      const inv01a = report.checks.find((c) => c.invariant_id === 'INV-01A');
      expect(inv01a).toBeDefined();
      expect(inv01a?.violations).toBeGreaterThan(0);
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }

    // Clean state restored
    const postReport = await verifyInvariants(pool);
    expect(postReport.ok).toBe(true);
    expect(postReport.totalViolations).toBe(0);
  });

  it('detects and flags multi-tenant application_id mismatch violation (INV-04A)', async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Create second application
      const appRes = await client.query(
        `INSERT INTO applications (name, owner_user_id) VALUES ('other-app', $1) RETURNING id`,
        [fix.userId],
      );
      const otherAppId = appRes.rows[0].id;

      // Create a fresh upload session under fix.appId
      const sessRes = await client.query(
        `INSERT INTO upload_sessions (
           application_id, api_key_id, policy_id, original_filename, declared_mime,
           declared_size, token_jti, expires_at
         )
         VALUES ($1, $2, $3, 'cross.pdf', 'application/pdf', 100, $4, now() + interval '1 hour')
         RETURNING id`,
        [fix.appId, fix.apiKeyId, fix.policyId, crypto.randomUUID()],
      );
      const newSessionId = sessRes.rows[0].id;

      // Create a file pointing to session from fix.appId, but belonging to otherAppId
      await client.query(
        `INSERT INTO files (application_id, upload_session_id, display_filename)
         VALUES ($1, $2, 'cross-tenant.pdf')`,
        [otherAppId, newSessionId],
      );

      const report = await verifyInvariants(client as unknown as pg.Pool);
      expect(report.ok).toBe(false);

      const inv04a = report.checks.find((c) => c.invariant_id === 'INV-04A');
      expect(inv04a).toBeDefined();
      expect(inv04a?.violations).toBeGreaterThan(0);
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }

    // Clean state restored
    const postReport = await verifyInvariants(pool);
    expect(postReport.ok).toBe(true);
    expect(postReport.totalViolations).toBe(0);
  });
});
