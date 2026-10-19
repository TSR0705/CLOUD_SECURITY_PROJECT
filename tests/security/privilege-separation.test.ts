import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
interface ParsedServiceConfig {
  networks: string[];
  ports: string[];
  cap_drop: string[];
  security_opt: string[];
  tmpfs: string[];
  secrets: string[];
  container_name?: string;
  restart?: string;
  read_only?: boolean;
  user?: string;
  healthcheck?: {
    test?: unknown;
    interval?: string;
    timeout?: string;
    retries?: string;
    start_period?: string;
    [k: string]: unknown;
  };
  [key: string]: unknown;
}

interface ParsedNetworkConfig {
  internal?: boolean;
  [key: string]: unknown;
}

interface ParsedCompose {
  services: Record<string, ParsedServiceConfig>;
  networks: Record<string, ParsedNetworkConfig>;
  volumes: Record<string, unknown>;
  secrets: Record<string, unknown>;
}

function parseComposeYaml(yamlStr: string): ParsedCompose {
  const result: ParsedCompose = {
    services: {},
    networks: {},
    volumes: {},
    secrets: {},
  };
  const lines = yamlStr.split('\n');

  let currentTop: string | null = null;
  let currentService: string | null = null;
  let currentNetwork: string | null = null;
  let currentField: string | null = null;

  for (const rawLine of lines) {
    const commentIdx = rawLine.indexOf('#');
    const line = commentIdx >= 0 ? rawLine.slice(0, commentIdx) : rawLine;
    if (!line.trim()) continue;

    const indent = line.search(/\S/);
    const trimmed = line.trim();

    if (indent === 0) {
      if (trimmed.startsWith('services:')) currentTop = 'services';
      else if (trimmed.startsWith('networks:')) currentTop = 'networks';
      else if (trimmed.startsWith('volumes:')) currentTop = 'volumes';
      else if (trimmed.startsWith('secrets:')) currentTop = 'secrets';
      else currentTop = null;
      currentService = null;
      currentNetwork = null;
      currentField = null;
    } else if (indent === 2 && currentTop === 'services') {
      const match = trimmed.match(/^([^:]+):$/);
      if (match) {
        currentService = match[1]!;
        result.services[currentService] = {
          networks: [],
          ports: [],
          cap_drop: [],
          security_opt: [],
          tmpfs: [],
          secrets: [],
        };
        currentField = null;
      }
    } else if (indent === 2 && currentTop === 'networks') {
      const match = trimmed.match(/^([^:]+):$/);
      if (match) {
        currentNetwork = match[1]!;
        result.networks[currentNetwork] = {};
        currentField = null;
      }
    } else if (indent === 4 && currentTop === 'networks' && currentNetwork) {
      const [k, ...v] = trimmed.split(':');
      const val = v.join(':').trim();
      result.networks[currentNetwork][k!.trim()] =
        val === 'true' ? true : val === 'false' ? false : val;
    } else if (indent === 4 && currentTop === 'services' && currentService) {
      const [k, ...v] = trimmed.split(':');
      const key = k!.trim();
      const val = v.join(':').trim();
      currentField = key;
      if (val === '') {
        // e.g. networks: or ports:
      } else if (val === 'true') {
        result.services[currentService][key] = true;
      } else if (val === 'false') {
        result.services[currentService][key] = false;
      } else {
        result.services[currentService][key] = val.replace(/^['"]|['"]$/g, '');
      }
    } else if (indent === 6 && currentTop === 'services' && currentService && currentField) {
      if (currentField === 'healthcheck') {
        const [hk, ...hv] = trimmed.split(':');
        const hkey = hk!.trim();
        const hval = hv.join(':').trim();
        if (!result.services[currentService].healthcheck) {
          result.services[currentService].healthcheck = {};
        }
        if (hkey === 'test' && hval.startsWith('[')) {
          try {
            result.services[currentService].healthcheck.test = JSON.parse(hval.replace(/'/g, '"'));
          } catch {
            result.services[currentService].healthcheck.test = hval;
          }
        } else {
          result.services[currentService].healthcheck[hkey] = hval;
        }
      } else if (currentField === 'secrets') {
        const item = trimmed.replace(/^-\s*/, '').trim();
        if (item.startsWith('source:')) {
          result.services[currentService].secrets.push(
            item
              .replace(/^source:\s*/, '')
              .trim()
              .replace(/^['"]|['"]$/g, ''),
          );
        } else if (item.startsWith('mode:') || item.startsWith('target:')) {
          // attribute of previous secret object
        } else {
          result.services[currentService].secrets.push(item.replace(/^['"]|['"]$/g, ''));
        }
      } else if (trimmed.startsWith('- ')) {
        const item = trimmed
          .slice(2)
          .trim()
          .replace(/^['"]|['"]$/g, '');
        if (Array.isArray(result.services[currentService][currentField])) {
          result.services[currentService][currentField].push(item);
        }
      }
    }
  }

  return result;
}
import { execSync } from 'node:child_process';
import type pg from 'pg';
import { createPool, createBaseFixtures, type FixtureContext } from '../integration/db/helpers.js';
import { loadConfig, getServiceStorageCredentials, redactConfig } from '@sug/shared/config';
import { createS3Provider } from '@sug/storage';

describe('Phase P22: Local Privilege Separation & Blast-Radius Mitigation', () => {
  let adminPool: pg.Pool;
  let apiPool: pg.Pool;
  let scannerPool: pg.Pool;
  let promoterPool: pg.Pool;
  let replicatorPool: pg.Pool;
  let auditorPool: pg.Pool;
  let fix: FixtureContext;

  beforeAll(async () => {
    adminPool = createPool('sug_admin', 'sug_dev_password');
    apiPool = createPool('sug_api', 'sug_api_dev_password');
    scannerPool = createPool('sug_scanner', 'sug_scanner_dev_password');
    promoterPool = createPool('sug_promoter', 'sug_promoter_dev_password');
    replicatorPool = createPool('sug_replicator', 'sug_replicator_dev_password');
    auditorPool = createPool('sug_auditor', 'sug_auditor_dev_password');

    fix = await createBaseFixtures(adminPool);
  });

  afterAll(async () => {
    if (fix) {
      let client: pg.PoolClient | undefined;
      try {
        client = await adminPool.connect();
        // Administrator-privileged session configuration strictly scoped to test teardown.
        // This is never an application runtime path and is used solely to clean up test fixtures.
        await client.query("SET session_replication_role = 'replica'");
        await client.query(`DELETE FROM cloud_objects WHERE file_version_id = $1`, [
          fix.fileVersionId,
        ]);
        await client.query(
          `DELETE FROM promotion_jobs WHERE decision_id IN (SELECT id FROM security_decisions WHERE file_version_id = $1)`,
          [fix.fileVersionId],
        );
        await client.query(`DELETE FROM scan_results WHERE file_version_id = $1`, [
          fix.fileVersionId,
        ]);
        await client.query(`DELETE FROM scan_jobs WHERE file_version_id = $1`, [fix.fileVersionId]);
        await client.query(`DELETE FROM security_decisions WHERE file_version_id = $1`, [
          fix.fileVersionId,
        ]);
        await client.query(`UPDATE files SET current_version_id = NULL WHERE id = $1`, [
          fix.fileId,
        ]);
        await client.query(`DELETE FROM file_versions WHERE file_id = $1`, [fix.fileId]);
        await client.query(`DELETE FROM files WHERE id = $1`, [fix.fileId]);
        await client.query(`DELETE FROM upload_sessions WHERE id = $1`, [fix.sessionId]);
        await client.query(`UPDATE applications SET active_policy_id = NULL WHERE id = $1`, [
          fix.appId,
        ]);
        await client.query(`DELETE FROM security_policies WHERE application_id = $1`, [fix.appId]);
        await client.query(`DELETE FROM api_keys WHERE application_id = $1`, [fix.appId]);
        await client.query(`DELETE FROM applications WHERE id = $1`, [fix.appId]);
        await client.query(`DELETE FROM users WHERE id = $1`, [fix.userId]);
      } catch (err) {
        console.warn('Failed to clean up test fixtures in privilege-separation test:', err);
      } finally {
        if (client) {
          try {
            await client.query("SET session_replication_role = 'origin'");
          } catch {
            // Ignore rollback errors during pool release
          }
          client.release();
        }
      }
    }

    await Promise.all([
      adminPool.end(),
      apiPool.end(),
      scannerPool.end(),
      promoterPool.end(),
      replicatorPool.end(),
      auditorPool.end(),
    ]);
  });

  // =========================================================================
  // 1. PostgreSQL Role Privilege Matrix (ADR-0004 & DEC-003)
  // =========================================================================
  describe('1. PostgreSQL Role Least Privilege Matrix', () => {
    describe('sug_scanner — Compromised Scanner Containment', () => {
      let scanJobId: string;

      beforeAll(async () => {
        const res = await adminPool.query(
          `INSERT INTO scan_jobs (file_version_id, status) VALUES ($1, 'QUEUED') RETURNING id`,
          [fix.fileVersionId],
        );
        scanJobId = res.rows[0].id;
      });

      it('ALLOWED: can query scan_jobs and update execution lease', async () => {
        const res = await scannerPool.query(`SELECT id, status FROM scan_jobs WHERE id = $1`, [
          scanJobId,
        ]);
        expect(res.rows.length).toBe(1);

        const updateRes = await scannerPool.query(
          `UPDATE scan_jobs SET status = 'RUNNING', locked_by = 'test-worker' WHERE id = $1 RETURNING status`,
          [scanJobId],
        );
        expect(updateRes.rows[0].status).toBe('RUNNING');
      });

      it('ALLOWED: can insert scan_results for its assigned job', async () => {
        const dummySha = crypto.randomBytes(32);
        const res = await scannerPool.query(
          `INSERT INTO scan_results (
             scan_job_id, file_version_id, check_id, engine, engine_version,
             outcome, severity, confidence, evidence, scanned_storage_version_id, scanned_sha256, scanned_size
           )
           VALUES ($1, $2, 'chk-clamav', 'clamav', '1.4.6', 'PASS', 'INFO', 'CONFIRMED', '{}', 'v1', $3, 1024)
           RETURNING id`,
          [scanJobId, fix.fileVersionId, dummySha],
        );
        expect(res.rows[0].id).toBeTruthy();
      });

      it('ALLOWED: can query scan_results, file_versions, upload_sessions, security_policies', async () => {
        const srRes = await scannerPool.query(
          `SELECT id FROM scan_results WHERE scan_job_id = $1`,
          [scanJobId],
        );
        expect(srRes.rows.length).toBeGreaterThan(0);

        const fvRes = await scannerPool.query(`SELECT id FROM file_versions WHERE id = $1`, [
          fix.fileVersionId,
        ]);
        expect(fvRes.rows.length).toBe(1);

        const sessRes = await scannerPool.query(`SELECT id FROM upload_sessions WHERE id = $1`, [
          fix.sessionId,
        ]);
        expect(sessRes.rows.length).toBe(1);

        const polRes = await scannerPool.query(`SELECT id FROM security_policies WHERE id = $1`, [
          fix.policyId,
        ]);
        expect(polRes.rows.length).toBe(1);
      });

      it('ALLOWED: can append immutable audit records via audit_append()', async () => {
        const res = await scannerPool.query(
          `SELECT audit_append('service', 'sug-scanner', 'scan.started', '{"jobId":"${scanJobId}"}', '{}') as seq`,
        );
        expect(Number(res.rows[0].seq)).toBeGreaterThan(0);
      });

      it('DENIED: cannot insert security_decisions (cannot decide its own verdict)', async () => {
        const dummySha = crypto.createHash('sha256').update('dummy').digest();
        await expect(
          scannerPool.query(
            `INSERT INTO security_decisions (
               file_version_id, policy_id, decision, primary_reason, severity, confidence,
               risk_score, policy_result, scanner_result, integrity_result, authorization_result,
               bound_bucket, bound_key, bound_storage_version_id, bound_sha256, bound_size,
               record, engine_version, decided_by
             )
             VALUES (
               $1, $2, 'ALLOW', 'Scanner forged decision', 'INFO', 'CONFIRMED',
               0, 'PASS', 'PASS', 'MATCH', 'AUTHORIZED',
               'sug-quarantine', 'key', 'v1', $3, 1024,
               '{}', '1.0.0', 'compromised-scanner'
             )`,
            [fix.fileVersionId, fix.policyId, dummySha],
          ),
        ).rejects.toThrow(/permission denied/);
      });

      it('DENIED: cannot insert promotion_jobs (cannot trigger promotion)', async () => {
        await expect(
          scannerPool.query(
            `INSERT INTO promotion_jobs (decision_id) VALUES ('018f0000-0000-7000-8000-000000000001')`,
          ),
        ).rejects.toThrow(/permission denied/);
      });

      it('DENIED: cannot insert or update cloud_objects (cannot write clean records)', async () => {
        await expect(
          scannerPool.query(
            `INSERT INTO cloud_objects (
               file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes
             )
             VALUES ($1, 'clean', 'aws', 'sug-clean-local', 'clean/key', 'v1', 1024)`,
            [fix.fileVersionId],
          ),
        ).rejects.toThrow(/permission denied/);
      });

      it('DENIED: cannot insert, update, or delete files', async () => {
        await expect(
          scannerPool.query(`UPDATE files SET status = 'PROMOTED' WHERE id = $1`, [fix.fileId]),
        ).rejects.toThrow(/permission denied/);

        await expect(
          scannerPool.query(`DELETE FROM files WHERE id = $1`, [fix.fileId]),
        ).rejects.toThrow(/permission denied/);
      });

      it('DENIED: cannot access sensitive user or authentication tables', async () => {
        await expect(scannerPool.query(`SELECT * FROM users`)).rejects.toThrow(/permission denied/);
        await expect(scannerPool.query(`SELECT * FROM api_keys`)).rejects.toThrow(
          /permission denied/,
        );
        await expect(scannerPool.query(`SELECT * FROM refresh_tokens`)).rejects.toThrow(
          /permission denied/,
        );
        await expect(scannerPool.query(`SELECT * FROM applications`)).rejects.toThrow(
          /permission denied/,
        );
      });

      it('DENIED: cannot create or insert audit_checkpoints', async () => {
        const dummyHash = crypto.randomBytes(32);
        const dummySig = crypto.randomBytes(64);
        await expect(
          scannerPool.query(
            `INSERT INTO audit_checkpoints (last_seq, chain_hash, signature) VALUES (999999, $1, $2)`,
            [dummyHash, dummySig],
          ),
        ).rejects.toThrow(/permission denied/);
      });

      it('DENIED: scanner lacks UPDATE/DELETE on scan_results, and table is immutable via trigger', async () => {
        // sug_scanner lacks UPDATE/DELETE grants
        await expect(
          scannerPool.query(`UPDATE scan_results SET outcome = 'PASS' WHERE scan_job_id = $1`, [
            scanJobId,
          ]),
        ).rejects.toThrow(/permission denied/);

        await expect(
          scannerPool.query(`DELETE FROM scan_results WHERE scan_job_id = $1`, [scanJobId]),
        ).rejects.toThrow(/permission denied/);

        // sug_admin (with table grants) is blocked by append-only trigger
        await expect(
          adminPool.query(`UPDATE scan_results SET outcome = 'PASS' WHERE scan_job_id = $1`, [
            scanJobId,
          ]),
        ).rejects.toThrow(/scan_results is append-only/);

        await expect(
          adminPool.query(`DELETE FROM scan_results WHERE scan_job_id = $1`, [scanJobId]),
        ).rejects.toThrow(/scan_results is append-only/);
      });
    });

    describe('sug_api — Edge API Least Privilege', () => {
      it('ALLOWED: can manage upload sessions and create files', async () => {
        const jti = crypto.randomUUID();
        const expiresAt = new Date(Date.now() + 600000);
        const sessRes = await apiPool.query(
          `INSERT INTO upload_sessions (
             application_id, api_key_id, policy_id, original_filename, declared_mime,
             declared_size, token_jti, expires_at
           )
           VALUES ($1, $2, $3, 'test.pdf', 'application/pdf', 1024, $4, $5)
           RETURNING id`,
          [fix.appId, fix.apiKeyId, fix.policyId, jti, expiresAt],
        );
        expect(sessRes.rows[0].id).toBeTruthy();
      });

      it('ALLOWED: can execute audit_checkpoint_create via SECURITY DEFINER function', async () => {
        const client = await apiPool.connect();
        try {
          await client.query('BEGIN');
          // Find existing latest audit seq and hash
          const evRes = await client.query(
            `SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1`,
          );
          const latestSeq = Number(evRes.rows[0].seq);
          const latestHash = evRes.rows[0].event_hash;
          const dummySig = crypto.randomBytes(64);

          const chkRes = await client.query(
            `SELECT audit_checkpoint_create($1, $2, $3, $4, $5) as id`,
            [crypto.randomUUID(), latestSeq, latestHash, dummySig, 's3-ver-test'],
          );
          expect(chkRes.rows[0].id).toBeTruthy();
          await client.query('ROLLBACK');
        } finally {
          client.release();
        }
      });

      it('DENIED: cannot directly INSERT into audit_checkpoints table', async () => {
        const dummyHash = crypto.randomBytes(32);
        const dummySig = crypto.randomBytes(64);
        await expect(
          apiPool.query(
            `INSERT INTO audit_checkpoints (last_seq, chain_hash, signature) VALUES (888888, $1, $2)`,
            [dummyHash, dummySig],
          ),
        ).rejects.toThrow(/permission denied/);
      });

      it('DENIED: cannot insert security_decisions, promotion_jobs, or cloud_objects', async () => {
        const dummySha = crypto.randomBytes(32);
        await expect(
          apiPool.query(
            `INSERT INTO security_decisions (
               file_version_id, policy_id, decision, primary_reason, severity, confidence,
               risk_score, policy_result, scanner_result, integrity_result, authorization_result,
               bound_bucket, bound_key, bound_storage_version_id, bound_sha256, bound_size,
               record, engine_version, decided_by
             )
             VALUES (
               $1, $2, 'ALLOW', 'API bypass', 'INFO', 'CONFIRMED',
               0, 'PASS', 'PASS', 'MATCH', 'AUTHORIZED',
               'sug-quarantine', 'key', 'v1', $3, 1024,
               '{}', '1.0.0', 'api'
             )`,
            [fix.fileVersionId, fix.policyId, dummySha],
          ),
        ).rejects.toThrow(/permission denied/);

        await expect(
          apiPool.query(
            `INSERT INTO promotion_jobs (decision_id) VALUES ('018f0000-0000-7000-8000-000000000002')`,
          ),
        ).rejects.toThrow(/permission denied/);

        await expect(
          apiPool.query(
            `INSERT INTO cloud_objects (file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes)
             VALUES ($1, 'clean', 'aws', 'sug-clean-local', 'clean/key', 'v1', 1024)`,
            [fix.fileVersionId],
          ),
        ).rejects.toThrow(/permission denied/);
      });

      it('DENIED: cannot delete users or update user password_hash / role', async () => {
        await expect(
          apiPool.query(`DELETE FROM users WHERE id = $1`, [fix.userId]),
        ).rejects.toThrow(/permission denied/);

        await expect(
          apiPool.query(`UPDATE users SET password_hash = 'tampered' WHERE id = $1`, [fix.userId]),
        ).rejects.toThrow(/permission denied/);

        await expect(
          apiPool.query(`UPDATE users SET role = 'admin' WHERE id = $1`, [fix.userId]),
        ).rejects.toThrow(/permission denied/);
      });
    });

    describe('sug_promoter — Promotion Engine Least Privilege', () => {
      let decisionId: string;

      beforeAll(async () => {
        const boundSha = crypto.randomBytes(32);
        const decRes = await promoterPool.query(
          `INSERT INTO security_decisions (
             file_version_id, policy_id, decision, primary_reason, severity, confidence,
             risk_score, policy_result, scanner_result, integrity_result, authorization_result,
             bound_bucket, bound_key, bound_storage_version_id, bound_sha256, bound_size,
             record, engine_version, decided_by
           )
           VALUES (
             $1, $2, 'ALLOW', 'Promoter Test', 'INFO', 'CONFIRMED',
             0, 'PASS', 'PASS', 'MATCH', 'AUTHORIZED',
             'sug-quarantine-local', 'key', 'v1', $3, 1024,
             '{}', '1.0.0', 'decision-engine'
           )
           RETURNING id`,
          [fix.fileVersionId, fix.policyId, boundSha],
        );
        decisionId = decRes.rows[0].id;
      });

      it('ALLOWED: can create promotion jobs and insert clean cloud_objects', async () => {
        const jobRes = await promoterPool.query(
          `INSERT INTO promotion_jobs (decision_id) VALUES ($1) RETURNING id`,
          [decisionId],
        );
        expect(jobRes.rows[0].id).toBeTruthy();

        const uniqueCleanKey = `clean/promoted-${crypto.randomUUID()}`;
        const uniqueCleanVer = `v-${crypto.randomUUID()}`;
        const coRes = await promoterPool.query(
          `INSERT INTO cloud_objects (
             file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes
           )
           VALUES ($1, 'clean', 'aws', 'sug-clean-local', $2, $3, 1024)
           RETURNING id`,
          [fix.fileVersionId, uniqueCleanKey, uniqueCleanVer],
        );
        expect(coRes.rows[0].id).toBeTruthy();
      });

      it('ALLOWED: can update file status to PROMOTED', async () => {
        const res = await promoterPool.query(
          `UPDATE files SET status = 'PROMOTED' WHERE id = $1 RETURNING status`,
          [fix.fileId],
        );
        expect(res.rows[0].status).toBe('PROMOTED');
      });

      it('DENIED: cannot query or modify user credentials or refresh tokens', async () => {
        await expect(promoterPool.query(`SELECT * FROM users`)).rejects.toThrow(
          /permission denied/,
        );
        await expect(promoterPool.query(`SELECT * FROM api_keys`)).rejects.toThrow(
          /permission denied/,
        );
        await expect(promoterPool.query(`SELECT * FROM refresh_tokens`)).rejects.toThrow(
          /permission denied/,
        );
      });

      it('DENIED: cannot insert scan results or direct audit checkpoints', async () => {
        const dummySha = crypto.randomBytes(32);
        await expect(
          promoterPool.query(
            `INSERT INTO scan_results (
               scan_job_id, file_version_id, check_id, engine, outcome,
               scanned_storage_version_id, scanned_sha256, scanned_size
             )
             VALUES ('018f0000-0000-7000-8000-000000000003', $1, 'p', '1.0', 'PASS', 'v1', $2, 1024)`,
            [fix.fileVersionId, dummySha],
          ),
        ).rejects.toThrow(/permission denied/);

        const dummyHash = crypto.randomBytes(32);
        const dummySig = crypto.randomBytes(64);
        await expect(
          promoterPool.query(
            `INSERT INTO audit_checkpoints (last_seq, chain_hash, signature) VALUES (777777, $1, $2)`,
            [dummyHash, dummySig],
          ),
        ).rejects.toThrow(/permission denied/);
      });
    });

    describe('sug_replicator — Replicator Least Privilege & RLS Enforcement', () => {
      it('ALLOWED: can insert replica zone cloud_objects', async () => {
        const uniqueKey = `replica/${crypto.randomUUID()}`;
        const coRes = await replicatorPool.query(
          `INSERT INTO cloud_objects (
             file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes
           )
           VALUES ($1, 'replica', 'gcp', 'sug-replica-local', $2, 'gen-12345', 1024)
           RETURNING id`,
          [fix.fileVersionId, uniqueKey],
        );
        expect(coRes.rows[0].id).toBeTruthy();
      });

      it('DENIED: cannot insert clean or quarantine zone cloud_objects (enforced by RLS)', async () => {
        const uniqueCleanKey = `clean/unauthorized-${crypto.randomUUID()}`;
        await expect(
          replicatorPool.query(
            `INSERT INTO cloud_objects (
               file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes
             )
             VALUES ($1, 'clean', 'aws', 'sug-clean-local', $2, 'ver-unauth', 1024)`,
            [fix.fileVersionId, uniqueCleanKey],
          ),
        ).rejects.toThrow(/row-level security policy for table "cloud_objects"/);

        const uniqueQuarKey = `quarantine/unauthorized-${crypto.randomUUID()}`;
        await expect(
          replicatorPool.query(
            `INSERT INTO cloud_objects (
               file_version_id, zone, provider, bucket, object_key, storage_version_id, size_bytes
             )
             VALUES ($1, 'quarantine', 'aws', 'sug-quarantine-local', $2, 'ver-unauth', 1024)`,
            [fix.fileVersionId, uniqueQuarKey],
          ),
        ).rejects.toThrow(/row-level security policy for table "cloud_objects"/);
      });

      it('DENIED: cannot insert direct audit checkpoints (revoked in 014)', async () => {
        const dummyHash = crypto.randomBytes(32);
        const dummySig = crypto.randomBytes(64);
        await expect(
          replicatorPool.query(
            `INSERT INTO audit_checkpoints (last_seq, chain_hash, signature) VALUES (666666, $1, $2)`,
            [dummyHash, dummySig],
          ),
        ).rejects.toThrow(/permission denied/);
      });

      it('DENIED: cannot modify scan_jobs, security_decisions, or files', async () => {
        await expect(
          replicatorPool.query(`UPDATE files SET status = 'QUARANTINED' WHERE id = $1`, [
            fix.fileId,
          ]),
        ).rejects.toThrow(/permission denied/);

        await expect(
          replicatorPool.query(`DELETE FROM security_decisions WHERE id = $1`, [
            '018f0000-0000-7000-8000-000000000001',
          ]),
        ).rejects.toThrow(/permission denied/);
      });
    });

    describe('sug_auditor — Read-Only Auditor Boundaries', () => {
      it('ALLOWED: can query all operational, scan, decision, and audit tables', async () => {
        const filesRes = await auditorPool.query(`SELECT count(*)::int as count FROM files`);
        expect(filesRes.rows[0].count).toBeGreaterThan(0);

        const decRes = await auditorPool.query(
          `SELECT count(*)::int as count FROM security_decisions`,
        );
        expect(decRes.rows[0].count).toBeGreaterThan(0);

        const auditRes = await auditorPool.query(`SELECT count(*)::int as count FROM audit_events`);
        expect(auditRes.rows[0].count).toBeGreaterThan(0);

        const chkRes = await auditorPool.query(
          `SELECT count(*)::int as count FROM audit_checkpoints`,
        );
        expect(chkRes.rows[0].count).toBeGreaterThan(0);
      });

      it('ALLOWED: can query non-sensitive columns on users and api_keys', async () => {
        const userRes = await auditorPool.query(
          `SELECT id, email, role, is_active, created_at FROM users WHERE id = $1`,
          [fix.userId],
        );
        expect(userRes.rows.length).toBe(1);

        const keyRes = await auditorPool.query(
          `SELECT id, application_id, key_prefix, scopes FROM api_keys WHERE id = $1`,
          [fix.apiKeyId],
        );
        expect(keyRes.rows.length).toBe(1);
      });

      it('DENIED: cannot select users.password_hash or api_keys.key_hmac', async () => {
        await expect(auditorPool.query(`SELECT password_hash FROM users`)).rejects.toThrow(
          /permission denied/,
        );

        await expect(auditorPool.query(`SELECT key_hmac FROM api_keys`)).rejects.toThrow(
          /permission denied/,
        );
      });

      it('DENIED: cannot access refresh_tokens table', async () => {
        await expect(auditorPool.query(`SELECT * FROM refresh_tokens`)).rejects.toThrow(
          /permission denied/,
        );
      });

      it('DENIED: zero write permissions across entire database', async () => {
        await expect(
          auditorPool.query(
            `INSERT INTO applications (name, owner_user_id) VALUES ('auditor-app', $1)`,
            [fix.userId],
          ),
        ).rejects.toThrow(/permission denied/);

        await expect(
          auditorPool.query(`UPDATE files SET status = 'QUARANTINED' WHERE id = $1`, [fix.fileId]),
        ).rejects.toThrow(/permission denied/);

        await expect(
          auditorPool.query(`DELETE FROM upload_sessions WHERE id = $1`, [fix.sessionId]),
        ).rejects.toThrow(/permission denied/);
      });
    });
  });

  // =========================================================================
  // 2. Storage Credential Scoping & Isolation (OPEN-2 & DEC-003)
  // =========================================================================
  describe('2. Local Storage Credential Scoping & Isolation', () => {
    it('resolves distinct credentials for each pipeline service', () => {
      const config = loadConfig({
        env: {
          AWS_ACCESS_KEY_ID_API: 'sug-api-key',
          AWS_ACCESS_KEY_ID_SCANNER: 'sug-scanner-key',
          AWS_ACCESS_KEY_ID_PROMOTER: 'sug-promoter-key',
          AWS_ACCESS_KEY_ID_REPLICATOR: 'sug-replicator-key',
        },
        secretsDir: path.resolve(process.cwd(), 'secrets'),
      });

      const apiCreds = getServiceStorageCredentials(config, 'api');
      const scannerCreds = getServiceStorageCredentials(config, 'scanner');
      const promoterCreds = getServiceStorageCredentials(config, 'promoter');
      const replicatorCreds = getServiceStorageCredentials(config, 'replicator');

      expect(apiCreds.accessKeyId).toBe('sug-api-key');
      expect(scannerCreds.accessKeyId).toBe('sug-scanner-key');
      expect(promoterCreds.accessKeyId).toBe('sug-promoter-key');
      expect(replicatorCreds.accessKeyId).toBe('sug-replicator-key');

      // Verify each service receives distinct secret access keys from its dedicated secret file
      expect(apiCreds.secretAccessKey).toBeTruthy();
      expect(scannerCreds.secretAccessKey).toBeTruthy();
      expect(promoterCreds.secretAccessKey).toBeTruthy();
      expect(replicatorCreds.secretAccessKey).toBeTruthy();

      const allKeys = [
        apiCreds.accessKeyId,
        scannerCreds.accessKeyId,
        promoterCreds.accessKeyId,
        replicatorCreds.accessKeyId,
      ];
      expect(new Set(allKeys).size).toBe(4);

      const allSecrets = [
        apiCreds.secretAccessKey,
        scannerCreds.secretAccessKey,
        promoterCreds.secretAccessKey,
        replicatorCreds.secretAccessKey,
      ];
      expect(new Set(allSecrets).size).toBe(4);
    });

    it('redactConfig redacts all per-service storage secret keys', () => {
      const config = loadConfig({
        env: {
          AWS_ACCESS_KEY_ID_API: 'sug-api-key',
          AWS_ACCESS_KEY_ID_SCANNER: 'sug-scanner-key',
          AWS_ACCESS_KEY_ID_PROMOTER: 'sug-promoter-key',
          AWS_ACCESS_KEY_ID_REPLICATOR: 'sug-replicator-key',
        },
        secretsDir: path.resolve(process.cwd(), 'secrets'),
      });

      const redacted = redactConfig(config);
      expect(redacted.secrets.services?.api?.secretAccessKey).toBe('[REDACTED]');
      expect(redacted.secrets.services?.scanner?.secretAccessKey).toBe('[REDACTED]');
      expect(redacted.secrets.services?.promoter?.secretAccessKey).toBe('[REDACTED]');
      expect(redacted.secrets.services?.replicator?.secretAccessKey).toBe('[REDACTED]');
    });

    it('initializes S3 storage provider with scanner service credentials', async () => {
      const config = loadConfig({
        env: {
          AWS_ACCESS_KEY_ID_SCANNER: 'sug-scanner-key',
        },
        secretsDir: path.resolve(process.cwd(), 'secrets'),
      });

      const scannerCreds = getServiceStorageCredentials(config, 'scanner');
      const provider = createS3Provider({
        endpoint: config.storage.s3.endpoint,
        region: config.storage.s3.region,
        credentials: {
          accessKeyId: scannerCreds.accessKeyId,
          secretAccessKey: scannerCreds.secretAccessKey ?? '',
        },
        forcePathStyle: true,
      });

      expect(provider).toBeDefined();
      expect(typeof provider.getByVersion).toBe('function');
    });

    it('executes live storage authorization negative test and documents emulator IAM boundary limitations', async () => {
      const config = loadConfig({
        env: {
          AWS_ACCESS_KEY_ID_SCANNER: 'sug-scanner-key',
        },
        secretsDir: path.resolve(process.cwd(), 'secrets'),
      });

      const scannerCreds = getServiceStorageCredentials(config, 'scanner');
      const { S3Client, PutObjectCommand, GetObjectCommand } = await import('@aws-sdk/client-s3');
      const s3Scanner = new S3Client({
        endpoint: config.storage.s3.endpoint,
        region: config.storage.s3.region,
        credentials: {
          accessKeyId: scannerCreds.accessKeyId,
          secretAccessKey: scannerCreds.secretAccessKey ?? 'test',
        },
        forcePathStyle: true,
      });

      // 1. Scanner can reach quarantine storage
      let quarantineAccessible = false;
      try {
        await s3Scanner.send(
          new GetObjectCommand({
            Bucket: config.storage.s3.quarantineBucket,
            Key: 'non-existent-probe-key',
          }),
        );
      } catch (err: unknown) {
        if ((err as { name?: string }).name === 'NoSuchKey') {
          quarantineAccessible = true;
        }
      }
      expect(quarantineAccessible).toBe(true);

      // 2. Negative Test: Scanner attempts unauthorized write to clean storage
      // Under LocalStack Community (ADR-0004, DEC-003), IAM policies are not enforced.
      // This test executes the real negative request and documents whether the emulator enforced boundaries.
      let cleanWriteResult = 'UNKNOWN';
      try {
        await s3Scanner.send(
          new PutObjectCommand({
            Bucket: config.storage.s3.cleanBucket,
            Key: 'unauthorized-scanner-test.txt',
            Body: 'malicious payload',
          }),
        );
        cleanWriteResult = 'ALLOWED_BY_LOCALSTACK_COMMUNITY_NO_IAM';
      } catch (err: unknown) {
        if (
          (err as { name?: string }).name === 'AccessDenied' ||
          (err as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode === 403
        ) {
          cleanWriteResult = 'DENIED_BY_IAM';
        } else {
          cleanWriteResult = `ERROR_${(err as Error).name}`;
        }
      }

      // Verify and record the empirical reality: LocalStack Community lacks IAM enforcement.
      // Acceptance criterion for storage-level denial is recorded as blocked/unsupported locally.
      expect(cleanWriteResult).toBe('ALLOWED_BY_LOCALSTACK_COMMUNITY_NO_IAM');
    });
  });

  // =========================================================================
  // 3. Docker Compose Network Segmentation & Scanner Hardening
  // =========================================================================
  describe('3. Docker Network Segmentation & Scanner Hardening (Static & Dynamic)', () => {
    it('docker-compose.yml defines strictly segmented networks with internal scan network', () => {
      const composePath = path.resolve(process.cwd(), 'infrastructure/docker/docker-compose.yml');
      const composeContent = fs.readFileSync(composePath, 'utf8');
      const parsed = parseComposeYaml(composeContent);

      // 1. Verify networks
      expect(parsed.networks).toBeDefined();
      expect(parsed.networks.edge).toBeDefined();
      expect(parsed.networks.data).toBeDefined();
      expect(parsed.networks.store).toBeDefined();
      expect(parsed.networks.scan).toBeDefined();
      expect(parsed.networks.egress).toBeDefined();

      // Scan network MUST be internal: true
      expect(parsed.networks.scan.internal).toBe(true);

      // 2. Verify service network memberships
      // Dependencies attached to internal scan network for scanner connectivity
      expect(parsed.services.postgres.networks).toContain('data');
      expect(parsed.services.postgres.networks).toContain('scan');
      expect(parsed.services.localstack.networks).toContain('store');
      expect(parsed.services.localstack.networks).toContain('scan');
      expect(parsed.services['fake-gcs-server'].networks).toEqual(['store']);
      expect(parsed.services.clamav.networks).toContain('scan');
      expect(parsed.services.clamav.networks).not.toContain('edge'); // ClamAV removed from edge!

      // 3. Published ports bound strictly to localhost (127.0.0.1)
      expect(parsed.services.postgres.ports[0]).toMatch(/^127\.0\.0\.1:/);
      expect(parsed.services.localstack.ports[0]).toMatch(/^127\.0\.0\.1:/);
      expect(parsed.services['fake-gcs-server'].ports[0]).toMatch(/^127\.0\.0\.1:/);
      expect(parsed.services.clamav.ports[0]).toMatch(/^127\.0\.0\.1:/);

      // 4. Verify scanner service hardening configuration
      const scanner = parsed.services.scanner;
      expect(scanner).toBeDefined();
      expect(scanner.networks).toEqual(['scan']); // Scanner attached strictly to internal scan network!
      expect(scanner.networks).not.toContain('data');
      expect(scanner.networks).not.toContain('store');
      expect(scanner.networks).not.toContain('edge');
      expect(scanner.networks).not.toContain('egress');

      expect(scanner.read_only).toBe(true);
      expect(scanner.user).toBe('1000:1000');
      expect(scanner.cap_drop).toEqual(['ALL']);
      expect(scanner.security_opt).toContain('no-new-privileges:true');
      expect(scanner.tmpfs).toContain('/tmp:rw,noexec,nosuid,size=128M');
      expect(scanner.healthcheck).toBeDefined();
      expect(scanner.healthcheck.test).toEqual([
        'CMD',
        'curl',
        '-f',
        'http://127.0.0.1:3001/health',
      ]);

      // 5. Verify secrets attached to scanner
      expect(scanner.secrets).toContain('aws_secret_access_key_scanner');
      expect(scanner.secrets).toContain('db_password');
    });

    it('validates live docker container security boundaries on the actual sug-scanner container', () => {
      // Dynamic verification directly against the running sug-scanner container
      try {
        // 1. Inspect real sug-scanner container configuration
        const inspectRaw = execSync('docker inspect sug-scanner', {
          encoding: 'utf8',
          stdio: 'pipe',
        });
        const [inspectData] = JSON.parse(inspectRaw);

        expect(inspectData.State.Running).toBe(true);
        expect(inspectData.HostConfig.ReadonlyRootfs).toBe(true);
        expect(inspectData.Config.User).toBe('1000:1000');
        expect(inspectData.HostConfig.CapDrop).toContain('ALL');
        expect(inspectData.HostConfig.SecurityOpt).toContain('no-new-privileges:true');

        // Verify container is attached strictly to sug-scan (internal: true)
        const attachedNetworks = Object.keys(inspectData.NetworkSettings.Networks);
        expect(attachedNetworks).toEqual(['sug-scan']);

        // Verify healthcheck is configured
        expect(inspectData.Config.Healthcheck).toBeDefined();

        // 2. Dynamic Internet Egress Tests INSIDE actual sug-scanner container
        // Direct IP egress (1.1.1.1) MUST be blocked
        const ipOut = execSync(
          "docker exec sug-scanner node -e \"fetch('http://1.1.1.1', { signal: AbortSignal.timeout(1500) }).then(() => console.log('CONNECTED')).catch(e => console.log('BLOCKED:' + (e.cause?.code || e.message)))\"",
          { encoding: 'utf8', stdio: 'pipe' },
        );
        expect(ipOut).toMatch(/BLOCKED:(ENETUNREACH|EAI_AGAIN|UND_ERR_CONNECT_TIMEOUT)/);

        // DNS name resolution (example.com) MUST be blocked
        const dnsOut = execSync(
          "docker exec sug-scanner node -e \"fetch('http://example.com', { signal: AbortSignal.timeout(1500) }).then(() => console.log('CONNECTED')).catch(e => console.log('BLOCKED:' + (e.cause?.code || e.message)))\"",
          { encoding: 'utf8', stdio: 'pipe' },
        );
        expect(dnsOut).toMatch(/BLOCKED:(EAI_AGAIN|ENOTFOUND|ENETUNREACH|UND_ERR_CONNECT_TIMEOUT)/);

        // 3. Dynamic Internal Connectivity Tests INSIDE actual sug-scanner container
        // Reach postgres (port 5432)
        const pgOut = execSync(
          "docker exec sug-scanner node -e \"const net=require('net'); const s=net.connect(5432, 'postgres', () => { console.log('PG_OK'); s.destroy(); }); s.on('error', e => console.log('PG_ERR:' + e.message));\"",
          { encoding: 'utf8', stdio: 'pipe' },
        );
        expect(pgOut).toContain('PG_OK');

        // Reach clamav (port 3310)
        const clamOut = execSync(
          "docker exec sug-scanner node -e \"const net=require('net'); const s=net.connect(3310, 'clamav', () => { console.log('CLAM_OK'); s.destroy(); }); s.on('error', e => console.log('CLAM_ERR:' + e.message));\"",
          { encoding: 'utf8', stdio: 'pipe' },
        );
        expect(clamOut).toContain('CLAM_OK');

        // Reach localstack (port 4566)
        const s3Out = execSync(
          "docker exec sug-scanner node -e \"fetch('http://localstack:4566/_localstack/health').then(r => console.log('S3_OK')).catch(e => console.log('S3_ERR:' + e.message))\"",
          { encoding: 'utf8', stdio: 'pipe' },
        );
        expect(s3Out).toContain('S3_OK');

        // 4. Filesystem Immutability INSIDE actual sug-scanner container
        const roOut = execSync(
          "docker exec sug-scanner node -e \"const fs=require('fs'); try { fs.writeFileSync('/root-test.txt', 'x'); } catch(e) { console.log('RO_BLOCKED:' + e.code); } fs.writeFileSync('/tmp/health-test.txt', 'pass'); console.log('TMP_OK:' + fs.readFileSync('/tmp/health-test.txt', 'utf8'));\"",
          { encoding: 'utf8', stdio: 'pipe' },
        );
        expect(roOut).toContain('RO_BLOCKED:EROFS');
        expect(roOut).toContain('TMP_OK:pass');

        // 5. Capability & User verification INSIDE actual sug-scanner container
        const idOut = execSync(
          'docker exec sug-scanner node -e "console.log(\'UID:\' + process.getuid());"',
          {
            encoding: 'utf8',
            stdio: 'pipe',
          },
        );
        expect(idOut).toContain('UID:1000');

        const capOut = execSync(
          'docker exec sug-scanner sh -c "cat /proc/1/status | grep CapEff"',
          {
            encoding: 'utf8',
            stdio: 'pipe',
          },
        );
        expect(capOut).toContain('CapEff:\t0000000000000000');
      } catch (err) {
        throw new Error(
          `Live docker verification on sug-scanner failed: ${(err as Error).message}`,
        );
      }
    });
  });
});
