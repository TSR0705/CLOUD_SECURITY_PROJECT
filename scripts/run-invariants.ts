/**
 * scripts/run-invariants.ts
 * Executes canonical invariants.sql against the Secure Upload Gateway database
 * Returns exit code 0 if all invariants pass (0 violations), or exit code 1 if any violation is found.
 */

import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

export interface InvariantCheckResult {
  invariant_id: string;
  description: string;
  violations: number;
}

export interface InvariantVerificationReport {
  ok: boolean;
  totalChecks: number;
  totalViolations: number;
  checks: InvariantCheckResult[];
}

export async function verifyInvariants(pool: pg.Pool): Promise<InvariantVerificationReport> {
  const sqlPath = path.resolve(process.cwd(), 'invariants.sql');
  const sqlContent = fs.readFileSync(sqlPath, 'utf8');

  // Split into individual statements, stripping leading line comments
  const rawBlocks = sqlContent.split(';');
  const statements: string[] = [];

  for (const block of rawBlocks) {
    // Strip comments to find the actual SQL command
    const cleaned = block
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => !line.startsWith('--'))
      .join('\n')
      .trim();

    if (cleaned.length > 0 && cleaned.toUpperCase().startsWith('SELECT')) {
      statements.push(cleaned);
    }
  }

  const checks: InvariantCheckResult[] = [];
  let totalViolations = 0;

  for (const statement of statements) {
    const res = await pool.query<InvariantCheckResult>(statement);
    for (const row of res.rows) {
      const violations = Number(row.violations);
      checks.push({
        invariant_id: row.invariant_id,
        description: row.description,
        violations,
      });
      totalViolations += violations;
    }
  }

  return {
    ok: totalViolations === 0,
    totalChecks: checks.length,
    totalViolations,
    checks,
  };
}

async function main() {
  const port = process.env.POSTGRES_PORT || (process.env.CI ? '5432' : '5433');
  const host = process.env.POSTGRES_HOST || '127.0.0.1';
  const user = process.env.POSTGRES_USER || 'sug_admin';
  const password = process.env.POSTGRES_PASSWORD || 'sug_dev_password';
  const database = process.env.POSTGRES_DB || 'sug';

  const connectionString =
    process.env.DATABASE_URL || `postgres://${user}:${password}@${host}:${port}/${database}`;

  const pool = new pg.Pool({ connectionString });

  try {
    console.log(`Connecting to database at ${host}:${port}/${database}...`);
    const report = await verifyInvariants(pool);

    console.log(
      '\n================================================================================',
    );
    console.log('SECURE UPLOAD GATEWAY (SUG) — DATABASE INVARIANT VERIFICATION REPORT');
    console.log(
      '================================================================================\n',
    );

    console.log('ID'.padEnd(10) + 'VIOLATIONS'.padEnd(14) + 'STATUS'.padEnd(10) + 'DESCRIPTION');
    console.log('-'.repeat(80));

    for (const check of report.checks) {
      const status = check.violations === 0 ? '[PASS]' : '[FAIL]';
      console.log(
        check.invariant_id.padEnd(10) +
          String(check.violations).padEnd(14) +
          status.padEnd(10) +
          check.description,
      );
    }

    console.log('-'.repeat(80));
    console.log(
      `SUMMARY: ${report.totalChecks} checks evaluated | ${report.totalViolations} total violations.\n`,
    );

    if (!report.ok) {
      console.error(
        `[FATAL] Invariant verification FAILED with ${report.totalViolations} violation(s)!`,
      );
      process.exit(1);
    }

    console.log('[PASS] All database security and consistency invariants hold strictly.\n');
    process.exit(0);
  } catch (err) {
    console.error('[ERROR] Failed executing invariant checks:', err);
    process.exit(2);
  } finally {
    await pool.end();
  }
}

// Run CLI if invoked directly
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) ===
    path.resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
) {
  void main();
}
