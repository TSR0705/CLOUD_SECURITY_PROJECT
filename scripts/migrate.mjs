import { runner } from 'node-pg-migrate';
import { resolve } from 'node:path';

const action = process.argv[2] || 'up';
const defaultPort = process.env.POSTGRES_PORT || (process.env.CI ? '5432' : '5433');
const databaseUrl =
  process.env.DATABASE_URL || `postgres://sug_admin:sug_dev_password@localhost:${defaultPort}/sug`;
const migrationsDir = resolve(process.cwd(), 'migrations');

async function main() {
  const direction = action === 'down' || action === 'rollback' ? 'down' : 'up';
  const count = process.argv[3] ? parseInt(process.argv[3], 10) : undefined;

  console.log(`[migrate] Running migrations ${direction} on ${databaseUrl}...`);

  const results = await runner({
    databaseUrl,
    dir: migrationsDir,
    direction,
    count: count ?? (direction === 'down' ? 1 : undefined),
    migrationsTable: 'pgmigrations',
    verbose: true,
    singleTransaction: true,
    schema: 'public',
    decamelize: false,
  });

  console.log(`[migrate] Successfully completed ${results?.length ?? 0} migrations.`);
}

main().catch((err) => {
  console.error('[migrate] Failed:', err);
  process.exit(1);
});
