import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../services/api/dist/app.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const openApiPath = path.join(rootDir, 'docs', 'openapi.json');

const isCheck = process.argv.includes('--check');

async function main() {
  // Provide mock dependencies and config so OpenAPI generation never requires live cloud, DB, or secrets
  const mockDb = {
    checkReachability: async () => {},
  };
  const mockStorage = {
    checkReachability: async () => {},
  };
  const mockConfig = {
    nodeEnv: 'test',
    logLevel: 'info',
    port: 3000,
    host: '0.0.0.0',
    serviceName: 'sug-api',
    database: {
      url: 'postgres://sug_admin:dummy@127.0.0.1:5432/sug',
      host: '127.0.0.1',
      port: 5432,
      user: 'sug_admin',
      name: 'sug',
    },
    storage: {
      s3: {
        endpoint: 'http://localhost:4566',
        region: 'us-east-1',
        quarantineBucket: 'sug-quarantine-local',
        cleanBucket: 'sug-clean-local',
        accessKeyId: 'test',
      },
      gcs: {
        endpoint: 'http://localhost:4443',
        replicaBucket: 'sug-replica-local',
        projectId: 'sug-local-project',
      },
      services: {
        api: { accessKeyId: 'test' },
        scanner: { accessKeyId: 'test' },
        promoter: { accessKeyId: 'test' },
        replicator: { accessKeyId: 'test' },
      },
    },
    secrets: {
      pepper: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      kek: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      jwtPrivateKey: 'dummy',
      checkpointPrivateKey: 'dummy',
    },
    toRedacted: () => ({}),
    toJSON: () => ({}),
  };

  const app = await createApp({
    config: mockConfig,
    db: mockDb,
    storage: mockStorage,
    logger: false,
  });

  await app.ready();

  const openApiSpec = app.swagger();
  const serialized = JSON.stringify(openApiSpec, null, 2) + '\n';

  await app.close();

  if (isCheck) {
    if (!fs.existsSync(openApiPath)) {
      console.error(
        `[openapi:check] FAILED: ${openApiPath} does not exist. Run 'pnpm openapi:generate' to generate it.`,
      );
      process.exit(1);
    }

    try {
      const existing = JSON.parse(fs.readFileSync(openApiPath, 'utf8'));
      const generated = JSON.parse(serialized);

      if (JSON.stringify(existing) !== JSON.stringify(generated)) {
        console.error(
          `[openapi:check] FAILED: docs/openapi.json is out of date with API route definitions. Run 'pnpm openapi:generate' to update it.`,
        );
        process.exit(1);
      }
    } catch (err) {
      console.error(`[openapi:check] FAILED to parse docs/openapi.json: ${err.message}`);
      process.exit(1);
    }

    console.log('[openapi:check] OK: docs/openapi.json is up to date.');
    process.exit(0);
  } else {
    fs.writeFileSync(openApiPath, serialized, 'utf8');
    console.log(`[openapi:generate] Successfully generated ${openApiPath}`);
  }
}

main().catch((err) => {
  console.error('[openapi] Fatal error:', err);
  process.exit(1);
});
