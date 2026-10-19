/**
 * @sug/service-scanner
 * Security analysis background worker service
 */

import pg from 'pg';
import { loadConfig, getServiceStorageCredentials } from '@sug/shared/config';
import { createS3Provider } from '@sug/storage';
import { ClamAvScanner, YaraScanner } from '@sug/scanner';
import { ScannerWorker } from './worker.js';

export const Service_ScannerPackageName = '@sug/service-scanner' as const;

export interface Service_ScannerInfo {
  name: typeof Service_ScannerPackageName;
  version: string;
}

export const Service_ScannerInfo: Service_ScannerInfo = {
  name: Service_ScannerPackageName,
  version: '0.1.0',
};

export interface ScannerRunnerOptions {
  pool?: pg.Pool;
  worker?: ScannerWorker;
}

export async function startScanner(options: ScannerRunnerOptions = {}): Promise<ScannerWorker> {
  const config = loadConfig();
  const dbUser = process.env.POSTGRES_USER ?? 'sug_scanner';
  const dbPass =
    process.env.SUG_DB_PASSWORD ??
    process.env.POSTGRES_PASSWORD ??
    config.secrets.dbPassword ??
    'sug_scanner_dev_password';
  const dbHost = process.env.POSTGRES_HOST ?? config.database.host;
  const dbPort = process.env.POSTGRES_PORT
    ? parseInt(process.env.POSTGRES_PORT, 10)
    : config.database.port;
  const dbName = process.env.POSTGRES_DB ?? config.database.name;

  const dbUrl =
    process.env.DATABASE_URL ?? `postgres://${dbUser}:${dbPass}@${dbHost}:${dbPort}/${dbName}`;
  const pool = options.pool ?? new pg.Pool({ connectionString: dbUrl });

  const storageCreds = getServiceStorageCredentials(config, 'scanner');
  const storageProvider = createS3Provider({
    endpoint: config.storage.s3.endpoint,
    region: config.storage.s3.region,
    credentials: {
      accessKeyId: storageCreds.accessKeyId,
      secretAccessKey: storageCreds.secretAccessKey ?? '',
    },
    forcePathStyle: true,
  });

  const clamavHost = process.env.CLAMAV_HOST ?? 'localhost';
  const clamavPort = parseInt(process.env.CLAMAV_PORT ?? '3310', 10);
  const clamavScanner = new ClamAvScanner({ host: clamavHost, port: clamavPort });
  const yaraScanner = new YaraScanner();

  const worker =
    options.worker ??
    new ScannerWorker({
      db: pool,
      storageProvider,
      clamavScanner,
      enableClamAv: true,
      yaraScanner,
      enableYara: true,
      enableArchive: true,
      enableFormatChecks: true,
      ...(process.env.YARA_RULES_PATH ? { rulesDir: process.env.YARA_RULES_PATH } : {}),
    });

  worker.start();

  const shutdown = async () => {
    try {
      await worker.stop();
      await pool.end();
      process.exit(0);
    } catch {
      process.exit(1);
    }
  };

  process.once('SIGTERM', () => void shutdown());
  process.once('SIGINT', () => void shutdown());

  return worker;
}

export * from './worker.js';

const isMain =
  process.argv[1] && (process.argv[1].endsWith('index.js') || process.argv[1].endsWith('index.ts'));
if (isMain) {
  startScanner().catch((err) => {
    console.error('Fatal scanner startup error:', err);
    process.exit(1);
  });
}
