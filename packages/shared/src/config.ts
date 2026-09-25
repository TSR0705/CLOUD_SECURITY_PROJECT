import fs from 'node:fs';
import path from 'node:path';
import { inspect } from 'node:util';
import { z } from 'zod';

/**
 * Custom error thrown when configuration loading or secret resolution fails.
 * Guarantees that sensitive values are NEVER included in error messages or stack traces.
 */
export class ConfigurationError extends Error {
  public readonly issues: Array<{ key: string; reason: string }>;

  constructor(issues: Array<{ key: string; reason: string }>) {
    const formatted = issues.map((i) => `  - ${i.key}: ${i.reason}`).join('\n');
    super(`Configuration validation failed:\n${formatted}`);
    this.name = 'ConfigurationError';
    this.issues = issues;
  }
}

/**
 * Validates Ed25519 private keys.
 * Accepts standard PKCS#8 PEM strings (BEGIN PRIVATE KEY) or raw 32/64-byte keys.
 * NEVER prints the key value on failure.
 */
const ed25519PrivateKeySchema = z
  .string()
  .min(1, 'required secret is missing')
  .refine(
    (val) => {
      const trimmed = val.trim();
      // PEM check
      const pemPrefixStandard = ['-----', 'BEGIN ', 'PRIVATE KEY', '-----'].join('');
      const pemPrefixEd25519 = ['-----', 'BEGIN ', 'ED25519 ', 'PRIVATE KEY', '-----'].join('');
      const pemSuffixStandard = ['-----', 'END ', 'PRIVATE KEY', '-----'].join('');
      const pemSuffixEd25519 = ['-----', 'END ', 'ED25519 ', 'PRIVATE KEY', '-----'].join('');

      if (
        (trimmed.startsWith(pemPrefixStandard) || trimmed.startsWith(pemPrefixEd25519)) &&
        (trimmed.endsWith(pemSuffixStandard) || trimmed.endsWith(pemSuffixEd25519))
      ) {
        return true;
      }
      // Raw hex (32 bytes = 64 chars, 64 bytes = 128 chars)
      if (/^[0-9a-fA-F]{64}$/.test(trimmed) || /^[0-9a-fA-F]{128}$/.test(trimmed)) {
        return true;
      }
      // Raw base64 (32 bytes = 44 chars)
      if (/^[A-Za-z0-9+/]{43}=$/.test(trimmed) || /^[A-Za-z0-9+/]{86}==$/.test(trimmed)) {
        return true;
      }
      return false;
    },
    {
      message: 'must be a valid PEM-encoded or 32/64-byte Ed25519 private key',
    },
  );

/**
 * Validates the Master Key Encryption Key (KEK) for AES-256-KeyWrap (RFC 3394).
 * Must represent 256 bits (32 bytes) as 64 hex characters or 32-byte base64.
 */
const kekSchema = z
  .string()
  .min(1, 'required secret is missing')
  .refine(
    (val) => {
      const trimmed = val.trim();
      return /^[0-9a-fA-F]{64}$/.test(trimmed) || /^[A-Za-z0-9+/]{43}=$/.test(trimmed);
    },
    {
      message: 'must be a 256-bit key (64 hex characters or 32-byte base64 string)',
    },
  );

/**
 * Validates the API/key pepper for HMAC generation.
 * Cryptographic standard: generated as 32 cryptographically secure random bytes
 * (64 hex characters = 256 bits entropy) or 32-byte base64 (44 characters).
 * The schema enforces a minimum length of 32 characters.
 */
const pepperSchema = z
  .string()
  .min(1, 'required secret is missing')
  .min(
    32,
    'must be at least 32 characters (recommended: 32 random bytes as 64 hex characters for 256-bit entropy)',
  );

/**
 * Validates database password.
 */
const dbPasswordSchema = z.string().min(1, 'required secret is missing');

/**
 * Validates AWS Secret Access Key.
 */
const awsSecretAccessKeySchema = z
  .string()
  .min(1, 'required secret is missing')
  .min(4, 'must be at least 4 characters');

export interface SecretResolutionResult {
  value?: string;
  source: 'file' | 'env' | 'missing';
  error?: string;
}

/**
 * Resolves a secret following the strict precedence:
 * 1. Docker file secret: /run/secrets/<secret-name>
 * 2. Explicit environment variable: only if file secret does NOT exist.
 *
 * Rejects empty secret files and empty environment variables with explicit errors.
 */
export function resolveSecret(
  secretName: string,
  envVarNames: string[],
  secretsDir: string,
  env: Record<string, string | undefined>,
  alternateFilenames: string[] = [],
): SecretResolutionResult {
  // 1. Try Docker file secret first (primary filename + alternates)
  const candidateFiles = [secretName, ...alternateFilenames];
  for (const filename of candidateFiles) {
    const filePath = path.join(secretsDir, filename);
    if (fs.existsSync(filePath)) {
      try {
        const stats = fs.statSync(filePath);
        if (stats.isDirectory()) {
          continue;
        }
        const content = fs.readFileSync(filePath, 'utf8');
        if (content.trim().length === 0) {
          return { source: 'file', error: 'secret file is empty' };
        }
        // Trim trailing newline only, preserving internal whitespace/newlines for PEM keys
        const trimmed = content.replace(/[\r\n]+$/, '');
        return { source: 'file', value: trimmed };
      } catch (err: unknown) {
        return {
          source: 'file',
          error: `failed to read secret file: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }
  }

  // 2. Fall back to environment variables only if file secret does not exist
  for (const envVar of envVarNames) {
    if (Object.prototype.hasOwnProperty.call(env, envVar)) {
      const val = env[envVar];
      if (val === undefined || val === '') {
        return { source: 'env', error: 'secret environment variable is empty' };
      }
      return { source: 'env', value: val.trim() };
    }
  }

  return { source: 'missing' };
}

export interface ConfigOptions {
  env?: Record<string, string | undefined>;
  secretsDir?: string;
}

export interface DatabaseConfig {
  url: string;
  host: string;
  port: number;
  user: string;
  name: string;
}

export interface ServiceStorageConfig {
  accessKeyId: string;
}

export interface StorageConfig {
  s3: {
    endpoint?: string | undefined;
    region: string;
    quarantineBucket: string;
    cleanBucket: string;
    accessKeyId: string;
  };
  gcs: {
    endpoint?: string | undefined;
    replicaBucket: string;
    projectId: string;
  };
  services: {
    api: ServiceStorageConfig;
    scanner: ServiceStorageConfig;
    promoter: ServiceStorageConfig;
    replicator: ServiceStorageConfig;
  };
}

export interface ServiceStorageSecret {
  secretAccessKey?: string | undefined;
}

export interface SecretsConfig {
  pepper: string;
  kek: string;
  jwtPrivateKey: string;
  checkpointPrivateKey: string;
  dbPassword?: string | undefined;
  awsSecretAccessKey?: string | undefined;
  services?:
    | {
        api?: ServiceStorageSecret | undefined;
        scanner?: ServiceStorageSecret | undefined;
        promoter?: ServiceStorageSecret | undefined;
        replicator?: ServiceStorageSecret | undefined;
      }
    | undefined;
}

export interface ServiceStorageCredentials {
  accessKeyId: string;
  secretAccessKey?: string | undefined;
}

export type StorageServiceName = 'api' | 'scanner' | 'promoter' | 'replicator';

/**
 * Resolves effective storage credentials for a specific pipeline service.
 * Supports least-privilege per-service overrides while falling back to base credentials.
 */
export function getServiceStorageCredentials(
  config: Config | RedactedConfig,
  service: StorageServiceName,
): ServiceStorageCredentials {
  const serviceConfig = config.storage.services[service];
  const serviceSecret = config.secrets.services?.[service];
  return {
    accessKeyId: serviceConfig?.accessKeyId ?? config.storage.s3.accessKeyId,
    secretAccessKey: serviceSecret?.secretAccessKey ?? config.secrets.awsSecretAccessKey,
  };
}

export interface Config {
  nodeEnv: 'development' | 'production' | 'test';
  logLevel: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  port: number;
  host: string;
  serviceName: string;
  database: DatabaseConfig;
  storage: StorageConfig;
  secrets: SecretsConfig;
  toRedacted(): RedactedConfig;
  [inspect.custom](): string;
  toJSON(): Record<string, unknown>;
}

export interface RedactedConfig {
  nodeEnv: string;
  logLevel: string;
  port: number;
  host: string;
  serviceName: string;
  database: {
    url: string;
    host: string;
    port: number;
    user: string;
    name: string;
  };
  storage: StorageConfig;
  secrets: {
    pepper: string;
    kek: string;
    jwtPrivateKey: string;
    checkpointPrivateKey: string;
    dbPassword?: string | undefined;
    awsSecretAccessKey?: string | undefined;
    services?:
      | {
          api?: ServiceStorageSecret | undefined;
          scanner?: ServiceStorageSecret | undefined;
          promoter?: ServiceStorageSecret | undefined;
          replicator?: ServiceStorageSecret | undefined;
        }
      | undefined;
  };
}

/**
 * Creates a sanitized, redacted representation of the configuration.
 * All sensitive keys and database URL passwords are replaced with '[REDACTED]'.
 */
export function redactConfig(config: Config | RedactedConfig): RedactedConfig {
  const redactedDbUrl = config.database.url.replace(
    /(postgres(?:ql)?:\/\/[^:]+:)([^@]+)(@.+)/i,
    '$1[REDACTED]$3',
  );

  const redactedServices:
    | {
        api?: ServiceStorageSecret;
        scanner?: ServiceStorageSecret;
        promoter?: ServiceStorageSecret;
        replicator?: ServiceStorageSecret;
      }
    | undefined = config.secrets.services
    ? {
        ...(config.secrets.services.api
          ? {
              api: {
                ...(config.secrets.services.api.secretAccessKey !== undefined
                  ? { secretAccessKey: '[REDACTED]' }
                  : {}),
              },
            }
          : {}),
        ...(config.secrets.services.scanner
          ? {
              scanner: {
                ...(config.secrets.services.scanner.secretAccessKey !== undefined
                  ? { secretAccessKey: '[REDACTED]' }
                  : {}),
              },
            }
          : {}),
        ...(config.secrets.services.promoter
          ? {
              promoter: {
                ...(config.secrets.services.promoter.secretAccessKey !== undefined
                  ? { secretAccessKey: '[REDACTED]' }
                  : {}),
              },
            }
          : {}),
        ...(config.secrets.services.replicator
          ? {
              replicator: {
                ...(config.secrets.services.replicator.secretAccessKey !== undefined
                  ? { secretAccessKey: '[REDACTED]' }
                  : {}),
              },
            }
          : {}),
      }
    : undefined;

  return {
    nodeEnv: config.nodeEnv,
    logLevel: config.logLevel,
    port: config.port,
    host: config.host,
    serviceName: config.serviceName,
    database: {
      url: redactedDbUrl,
      host: config.database.host,
      port: config.database.port,
      user: config.database.user,
      name: config.database.name,
    },
    storage: {
      s3: { ...config.storage.s3 },
      gcs: { ...config.storage.gcs },
      services: {
        api: { ...config.storage.services.api },
        scanner: { ...config.storage.services.scanner },
        promoter: { ...config.storage.services.promoter },
        replicator: { ...config.storage.services.replicator },
      },
    },
    secrets: {
      pepper: '[REDACTED]',
      kek: '[REDACTED]',
      jwtPrivateKey: '[REDACTED]',
      checkpointPrivateKey: '[REDACTED]',
      ...(config.secrets.dbPassword !== undefined ? { dbPassword: '[REDACTED]' } : {}),
      ...(config.secrets.awsSecretAccessKey !== undefined
        ? { awsSecretAccessKey: '[REDACTED]' }
        : {}),
      ...(redactedServices !== undefined ? { services: redactedServices } : {}),
    },
  };
}

/**
 * Loads, resolves, and validates all application configuration and secrets.
 * Aborts with a ConfigurationError if any required variable or secret is missing or malformed.
 */
export function loadConfig(options: ConfigOptions = {}): Config {
  const env = options.env ?? process.env;
  const secretsDir = options.secretsDir ?? env.SECRETS_DIR ?? '/run/secrets';

  const issues: Array<{ key: string; reason: string }> = [];

  // --- Non-Secret Environment Parsing ---
  const nodeEnvRaw = env.NODE_ENV ?? 'development';
  const nodeEnvResult = z.enum(['development', 'production', 'test']).safeParse(nodeEnvRaw);
  if (!nodeEnvResult.success) {
    issues.push({
      key: 'NODE_ENV',
      reason: "must be one of 'development', 'production', 'test'",
    });
  }

  const logLevelRaw = env.LOG_LEVEL ?? 'info';
  const logLevelResult = z
    .enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal'])
    .safeParse(logLevelRaw);
  if (!logLevelResult.success) {
    issues.push({
      key: 'LOG_LEVEL',
      reason: "must be one of 'trace', 'debug', 'info', 'warn', 'error', 'fatal'",
    });
  }

  const portRaw = env.PORT ?? '3000';
  const portResult = z.coerce.number().int().min(1).max(65535).safeParse(portRaw);
  if (!portResult.success) {
    issues.push({ key: 'PORT', reason: 'must be a valid integer between 1 and 65535' });
  }

  const host = env.HOST ?? '0.0.0.0';
  const serviceName = env.SERVICE_NAME ?? 'sug-api';

  // --- Database Configuration ---
  const dbHost = env.POSTGRES_HOST ?? '127.0.0.1';
  const dbPortParsed = parseInt(
    env.POSTGRES_PORT ?? (env.CI ? '5432' : nodeEnvRaw === 'test' ? '5433' : '5432'),
    10,
  );
  const dbPort = Number.isNaN(dbPortParsed) ? 5432 : dbPortParsed;
  const dbUser = env.POSTGRES_USER ?? 'sug_admin';
  const dbName = env.POSTGRES_DB ?? 'sug';

  // Resolve DB Password secret
  const dbPassRes = resolveSecret(
    'db_password',
    ['SUG_DB_PASSWORD', 'POSTGRES_PASSWORD'],
    secretsDir,
    env,
  );
  const dbPassword = dbPassRes.value;
  if (dbPassRes.error) {
    issues.push({ key: 'POSTGRES_PASSWORD', reason: dbPassRes.error });
  } else if (!dbPassword && nodeEnvRaw !== 'test' && !env.DATABASE_URL) {
    issues.push({ key: 'POSTGRES_PASSWORD', reason: 'required secret is missing' });
  } else if (dbPassword) {
    const valRes = dbPasswordSchema.safeParse(dbPassword);
    if (!valRes.success) {
      issues.push({
        key: 'POSTGRES_PASSWORD',
        reason: valRes.error.issues[0]?.message ?? 'invalid',
      });
    }
  }

  // Construct or validate DATABASE_URL
  let databaseUrl = env.DATABASE_URL;
  if (!databaseUrl) {
    const passPart = dbPassword
      ? `:${dbPassword}`
      : nodeEnvRaw === 'test'
        ? ':sug_dev_password'
        : '';
    databaseUrl = `postgres://${dbUser}${passPart}@${dbHost}:${dbPort}/${dbName}`;
  }

  if (!databaseUrl.startsWith('postgres://') && !databaseUrl.startsWith('postgresql://')) {
    issues.push({
      key: 'DATABASE_URL',
      reason: 'must begin with postgres:// or postgresql://',
    });
  }

  // --- Storage Configuration ---
  const s3Endpoint =
    env.S3_ENDPOINT || (nodeEnvRaw === 'production' ? undefined : 'http://localhost:4566');
  const s3Region = env.AWS_REGION ?? env.AWS_DEFAULT_REGION ?? 'us-east-1';
  const s3QuarantineBucket = env.S3_QUARANTINE_BUCKET ?? 'sug-quarantine-local';
  const s3CleanBucket = env.S3_CLEAN_BUCKET ?? 'sug-clean-local';
  const awsAccessKeyId = env.AWS_ACCESS_KEY_ID ?? 'test';

  const gcsEndpoint =
    env.GCS_ENDPOINT || (nodeEnvRaw === 'production' ? undefined : 'http://localhost:4443');
  const gcsReplicaBucket = env.GCS_REPLICA_BUCKET ?? 'sug-replica-local';
  const gcsProjectId = env.GCS_PROJECT_ID ?? 'sug-local-project';

  // Base optional storage secret
  const awsSecRes = resolveSecret(
    'aws_secret_access_key',
    ['AWS_SECRET_ACCESS_KEY'],
    secretsDir,
    env,
  );
  const awsSecretAccessKey = awsSecRes.value;
  if (awsSecRes.error) {
    issues.push({ key: 'AWS_SECRET_ACCESS_KEY', reason: awsSecRes.error });
  } else if (awsSecretAccessKey) {
    const valRes = awsSecretAccessKeySchema.safeParse(awsSecretAccessKey);
    if (!valRes.success) {
      issues.push({
        key: 'AWS_SECRET_ACCESS_KEY',
        reason: valRes.error.issues[0]?.message ?? 'invalid',
      });
    }
  }

  // Per-service storage credentials (API, Scanner, Promoter, Replicator)
  const serviceNames = ['api', 'scanner', 'promoter', 'replicator'] as const;
  const storageServices: Record<StorageServiceName, ServiceStorageConfig> = {
    api: { accessKeyId: env.AWS_ACCESS_KEY_ID_API ?? awsAccessKeyId },
    scanner: { accessKeyId: env.AWS_ACCESS_KEY_ID_SCANNER ?? awsAccessKeyId },
    promoter: { accessKeyId: env.AWS_ACCESS_KEY_ID_PROMOTER ?? awsAccessKeyId },
    replicator: { accessKeyId: env.AWS_ACCESS_KEY_ID_REPLICATOR ?? awsAccessKeyId },
  };

  const serviceStorageSecrets: Partial<Record<StorageServiceName, ServiceStorageSecret>> = {};
  for (const svc of serviceNames) {
    const secretFileName = `aws_secret_access_key_${svc}`;
    const envVarName = `AWS_SECRET_ACCESS_KEY_${svc.toUpperCase()}`;
    const svcSecRes = resolveSecret(secretFileName, [envVarName], secretsDir, env);
    if (svcSecRes.error) {
      issues.push({ key: envVarName, reason: svcSecRes.error });
    } else if (svcSecRes.value) {
      const valRes = awsSecretAccessKeySchema.safeParse(svcSecRes.value);
      if (!valRes.success) {
        issues.push({
          key: envVarName,
          reason: valRes.error.issues[0]?.message ?? 'invalid',
        });
      } else {
        serviceStorageSecrets[svc] = { secretAccessKey: svcSecRes.value };
      }
    }
  }

  // --- Required Application Secrets ---

  // 1. PEPPER
  const pepperRes = resolveSecret('pepper', ['SUG_PEPPER', 'PEPPER'], secretsDir, env);
  const pepper = pepperRes.value;
  if (pepperRes.error) {
    issues.push({ key: 'PEPPER', reason: pepperRes.error });
  } else if (!pepper) {
    issues.push({ key: 'PEPPER', reason: 'required secret is missing' });
  } else {
    const valRes = pepperSchema.safeParse(pepper);
    if (!valRes.success) {
      issues.push({ key: 'PEPPER', reason: valRes.error.issues[0]?.message ?? 'invalid' });
    }
  }

  // 2. KEK
  const kekRes = resolveSecret('kek', ['SUG_KEK', 'KEK'], secretsDir, env);
  const kek = kekRes.value;
  if (kekRes.error) {
    issues.push({ key: 'KEK', reason: kekRes.error });
  } else if (!kek) {
    issues.push({ key: 'KEK', reason: 'required secret is missing' });
  } else {
    const valRes = kekSchema.safeParse(kek);
    if (!valRes.success) {
      issues.push({ key: 'KEK', reason: valRes.error.issues[0]?.message ?? 'invalid' });
    }
  }

  // 3. JWT Ed25519 Private Key
  const jwtRes = resolveSecret(
    'jwt_private_key',
    ['SUG_JWT_PRIVATE_KEY', 'JWT_PRIVATE_KEY'],
    secretsDir,
    env,
    ['jwt_private_key.pem'],
  );
  const jwtPrivateKey = jwtRes.value;
  if (jwtRes.error) {
    issues.push({ key: 'JWT_PRIVATE_KEY', reason: jwtRes.error });
  } else if (!jwtPrivateKey) {
    issues.push({ key: 'JWT_PRIVATE_KEY', reason: 'required secret is missing' });
  } else {
    const valRes = ed25519PrivateKeySchema.safeParse(jwtPrivateKey);
    if (!valRes.success) {
      issues.push({ key: 'JWT_PRIVATE_KEY', reason: valRes.error.issues[0]?.message ?? 'invalid' });
    }
  }

  // 4. Audit Checkpoint Signing Key
  const cpRes = resolveSecret(
    'checkpoint_private_key',
    ['SUG_CHECKPOINT_PRIVATE_KEY', 'CHECKPOINT_PRIVATE_KEY'],
    secretsDir,
    env,
    ['checkpoint_private_key.pem'],
  );
  const checkpointPrivateKey = cpRes.value;
  if (cpRes.error) {
    issues.push({ key: 'CHECKPOINT_PRIVATE_KEY', reason: cpRes.error });
  } else if (!checkpointPrivateKey) {
    issues.push({ key: 'CHECKPOINT_PRIVATE_KEY', reason: 'required secret is missing' });
  } else {
    const valRes = ed25519PrivateKeySchema.safeParse(checkpointPrivateKey);
    if (!valRes.success) {
      issues.push({
        key: 'CHECKPOINT_PRIVATE_KEY',
        reason: valRes.error.issues[0]?.message ?? 'invalid',
      });
    }
  }

  // If any configuration or secret issues exist, ABORT startup
  if (issues.length > 0) {
    throw new ConfigurationError(issues);
  }

  const rawConfig = {
    nodeEnv: nodeEnvResult.data as 'development' | 'production' | 'test',
    logLevel: logLevelResult.data as 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal',
    port: portResult.data as number,
    host,
    serviceName,
    database: {
      url: databaseUrl,
      host: dbHost,
      port: dbPort,
      user: dbUser,
      name: dbName,
    },
    storage: {
      s3: {
        endpoint: s3Endpoint,
        region: s3Region,
        quarantineBucket: s3QuarantineBucket,
        cleanBucket: s3CleanBucket,
        accessKeyId: awsAccessKeyId,
      },
      gcs: {
        endpoint: gcsEndpoint,
        replicaBucket: gcsReplicaBucket,
        projectId: gcsProjectId,
      },
      services: storageServices,
    },
    secrets: {
      pepper: pepper!,
      kek: kek!,
      jwtPrivateKey: jwtPrivateKey!,
      checkpointPrivateKey: checkpointPrivateKey!,
      ...(dbPassword ? { dbPassword } : {}),
      ...(awsSecretAccessKey ? { awsSecretAccessKey } : {}),
      ...(Object.keys(serviceStorageSecrets).length > 0
        ? {
            services: serviceStorageSecrets as {
              api?: ServiceStorageSecret;
              scanner?: ServiceStorageSecret;
              promoter?: ServiceStorageSecret;
              replicator?: ServiceStorageSecret;
            },
          }
        : {}),
    },
  };

  const configObj: Config = {
    ...rawConfig,
    toRedacted(): RedactedConfig {
      return redactConfig(this);
    },
    [inspect.custom](): string {
      return inspect(redactConfig(this), { depth: 5, colors: false });
    },
    toJSON(): Record<string, unknown> {
      return redactConfig(this) as unknown as Record<string, unknown>;
    },
  };

  return Object.freeze(configObj);
}
