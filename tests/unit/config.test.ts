import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { inspect } from 'node:util';
import {
  loadConfig,
  redactConfig,
  resolveSecret,
  getServiceStorageCredentials,
  ConfigurationError,
  type Config,
} from '../../packages/shared/src/config.js';

describe('Configuration & Secret Loading (Phase P4)', () => {
  let tempDir: string;
  let validEd25519Pem: string;
  const validKek = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const validPepper = 'test_pepper_entropy_value_minimum_32_characters_long';

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sug-config-test-'));

    const { privateKey } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    validEd25519Pem = privateKey;
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on windows
    }
  });

  function populateValidSecretFiles(dir: string): void {
    fs.writeFileSync(path.join(dir, 'pepper'), `${validPepper}\n`);
    fs.writeFileSync(path.join(dir, 'kek'), `${validKek}\n`);
    fs.writeFileSync(path.join(dir, 'jwt_private_key.pem'), validEd25519Pem);
    fs.writeFileSync(path.join(dir, 'checkpoint_private_key.pem'), validEd25519Pem);
    fs.writeFileSync(path.join(dir, 'db_password'), 'sug_test_password\n');
  }

  function getValidEnv(): Record<string, string> {
    return {
      NODE_ENV: 'test',
      LOG_LEVEL: 'info',
      PORT: '3000',
      HOST: '0.0.0.0',
      SERVICE_NAME: 'sug-api',
      DATABASE_URL: 'postgres://sug_admin:sug_test_password@localhost:5433/sug',
      SUG_PEPPER: validPepper,
      SUG_KEK: validKek,
      SUG_JWT_PRIVATE_KEY: validEd25519Pem,
      SUG_CHECKPOINT_PRIVATE_KEY: validEd25519Pem,
      SUG_DB_PASSWORD: 'sug_test_password',
      AWS_REGION: 'us-east-1',
      S3_ENDPOINT: 'http://localhost:4566',
      S3_QUARANTINE_BUCKET: 'sug-quarantine-local',
      S3_CLEAN_BUCKET: 'sug-clean-local',
    };
  }

  it('1. Valid configuration loads successfully from environment variables', () => {
    const env = getValidEnv();
    const config = loadConfig({ env, secretsDir: path.join(tempDir, 'empty') });

    expect(config.nodeEnv).toBe('test');
    expect(config.logLevel).toBe('info');
    expect(config.port).toBe(3000);
    expect(config.host).toBe('0.0.0.0');
    expect(config.serviceName).toBe('sug-api');
    expect(config.database.url).toBe(env.DATABASE_URL);
    expect(config.secrets.pepper).toBe(validPepper);
    expect(config.secrets.kek).toBe(validKek);
    expect(config.secrets.jwtPrivateKey).toBe(validEd25519Pem.trim());
    expect(config.secrets.checkpointPrivateKey).toBe(validEd25519Pem.trim());
    expect(config.storage.s3.quarantineBucket).toBe('sug-quarantine-local');
  });

  it('2. Valid configuration loads successfully from Docker file secrets (/run/secrets)', () => {
    populateValidSecretFiles(tempDir);

    const env: Record<string, string> = {
      NODE_ENV: 'test',
      DATABASE_URL: 'postgres://sug_admin:sug_test_password@localhost:5433/sug',
    };

    const config = loadConfig({ env, secretsDir: tempDir });

    expect(config.secrets.pepper).toBe(validPepper);
    expect(config.secrets.kek).toBe(validKek);
    expect(config.secrets.jwtPrivateKey).toBe(validEd25519Pem.replace(/[\r\n]+$/, ''));
    expect(config.secrets.checkpointPrivateKey).toBe(validEd25519Pem.replace(/[\r\n]+$/, ''));
    expect(config.secrets.dbPassword).toBe('sug_test_password');
  });

  it('3. Missing required non-secret variable fails validation with clear reason', () => {
    const env = getValidEnv();

    // Invalid Port
    expect(() => loadConfig({ env: { ...env, PORT: '70000' }, secretsDir: tempDir })).toThrowError(
      ConfigurationError,
    );
    try {
      loadConfig({ env: { ...env, PORT: 'invalid_port' }, secretsDir: tempDir });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain('PORT: must be a valid integer');
    }

    // Invalid Log Level
    try {
      loadConfig({ env: { ...env, LOG_LEVEL: 'verbose' }, secretsDir: tempDir });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain('LOG_LEVEL: must be one of');
    }

    // Invalid Node Environment
    try {
      loadConfig({ env: { ...env, NODE_ENV: 'staging' }, secretsDir: tempDir });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain('NODE_ENV: must be one of');
    }

    // Invalid Database URL
    try {
      loadConfig({
        env: { ...env, DATABASE_URL: 'mysql://root@localhost/sug' },
        secretsDir: tempDir,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain(
        'DATABASE_URL: must begin with postgres:// or postgresql://',
      );
    }
  });

  it('4. Missing required secret file fails with explicit error', () => {
    // Empty directory, empty env
    expect(() => loadConfig({ env: {}, secretsDir: tempDir })).toThrowError(ConfigurationError);

    try {
      loadConfig({ env: {}, secretsDir: tempDir });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      const confErr = err as ConfigurationError;
      expect(confErr.message).toContain('PEPPER: required secret is missing');
      expect(confErr.message).toContain('KEK: required secret is missing');
      expect(confErr.message).toContain('JWT_PRIVATE_KEY: required secret is missing');
      expect(confErr.message).toContain('CHECKPOINT_PRIVATE_KEY: required secret is missing');
    }
  });

  it('5. Empty secret file fails validation', () => {
    populateValidSecretFiles(tempDir);
    // Write an empty pepper file
    fs.writeFileSync(path.join(tempDir, 'pepper'), '   \n\n  ');

    expect(() => loadConfig({ env: {}, secretsDir: tempDir })).toThrowError(ConfigurationError);
    try {
      loadConfig({ env: {}, secretsDir: tempDir });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain('PEPPER: secret file is empty');
    }
  });

  it('6. Empty secret environment variable fails validation', () => {
    const env = getValidEnv();
    env.SUG_PEPPER = '';

    expect(() => loadConfig({ env, secretsDir: path.join(tempDir, 'nonexistent') })).toThrowError(
      ConfigurationError,
    );

    try {
      loadConfig({ env, secretsDir: path.join(tempDir, 'nonexistent') });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain(
        'PEPPER: secret environment variable is empty',
      );
    }
  });

  it('7. Precedence rule: Docker file secret takes precedence over environment variable', () => {
    populateValidSecretFiles(tempDir);

    const filePepper = validPepper;
    const envPepper = 'env_pepper_value_that_should_be_ignored_due_to_precedence_rule_123';

    const env = getValidEnv();
    env.SUG_PEPPER = envPepper;

    const config = loadConfig({ env, secretsDir: tempDir });
    // File secret MUST win according to precedence rule 1 (file) > 2 (env)
    expect(config.secrets.pepper).toBe(filePepper);
    expect(config.secrets.pepper).not.toBe(envPepper);
  });

  it('8. Malformed KEK representation fails validation', () => {
    const env = getValidEnv();

    // Invalid length (31 chars instead of 64 hex)
    env.SUG_KEK = '0123456789abcdef0123456789abcde';
    expect(() => loadConfig({ env, secretsDir: tempDir })).toThrowError(ConfigurationError);
    try {
      loadConfig({ env, secretsDir: tempDir });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain('KEK: must be a 256-bit key');
    }

    // Invalid non-hex characters
    env.SUG_KEK = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg';
    try {
      loadConfig({ env, secretsDir: tempDir });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain('KEK: must be a 256-bit key');
    }
  });

  it('9. Malformed Ed25519 key fails validation', () => {
    const env = getValidEnv();
    env.SUG_JWT_PRIVATE_KEY = [
      '-----',
      'BEGIN RSA ',
      'PRIVATE KEY-----',
      '\nMIIE...\n',
      '-----END RSA PRIVATE KEY-----',
    ].join('');

    try {
      loadConfig({ env, secretsDir: tempDir });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain(
        'JWT_PRIVATE_KEY: must be a valid PEM-encoded or 32/64-byte Ed25519 private key',
      );
    }
  });

  it('10. Pepper shorter than 32 characters fails validation', () => {
    const env = getValidEnv();
    env.SUG_PEPPER = 'too-short-pepper';

    try {
      loadConfig({ env, secretsDir: tempDir });
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigurationError);
      expect((err as ConfigurationError).message).toContain(
        'PEPPER: must be at least 32 characters',
      );
    }
  });

  describe('Security & Redaction Proof (STEP 4 & STEP 12)', () => {
    const SENTINEL = 'P4_TEST_SUPER_SECRET_DO_NOT_LEAK';
    const sentinelPepper = `${SENTINEL}_pepper_padding_to_exceed_32_characters_entropy`;
    const sentinelDbPass = `${SENTINEL}_db_password`;

    it('proves sentinel secret NEVER appears in diagnostic or redacted output', () => {
      const env = getValidEnv();
      env.SUG_PEPPER = sentinelPepper;
      env.SUG_DB_PASSWORD = sentinelDbPass;
      env.DATABASE_URL = `postgres://sug_admin:${sentinelDbPass}@localhost:5433/sug`;

      const config: Config = loadConfig({ env, secretsDir: tempDir });

      // Raw secret is accessible in memory for authorized cryptographic usage
      expect(config.secrets.pepper).toBe(sentinelPepper);

      // 1. toRedacted()
      const redacted = config.toRedacted();
      expect(redacted.secrets.pepper).toBe('[REDACTED]');
      expect(redacted.secrets.kek).toBe('[REDACTED]');
      expect(redacted.secrets.jwtPrivateKey).toBe('[REDACTED]');
      expect(redacted.database.url).not.toContain(SENTINEL);
      expect(redacted.database.url).toContain('[REDACTED]');

      const redactedJson = JSON.stringify(redacted);
      expect(redactedJson).not.toContain(SENTINEL);
      expect(redactedJson).not.toContain(sentinelPepper);
      expect(redactedJson).not.toContain(sentinelDbPass);

      // 2. redactConfig standalone function
      const standaloneRedacted = redactConfig(config);
      const standaloneJson = JSON.stringify(standaloneRedacted);
      expect(standaloneJson).not.toContain(SENTINEL);
      expect(standaloneJson).not.toContain(sentinelPepper);
      expect(standaloneJson).not.toContain(sentinelDbPass);

      // 3. JSON.stringify(config) - protected by toJSON() override
      const serializedConfig = JSON.stringify(config);
      expect(serializedConfig).not.toContain(SENTINEL);
      expect(serializedConfig).not.toContain(sentinelPepper);
      expect(serializedConfig).not.toContain(sentinelDbPass);
      expect(serializedConfig).toContain('[REDACTED]');

      // 4. util.inspect(config) / console.log - protected by custom inspect override
      const inspectedConfig = inspect(config);
      expect(inspectedConfig).not.toContain(SENTINEL);
      expect(inspectedConfig).not.toContain(sentinelPepper);
      expect(inspectedConfig).not.toContain(sentinelDbPass);
      expect(inspectedConfig).toContain('[REDACTED]');
    });

    it('proves sentinel secret NEVER appears in thrown error messages or validation issues', () => {
      const env = getValidEnv();
      // Inject sentinel into an invalid KEK
      const invalidKekWithSentinel = `invalid_${SENTINEL}_kek`;
      env.SUG_KEK = invalidKekWithSentinel;

      try {
        loadConfig({ env, secretsDir: tempDir });
        expect.unreachable('Should have thrown ConfigurationError');
      } catch (err: unknown) {
        expect(err).toBeInstanceOf(ConfigurationError);
        const confErr = err as ConfigurationError;

        // Error message must not contain the sensitive value
        expect(confErr.message).not.toContain(SENTINEL);
        expect(confErr.message).not.toContain(invalidKekWithSentinel);

        // Issues list must not contain the sensitive value
        for (const issue of confErr.issues) {
          expect(issue.reason).not.toContain(SENTINEL);
          expect(issue.reason).not.toContain(invalidKekWithSentinel);
        }

        // Serialized error must not contain the sensitive value
        const serialized = JSON.stringify({
          message: confErr.message,
          issues: confErr.issues,
        });
        expect(serialized).not.toContain(SENTINEL);
      }
    });
  });

  describe('resolveSecret direct unit tests', () => {
    it('returns source: missing when neither file nor env exists', () => {
      const res = resolveSecret('unknown', ['UNKNOWN_VAR'], tempDir, {});
      expect(res.source).toBe('missing');
      expect(res.value).toBeUndefined();
    });

    it('returns source: file with trimmed content when file exists', () => {
      fs.writeFileSync(path.join(tempDir, 'test_secret'), 'secret_content_value\r\n');
      const res = resolveSecret('test_secret', ['TEST_VAR'], tempDir, {
        TEST_VAR: 'env_value',
      });
      expect(res.source).toBe('file');
      expect(res.value).toBe('secret_content_value');
    });

    it('returns source: env when file is absent', () => {
      const res = resolveSecret('nonexistent_file', ['TEST_VAR'], tempDir, {
        TEST_VAR: 'env_secret_val',
      });
      expect(res.source).toBe('env');
      expect(res.value).toBe('env_secret_val');
    });

    it('returns error when file secret is empty', () => {
      fs.writeFileSync(path.join(tempDir, 'empty_secret'), '   \n');
      const res = resolveSecret('empty_secret', ['TEST_VAR'], tempDir, {});
      expect(res.source).toBe('file');
      expect(res.error).toBe('secret file is empty');
      expect(res.value).toBeUndefined();
    });

    it('returns error when env secret is empty', () => {
      const res = resolveSecret('nonexistent', ['EMPTY_VAR'], tempDir, {
        EMPTY_VAR: '',
      });
      expect(res.source).toBe('env');
      expect(res.error).toBe('secret environment variable is empty');
      expect(res.value).toBeUndefined();
    });
  });

  describe('Per-Service Storage Credentials', () => {
    it('defaults per-service credentials to base storage credentials when not overridden', () => {
      const env = {
        ...getValidEnv(),
        AWS_ACCESS_KEY_ID: 'global-key-id',
        AWS_SECRET_ACCESS_KEY: 'global-secret-key',
      };
      const config = loadConfig({ env, secretsDir: path.join(tempDir, 'empty') });

      const services = ['api', 'scanner', 'promoter', 'replicator'] as const;
      for (const svc of services) {
        expect(config.storage.services[svc].accessKeyId).toBe('global-key-id');
        const creds = getServiceStorageCredentials(config, svc);
        expect(creds.accessKeyId).toBe('global-key-id');
        expect(creds.secretAccessKey).toBe('global-secret-key');
      }
    });

    it('allows per-service credentials to be individually overridden via env vars', () => {
      const env = {
        ...getValidEnv(),
        AWS_ACCESS_KEY_ID: 'global-key-id',
        AWS_SECRET_ACCESS_KEY: 'global-secret-key',
        AWS_ACCESS_KEY_ID_API: 'api-service-key-id',
        AWS_SECRET_ACCESS_KEY_API: 'api-service-secret-key',
      };
      const config = loadConfig({ env, secretsDir: path.join(tempDir, 'empty') });

      // API service has specific override
      expect(config.storage.services.api.accessKeyId).toBe('api-service-key-id');
      const apiCreds = getServiceStorageCredentials(config, 'api');
      expect(apiCreds.accessKeyId).toBe('api-service-key-id');
      expect(apiCreds.secretAccessKey).toBe('api-service-secret-key');

      // Scanner service falls back to global credentials
      expect(config.storage.services.scanner.accessKeyId).toBe('global-key-id');
      const scannerCreds = getServiceStorageCredentials(config, 'scanner');
      expect(scannerCreds.accessKeyId).toBe('global-key-id');
      expect(scannerCreds.secretAccessKey).toBe('global-secret-key');
    });

    it('allows per-service storage secrets to be loaded from file secrets', () => {
      populateValidSecretFiles(tempDir);
      fs.writeFileSync(
        path.join(tempDir, 'aws_secret_access_key_scanner'),
        'scanner-file-secret-value\n',
      );

      const env: Record<string, string> = {
        NODE_ENV: 'test',
        DATABASE_URL: 'postgres://sug_admin:sug_test_password@localhost:5433/sug',
      };

      const config = loadConfig({ env, secretsDir: tempDir });
      const scannerCreds = getServiceStorageCredentials(config, 'scanner');
      expect(scannerCreds.secretAccessKey).toBe('scanner-file-secret-value');
    });

    it('strictly redacts per-service storage secrets in toRedacted, inspect, and toJSON', () => {
      const secretApiValue = 'super-confidential-api-secret-value';
      const env = {
        ...getValidEnv(),
        AWS_ACCESS_KEY_ID_API: 'api-service-key-id',
        AWS_SECRET_ACCESS_KEY_API: secretApiValue,
      };
      const config = loadConfig({ env, secretsDir: path.join(tempDir, 'empty') });

      // Direct secret is accessible on unredacted config
      expect(config.secrets.services?.api?.secretAccessKey).toBe(secretApiValue);

      // 1. toRedacted() replaces it with [REDACTED]
      const redacted = config.toRedacted();
      expect(redacted.secrets.services?.api?.secretAccessKey).toBe('[REDACTED]');

      // 2. inspect() does not contain the secret
      const inspected = inspect(config);
      expect(inspected).not.toContain(secretApiValue);
      expect(inspected).toContain('[REDACTED]');

      // 3. toJSON() does not contain the secret
      const serialized = JSON.stringify(config);
      expect(serialized).not.toContain(secretApiValue);
      expect(serialized).toContain('[REDACTED]');
    });
  });
});
