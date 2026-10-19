import crypto from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import { loadConfig, type Config } from '@sug/shared/config';
import { handleProblemError, handleNotFound } from './errors/problem.js';
import { type ReadinessDatabase, type ReadinessStorage } from './health/types.js';
import { PostgresReadinessCheck } from './health/database.js';
import { S3ReadinessCheck } from './health/storage.js';
import { healthRoutes } from './routes/health.js';
import { ApiKeyService } from './auth/service.js';
import type { ApiKeyDatabase } from './auth/types.js';
import { authRoutes } from './routes/auth.js';
import { UploadAuthorizationService } from './auth/session-service.js';
import { uploadAuthRoutes } from './routes/upload-auth.js';
import fastifyCookie from '@fastify/cookie';
import { UserService } from './auth/user-service.js';
import { userAuthRoutes } from './routes/user-auth.js';
import { PolicyService } from './policy/policy-service.js';
import { policyRoutes } from './routes/policy.js';
import { UploadSessionService } from './upload/session-service.js';
import { uploadSessionRoutes } from './routes/upload-session.js';
import { derivePublicKeyPem } from './auth/jwt.js';
import { createS3Provider, type StorageProvider } from '@sug/storage';
import { StreamingUploadService } from './upload/streaming-service.js';
import { uploadRoutes } from './routes/upload.js';
import { scansRoutes } from './routes/scans.js';
import { securityDecisionsRoutes } from './routes/security-decisions.js';
import { filesRoutes } from './routes/files.js';
import { auditRoutes } from './routes/audit.js';
import { LocalKeyProvider, type KeyProvider } from '@sug/crypto';
import pg from 'pg';

export interface AppOptions {
  config?: Config | undefined;
  db?: ReadinessDatabase | undefined;
  storage?: ReadinessStorage | undefined;
  storageProvider?: StorageProvider | undefined;
  keyProvider?: KeyProvider | undefined;
  apiKeyService?: ApiKeyService | undefined;
  uploadAuthService?: UploadAuthorizationService | undefined;
  userService?: UserService | undefined;
  policyService?: PolicyService | undefined;
  uploadSessionService?: UploadSessionService | undefined;
  streamingUploadService?: StreamingUploadService | undefined;
  authDb?: ApiKeyDatabase | undefined;
  logger?: boolean | object | undefined;
  rateLimitMax?: number | undefined;
  rateLimitTimeWindow?: string | number | undefined;
  checkpointPrivateKeyPem?: string | undefined;
  checkpointPublicKeyPem?: string | undefined;
}

const REQUEST_ID_MAX_LENGTH = 64;
const REQUEST_ID_SAFE_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

/**
 * Validates an incoming request ID against strict security policy:
 * - Length between 1 and 64 characters
 * - Alphanumeric, hyphen, or underscore ONLY
 * - No whitespace, control characters, or newlines (prevents log injection)
 *
 * If valid, returns the supplied ID. Otherwise, generates a secure random UUID.
 */
export function resolveRequestId(suppliedId?: string | string[]): string {
  if (typeof suppliedId === 'string') {
    const trimmed = suppliedId.trim();
    if (
      trimmed.length > 0 &&
      trimmed.length <= REQUEST_ID_MAX_LENGTH &&
      REQUEST_ID_SAFE_REGEX.test(trimmed)
    ) {
      return trimmed;
    }
  }
  return crypto.randomUUID();
}

/**
 * Fastify Application Factory for the Secure Upload Gateway Edge API.
 * Decoupled from network socket listening for fast, deterministic unit & integration testing.
 */
export async function createApp(options: AppOptions = {}): Promise<FastifyInstance> {
  const config = options.config ?? loadConfig();

  // Configure logger with strict redaction of credentials and Authorization headers
  let loggerConfig: boolean | object = false;
  if (options.logger === true) {
    loggerConfig = {
      redact: ['req.headers.authorization', 'headers.authorization'],
    };
  } else if (typeof options.logger === 'object' && options.logger !== null) {
    loggerConfig = {
      ...options.logger,
      redact: ['req.headers.authorization', 'headers.authorization'],
    };
  }

  const app: FastifyInstance = Fastify({
    logger: loggerConfig,
    requestIdHeader: false,
    genReqId: (req) => {
      const incomingId = req.headers['x-request-id'];
      return resolveRequestId(incomingId);
    },
  });

  // Ensure every response carries the canonical X-Request-ID header
  app.addHook('onSend', async (request, reply) => {
    reply.header('x-request-id', request.id);
  });

  // 1. Security Headers (Helmet)
  await app.register(helmet, {
    contentSecurityPolicy: false, // Pure REST API, prevents breaking cross-origin JSON fetches
    crossOriginEmbedderPolicy: false,
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' },
  });

  // 2. Cross-Origin Resource Sharing (CORS)
  await app.register(cors, {
    origin: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
    exposedHeaders: ['X-Request-ID'],
  });

  // 3. In-Memory Rate Limiting
  await app.register(rateLimit, {
    max: options.rateLimitMax ?? 100,
    timeWindow: options.rateLimitTimeWindow ?? '1 minute',
    allowList: (req) => {
      // Exclude liveness and readiness probes from global rate limiting
      const url = (req.url || '').split('?')[0];
      return url === '/healthz' || url === '/readyz';
    },
  });

  // 4. Cookie Support for Secure Refresh Tokens
  await app.register(fastifyCookie);

  // 5. OpenAPI / Swagger Documentation
  await app.register(swagger, {
    openapi: {
      openapi: '3.0.3',
      info: {
        title: 'Secure Upload Gateway API',
        description:
          'Edge API gateway for secure multi-engine file analysis, policy validation, and quarantined upload processing.',
        version: '0.1.0',
      },
      servers: [
        {
          url: '/',
          description: 'Gateway Local / Target Environment',
        },
      ],
      components: {
        schemas: {
          ProblemDetails: {
            type: 'object',
            properties: {
              type: { type: 'string', example: 'urn:sug:error:validation' },
              title: { type: 'string', example: 'Validation Error' },
              status: { type: 'integer', example: 400 },
              detail: { type: 'string', example: 'Invalid request parameter' },
              instance: { type: 'string', example: '/readyz' },
              requestId: { type: 'string', example: 'c0a80101-0000-0000-0000-000000000000' },
            },
            required: ['type', 'title', 'status', 'detail', 'instance', 'requestId'],
          },
        },
        headers: {
          'X-Request-ID': {
            description: 'Unique correlation ID for tracing the request lifecycle',
            schema: { type: 'string', example: 'c0a80101-0000-0000-0000-000000000000' },
          },
        },
        securitySchemes: {
          ApiKeyAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'API Key',
            description: 'API key in format sug_<key_prefix>_<secret>',
          },
          UserAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            description: 'EdDSA JWT access token issued by POST /api/v1/auth/login',
          },
        },
      },
    },
  });

  // 5. Standardized Problem Details Error Handlers
  app.setErrorHandler(handleProblemError);
  app.setNotFoundHandler(handleNotFound);

  // 6. Dependencies & Health Routes
  const db = options.db ?? new PostgresReadinessCheck({ connectionString: config.database.url });
  const storage =
    options.storage ??
    new S3ReadinessCheck({
      endpoint: config.storage.s3.endpoint,
      region: config.storage.s3.region,
      bucket: config.storage.s3.quarantineBucket,
      credentials: {
        accessKeyId: config.storage.services.api.accessKeyId,
        secretAccessKey:
          config.secrets.services?.api?.secretAccessKey ?? config.secrets.awsSecretAccessKey,
      },
    });

  await app.register(healthRoutes, { db, storage });

  // 7. API Key Authentication Service & Protected Routes
  let authPool: pg.Pool | undefined;
  const authDb =
    options.authDb ??
    (() => {
      authPool = new pg.Pool({ connectionString: config.database.url });
      return authPool;
    })();

  const apiKeyService =
    options.apiKeyService ??
    new ApiKeyService({
      db: authDb,
      pepper: config.secrets.pepper,
    });

  await app.register(authRoutes, { apiKeyService });

  // 8. Upload Authorization Service & Scoped Routes
  const uploadAuthService =
    options.uploadAuthService ??
    new UploadAuthorizationService({
      db: authDb,
    });

  await app.register(uploadAuthRoutes, { apiKeyService, uploadAuthService });

  // 9. Dashboard User Authentication & RBAC Routes
  const userService =
    options.userService ??
    new UserService({
      db: authDb,
    });

  await app.register(userAuthRoutes, {
    userService,
    jwtPrivateKeyPem: config.secrets.jwtPrivateKey,
    isProduction: config.nodeEnv === 'production',
  });

  // 10. Security Policy Engine & Versioning Routes
  const jwtPublicKeyPem = derivePublicKeyPem(config.secrets.jwtPrivateKey);

  const policyService =
    options.policyService ??
    new PolicyService({
      db: authDb,
    });

  await app.register(policyRoutes, {
    apiKeyService,
    policyService,
    jwtPublicKeyPem,
  });

  // 11. Upload Session & Pinned Token Routes
  const uploadSessionService =
    options.uploadSessionService ??
    new UploadSessionService({
      db: authDb,
      policyService,
    });

  await app.register(uploadSessionRoutes, {
    apiKeyService,
    uploadSessionService,
    jwtPrivateKeyPem: config.secrets.jwtPrivateKey,
    jwtPublicKeyPem,
  });

  // 12. Streaming Quarantine Upload Routes (P10)
  const storageProvider =
    options.storageProvider ??
    createS3Provider({
      endpoint: config.storage.s3.endpoint,
      region: config.storage.s3.region,
      credentials: {
        accessKeyId: config.storage.services.api.accessKeyId,
        secretAccessKey:
          config.secrets.services?.api?.secretAccessKey ?? config.secrets.awsSecretAccessKey ?? '',
      },
      forcePathStyle: true,
    });

  const streamingUploadService =
    options.streamingUploadService ??
    new StreamingUploadService({
      db: authDb,
      storageProvider,
      policyService,
      uploadSessionService,
      quarantineBucket: config.storage.s3.quarantineBucket,
    });

  await app.register(uploadRoutes, {
    apiKeyService,
    streamingUploadService,
    jwtPublicKeyPem,
  });

  // 13. Scan Findings & Status Routes (P17)
  await app.register(scansRoutes, {
    db: authDb,
    apiKeyService,
    jwtPublicKeyPem,
  });

  // 14. Security Decisions & Human Review Routes (P18)
  await app.register(securityDecisionsRoutes, {
    db: authDb,
    apiKeyService,
    jwtPublicKeyPem,
  });

  // 15. Clean Object Access & File Management Routes (P20)
  const keyProvider =
    options.keyProvider ??
    new LocalKeyProvider({
      keys: {
        'local:default': config.secrets.kek,
      },
      defaultKeyReference: 'local:default',
    });

  await app.register(filesRoutes, {
    db: authDb,
    apiKeyService,
    storageProvider,
    keyProvider,
    jwtPublicKeyPem,
  });

  // 16. Hash-Chained Audit System & Checkpoints (P21)
  const checkpointPrivateKey =
    options.checkpointPrivateKeyPem ?? config.secrets.checkpointPrivateKey;
  const checkpointPublicKey =
    options.checkpointPublicKeyPem ?? derivePublicKeyPem(checkpointPrivateKey);

  await app.register(auditRoutes, {
    db: authDb,
    apiKeyService,
    jwtPublicKeyPem,
    storageProvider,
    auditBucket: config.storage.s3.auditBucket,
    checkpointPrivateKeyPem: checkpointPrivateKey,
    checkpointPublicKeyPem: checkpointPublicKey,
  });

  // Clean shutdown hook
  app.addHook('onClose', async () => {
    if (db.close) {
      await db.close();
    }
    if (storage.close) {
      await storage.close();
    }
    if (authPool) {
      await authPool.end();
    }
  });

  return app;
}
