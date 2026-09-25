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
import pg from 'pg';

export interface AppOptions {
  config?: Config | undefined;
  db?: ReadinessDatabase | undefined;
  storage?: ReadinessStorage | undefined;
  apiKeyService?: ApiKeyService | undefined;
  authDb?: ApiKeyDatabase | undefined;
  logger?: boolean | object | undefined;
  rateLimitMax?: number | undefined;
  rateLimitTimeWindow?: string | number | undefined;
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

  // 4. OpenAPI / Swagger Documentation
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
  let apiKeyService = options.apiKeyService;
  if (!apiKeyService) {
    const authDb =
      options.authDb ??
      (() => {
        authPool = new pg.Pool({ connectionString: config.database.url });
        return authPool;
      })();
    apiKeyService = new ApiKeyService({
      db: authDb,
      pepper: config.secrets.pepper,
    });
  }

  await app.register(authRoutes, { apiKeyService });

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
