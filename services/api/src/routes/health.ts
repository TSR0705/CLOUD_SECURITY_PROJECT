import type { FastifyPluginAsync } from 'fastify';
import type { ReadinessDatabase, ReadinessStorage } from '../health/types.js';

export interface HealthRouteOptions {
  db: ReadinessDatabase;
  storage: ReadinessStorage;
}

/**
 * Health and readiness route plugin.
 * - GET /healthz: Process liveness only (zero I/O, deterministic 200).
 * - GET /readyz: Dependency reachability probe aggregating PostgreSQL and S3.
 */
export const healthRoutes: FastifyPluginAsync<HealthRouteOptions> = async (
  fastify,
  options,
): Promise<void> => {
  const { db, storage } = options;

  // 1. Liveness Probe
  fastify.get(
    '/healthz',
    {
      config: {
        rateLimit: false,
      },
      schema: {
        summary: 'Process liveness probe',
        description:
          'Answers whether the API process is alive. Does not perform I/O or query dependencies.',
        tags: ['Health'],
        response: {
          200: {
            description: 'API process is healthy and alive',
            type: 'object',
            properties: {
              status: { type: 'string', enum: ['ok'], example: 'ok' },
            },
            required: ['status'],
          },
        },
      },
    },
    async (_request, reply) => {
      return reply.status(200).send({ status: 'ok' });
    },
  );

  // 2. Readiness Probe
  fastify.get(
    '/readyz',
    {
      config: {
        rateLimit: false,
      },
      schema: {
        summary: 'Dependency readiness probe',
        description:
          'Verifies reachability of core infrastructure dependencies (PostgreSQL database and S3 storage) before accepting traffic.',
        tags: ['Health'],
        response: {
          200: {
            description: 'All core dependencies are reachable and ready to process traffic',
            type: 'object',
            properties: {
              status: { type: 'string', enum: ['ready'], example: 'ready' },
            },
            required: ['status'],
          },
          503: {
            description: 'One or more core dependencies are unreachable or degraded',
            type: 'object',
            properties: {
              status: { type: 'string', enum: ['not_ready'], example: 'not_ready' },
            },
            required: ['status'],
          },
        },
      },
    },
    async (request, reply) => {
      const [dbResult, storageResult] = await Promise.allSettled([
        db.checkReachability(),
        storage.checkReachability(),
      ]);

      const isDbOk = dbResult.status === 'fulfilled';
      const isStorageOk = storageResult.status === 'fulfilled';

      if (isDbOk && isStorageOk) {
        return reply.status(200).send({ status: 'ready' });
      }

      // Log diagnostic info internally without leaking to client response
      request.log.warn(
        {
          dbOk: isDbOk,
          storageOk: isStorageOk,
        },
        'Readiness check failed for one or more dependencies',
      );

      return reply.status(503).send({ status: 'not_ready' });
    },
  );
};
