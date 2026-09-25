import type { FastifyPluginAsync } from 'fastify';
import { authenticateApiKey } from '../auth/middleware.js';
import type { ApiKeyService } from '../auth/service.js';

export interface AuthRouteOptions {
  apiKeyService: ApiKeyService;
}

const problemDetailsSchema = {
  type: 'object' as const,
  properties: {
    type: { type: 'string', example: 'urn:sug:error:unauthorized' },
    title: { type: 'string', example: 'Unauthorized' },
    status: { type: 'integer', example: 401 },
    detail: { type: 'string', example: 'Authentication failed' },
    instance: { type: 'string', example: '/api/v1/auth/probe' },
    requestId: { type: 'string', example: '018f3a5e-7a42-7000-8000-000000000001' },
  },
  required: ['type', 'title', 'status', 'detail', 'instance', 'requestId'],
};

export const authRoutes: FastPlugin = async (app, options) => {
  const { apiKeyService } = options;

  app.get(
    '/api/v1/auth/probe',
    {
      schema: {
        tags: ['Authentication'],
        summary: 'Verify API key credential',
        description:
          'Validates the provided Bearer API key in constant time and returns non-sensitive authenticated application context.',
        security: [{ ApiKeyAuth: [] }],
        response: {
          200: {
            description: 'API key credential is valid',
            type: 'object',
            properties: {
              status: { type: 'string', example: 'authenticated' },
              applicationId: {
                type: 'string',
                format: 'uuid',
                example: '018f3a5e-7a42-7000-8000-000000000001',
              },
              keyPrefix: { type: 'string', example: 'a1b2c3d4' },
              scopes: {
                type: 'array',
                items: { type: 'string' },
                example: ['upload', 'read'],
              },
            },
            required: ['status', 'applicationId', 'keyPrefix', 'scopes'],
          },
          401: {
            description: 'Authentication failed or missing credential',
            ...problemDetailsSchema,
          },
          403: {
            description: 'Insufficient API key scopes',
            ...problemDetailsSchema,
          },
        },
      },
      preHandler: authenticateApiKey(apiKeyService),
    },
    async (request) => {
      const auth = request.auth!;
      return {
        status: 'authenticated',
        applicationId: auth.applicationId,
        keyPrefix: auth.keyPrefix,
        scopes: auth.scopes,
      };
    },
  );
};

type FastPlugin = FastifyPluginAsync<AuthRouteOptions>;
