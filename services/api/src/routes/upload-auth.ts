import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { authenticateApiKey } from '../auth/middleware.js';
import type { ApiKeyService } from '../auth/service.js';
import { UploadAuthorizationService } from '../auth/session-service.js';
import { enforceApplicationOwnership, requireScope } from '../auth/tenant.js';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import { generateQuarantineKey } from '../auth/session-utils.js';

export interface UploadAuthRouteOptions {
  apiKeyService: ApiKeyService;
  uploadAuthService: UploadAuthorizationService;
}

const problemDetailsSchema = {
  type: 'object' as const,
  properties: {
    type: { type: 'string', example: 'urn:sug:error:validation' },
    title: { type: 'string', example: 'Validation Error' },
    status: { type: 'integer', example: 400 },
    detail: { type: 'string', example: 'Invalid parameter' },
    instance: { type: 'string', example: '/api/v1/upload/authorize' },
    requestId: { type: 'string', example: '018f3a5e-7a42-7000-8000-000000000001' },
  },
  required: ['type', 'title', 'status', 'detail', 'instance', 'requestId'],
};

export const uploadAuthRoutes: FastPlugin = async (app, options) => {
  const { apiKeyService, uploadAuthService } = options;

  // 1. Authorize & Create Upload Session
  app.post(
    '/api/v1/upload/authorize',
    {
      schema: {
        tags: ['Upload Authorization'],
        summary: 'Authorize upload session',
        description:
          'Validates client upload parameters against application policy, bounds server-side expiration, and creates an upload session.',
        security: [{ ApiKeyAuth: [] }],
        body: {
          type: 'object',
          properties: {
            filename: { type: 'string', minLength: 1, maxLength: 255 },
            declaredSize: { type: 'integer', minimum: 1, maximum: 52428800 },
            declaredMime: { type: 'string', minLength: 1, maxLength: 127 },
            policyId: { type: 'string', format: 'uuid' },
            declaredSha256: { type: 'string', pattern: '^[0-9a-fA-F]{64}$' },
            clientRef: { type: 'string', maxLength: 128 },
            durationSeconds: { type: 'integer', minimum: 60, maximum: 900 },
            applicationId: { type: 'string', format: 'uuid' },
          },
          required: ['filename', 'declaredSize', 'declaredMime'],
        },
        response: {
          201: {
            description: 'Upload session authorized and reserved',
            type: 'object',
            properties: {
              sessionId: { type: 'string', format: 'uuid' },
              applicationId: { type: 'string', format: 'uuid' },
              status: { type: 'string', example: 'CREATED' },
              quarantineKey: { type: 'string', example: 'incoming/uuid/uuid' },
              tokenJti: { type: 'string', format: 'uuid' },
              policyId: { type: 'string', format: 'uuid' },
              expiresAt: { type: 'string', format: 'date-time' },
              maxFileSize: { type: 'integer' },
              declaredSize: { type: 'integer' },
              declaredMime: { type: 'string' },
            },
            required: [
              'sessionId',
              'applicationId',
              'status',
              'quarantineKey',
              'tokenJti',
              'policyId',
              'expiresAt',
              'maxFileSize',
              'declaredSize',
              'declaredMime',
            ],
          },
          400: { description: 'Validation error', ...problemDetailsSchema },
          401: { description: 'Unauthorized', ...problemDetailsSchema },
          403: { description: 'Forbidden', ...problemDetailsSchema },
          409: { description: 'Conflict: No active policy', ...problemDetailsSchema },
        },
      },
      preHandler: [
        authenticateApiKey(apiKeyService),
        requireScope('upload'),
        enforceApplicationOwnership(),
      ],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const auth = request.auth!;
      const body = request.body as {
        filename: string;
        declaredSize: number;
        declaredMime: string;
        policyId?: string | undefined;
        declaredSha256?: string | undefined;
        clientRef?: string | undefined;
        durationSeconds?: number | undefined;
      };

      try {
        const session = await uploadAuthService.createSession({
          applicationId: auth.applicationId,
          apiKeyId: auth.apiKeyId,
          filename: body.filename,
          declaredSize: body.declaredSize,
          declaredMime: body.declaredMime,
          policyId: body.policyId,
          declaredSha256: body.declaredSha256,
          clientRef: body.clientRef,
          durationSeconds: body.durationSeconds,
          clientIp: request.ip,
          requestId: request.id,
        });

        reply.status(201).send(session);
      } catch (err: unknown) {
        const error = err as Error;
        if (error.message === 'NO_ACTIVE_POLICY') {
          const problem = createProblemDetails(
            request,
            409,
            'Conflict',
            'No active security policy configured for this application',
            'urn:sug:error:conflict',
          );
          reply.status(409).type('application/problem+json; charset=utf-8').send(problem);
          return;
        }

        if (
          error.message.includes('exceeds') ||
          error.message.includes('must be') ||
          error.message.includes('invalid')
        ) {
          const problem = createProblemDetails(
            request,
            400,
            'Validation Error',
            error.message,
            ErrorTypes.VALIDATION,
          );
          reply.status(400).type('application/problem+json; charset=utf-8').send(problem);
          return;
        }

        throw err;
      }
    },
  );

  // 2. Get Upload Session Details (Scoped)
  app.get(
    '/api/v1/upload/sessions/:id',
    {
      schema: {
        tags: ['Upload Authorization'],
        summary: 'Get upload session details',
        description:
          'Retrieves upload session state strictly scoped to the authenticated application.',
        security: [{ ApiKeyAuth: [] }],
        params: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
          },
          required: ['id'],
        },
        response: {
          200: {
            description: 'Session details retrieved',
            type: 'object',
            properties: {
              id: { type: 'string', format: 'uuid' },
              applicationId: { type: 'string', format: 'uuid' },
              status: { type: 'string' },
              quarantineKey: { type: 'string' },
              originalFilename: { type: 'string' },
              declaredSize: { type: 'integer' },
              declaredMime: { type: 'string' },
              expiresAt: { type: 'string', format: 'date-time' },
              createdAt: { type: 'string', format: 'date-time' },
              completedAt: { type: ['string', 'null'], format: 'date-time' },
            },
            required: [
              'id',
              'applicationId',
              'status',
              'quarantineKey',
              'originalFilename',
              'declaredSize',
              'declaredMime',
              'expiresAt',
              'createdAt',
            ],
          },
          401: { description: 'Unauthorized', ...problemDetailsSchema },
          404: { description: 'Session not found', ...problemDetailsSchema },
        },
      },
      preHandler: [authenticateApiKey(apiKeyService)],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const auth = request.auth!;
      const params = request.params as { id: string };

      const session = await uploadAuthService.getSession(params.id, auth.applicationId);
      if (!session) {
        const problem = createProblemDetails(
          request,
          404,
          'Not Found',
          'Upload session not found',
          ErrorTypes.NOT_FOUND,
        );
        reply.status(404).type('application/problem+json; charset=utf-8').send(problem);
        return;
      }

      return {
        id: session.id,
        applicationId: session.application_id,
        status: session.status,
        quarantineKey: generateQuarantineKey(session.application_id, session.id),
        originalFilename: session.original_filename,
        declaredSize: Number(session.declared_size),
        declaredMime: session.declared_mime,
        expiresAt: session.expires_at.toISOString(),
        createdAt: session.created_at.toISOString(),
        completedAt: session.completed_at ? session.completed_at.toISOString() : null,
      };
    },
  );

  // 3. Abort Upload Session (Scoped)
  app.post(
    '/api/v1/upload/sessions/:id/abort',
    {
      schema: {
        tags: ['Upload Authorization'],
        summary: 'Abort upload session',
        description:
          'Aborts an active or created upload session for the authenticated application.',
        security: [{ ApiKeyAuth: [] }],
        params: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
          },
          required: ['id'],
        },
        response: {
          200: {
            description: 'Session aborted',
            type: 'object',
            properties: {
              sessionId: { type: 'string', format: 'uuid' },
              status: { type: 'string', example: 'FAILED' },
            },
            required: ['sessionId', 'status'],
          },
          401: { description: 'Unauthorized', ...problemDetailsSchema },
          404: { description: 'Session not found', ...problemDetailsSchema },
        },
      },
      preHandler: [authenticateApiKey(apiKeyService)],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const auth = request.auth!;
      const params = request.params as { id: string };

      const aborted = await uploadAuthService.abortSession(
        params.id,
        auth.applicationId,
        'CLIENT_ABORTED',
        request.id,
      );

      if (!aborted) {
        const problem = createProblemDetails(
          request,
          404,
          'Not Found',
          'Upload session not found or already completed',
          ErrorTypes.NOT_FOUND,
        );
        reply.status(404).type('application/problem+json; charset=utf-8').send(problem);
        return;
      }

      return {
        sessionId: aborted.id,
        status: aborted.status,
      };
    },
  );
};

type FastPlugin = FastifyPluginAsync<UploadAuthRouteOptions>;
