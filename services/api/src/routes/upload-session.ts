import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { authenticateApiKey } from '../auth/middleware.js';
import type { ApiKeyService } from '../auth/service.js';
import { UploadSessionService } from '../upload/session-service.js';
import { enforceApplicationOwnership, requireScope } from '../auth/tenant.js';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import { verifyUploadToken } from '../upload/upload-token.js';

export interface UploadSessionRouteOptions {
  apiKeyService: ApiKeyService;
  uploadSessionService: UploadSessionService;
  jwtPrivateKeyPem: string;
  jwtPublicKeyPem: string;
}

const problemDetailsSchema = {
  type: 'object' as const,
  properties: {
    type: { type: 'string', example: 'urn:sug:error:validation' },
    title: { type: 'string', example: 'Validation Error' },
    status: { type: 'integer', example: 400 },
    detail: { type: 'string', example: 'Invalid parameter' },
    instance: { type: 'string', example: '/api/v1/upload/session' },
    requestId: { type: 'string', example: '018f3a5e-7a42-7000-8000-000000000001' },
  },
  required: ['type', 'title', 'status', 'detail', 'instance', 'requestId'],
};

export const uploadSessionRoutes: FastifyPluginAsync<UploadSessionRouteOptions> = async (
  app,
  options,
) => {
  const { apiKeyService, uploadSessionService, jwtPrivateKeyPem, jwtPublicKeyPem } = options;

  const authHook = authenticateApiKey(apiKeyService);
  const scopeHook = requireScope('upload');
  const tenantHook = enforceApplicationOwnership();

  // Handler for creating an upload session
  async function handleCreateSession(request: FastifyRequest, reply: FastifyReply) {
    if (!request.auth) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authentication required',
        ErrorTypes.UNAUTHORIZED,
      );
      return reply.status(401).send(problem);
    }

    const body = (request.body ?? {}) as {
      filename?: string;
      declaredSize?: number;
      declaredMime?: string;
      declaredSha256?: string;
      clientRef?: string;
    };

    if (!body.filename || typeof body.filename !== 'string') {
      const problem = createProblemDetails(
        request,
        400,
        'Validation Error',
        'filename is required and must be a string',
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    if (body.declaredSize === undefined || typeof body.declaredSize !== 'number') {
      const problem = createProblemDetails(
        request,
        400,
        'Validation Error',
        'declaredSize is required and must be a number',
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    if (!body.declaredMime || typeof body.declaredMime !== 'string') {
      const problem = createProblemDetails(
        request,
        400,
        'Validation Error',
        'declaredMime is required and must be a string',
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    try {
      const session = await uploadSessionService.createSession({
        app: request.auth,
        filename: body.filename,
        declaredSize: body.declaredSize,
        declaredMime: body.declaredMime,
        declaredSha256: body.declaredSha256,
        clientRef: body.clientRef,
        clientIp: request.ip,
        requestId: request.id,
        jwtPrivateKeyPem,
      });

      return reply.status(201).send(session);
    } catch (err: unknown) {
      const errorObj = err as Record<string, unknown>;
      const statusCode = typeof errorObj.statusCode === 'number' ? errorObj.statusCode : 400;
      const message = err instanceof Error ? err.message : String(err);

      let errorType: string = ErrorTypes.VALIDATION;
      let errorTitle = 'Validation Error';

      if (statusCode === 409) {
        errorType = 'urn:sug:error:conflict';
        errorTitle = 'Conflict';
      } else if (statusCode === 403) {
        errorType = ErrorTypes.FORBIDDEN;
        errorTitle = 'Forbidden';
      }

      const problem = createProblemDetails(
        request,
        statusCode,
        errorTitle,
        message,
        errorType,
        errorObj.details as Record<string, unknown> | undefined,
      );

      return reply.status(statusCode).send(problem);
    }
  }

  // Handler for claiming an upload session (with upload token)
  async function handleClaimSession(request: FastifyRequest, reply: FastifyReply) {
    const authHeader = request.headers.authorization;
    if (!authHeader || typeof authHeader !== 'string') {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Upload token required in Authorization header',
        ErrorTypes.UNAUTHORIZED,
      );
      return reply.status(401).send(problem);
    }

    const trimmed = authHeader.trim();
    if (!trimmed.startsWith('Bearer ') && !trimmed.startsWith('bearer ')) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Invalid authorization scheme; expected Bearer upload token',
        ErrorTypes.UNAUTHORIZED,
      );
      return reply.status(401).send(problem);
    }

    const token = trimmed.slice(7).trim();
    let tokenPayload;

    try {
      tokenPayload = await verifyUploadToken(token, jwtPublicKeyPem);
    } catch (err) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        `Upload token verification failed: ${err instanceof Error ? err.message : String(err)}`,
        ErrorTypes.UNAUTHORIZED,
      );
      return reply.status(401).send(problem);
    }

    const params = request.params as { id: string };
    if (params.id.toLowerCase() !== tokenPayload.sid.toLowerCase()) {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        'Token sid claim does not match requested session ID',
        ErrorTypes.FORBIDDEN,
      );
      return reply.status(403).send(problem);
    }

    const claimResult = await uploadSessionService.claimSession(
      params.id,
      tokenPayload.sub,
      tokenPayload.jti,
      request.id,
    );

    if (claimResult.success) {
      return reply.status(200).send({
        claimed: true,
        sessionId: params.id,
        status: claimResult.session.status,
      });
    }

    if (claimResult.reason === 'ALREADY_CLAIMED') {
      const problem = createProblemDetails(
        request,
        409,
        'Conflict',
        'Upload session has already been claimed',
        'urn:sug:error:conflict',
      );
      return reply.status(409).send(problem);
    }

    if (claimResult.reason === 'SESSION_EXPIRED') {
      const problem = createProblemDetails(
        request,
        410,
        'Gone',
        'Upload session has expired',
        'urn:sug:error:expired',
      );
      return reply.status(410).send(problem);
    }

    const problem = createProblemDetails(
      request,
      404,
      'Not Found',
      'Upload session not found',
      ErrorTypes.NOT_FOUND,
    );
    return reply.status(404).send(problem);
  }

  const uploadSessionSchema = {
    tags: ['Upload Session'],
    summary: 'Create upload session',
    description:
      'Evaluates file metadata against active policy, pins policy version & hash, and issues a 10-minute single-use EdDSA upload token.',
    security: [{ ApiKeyAuth: [] }],
    body: {
      type: 'object',
      properties: {
        filename: { type: 'string', minLength: 1, maxLength: 255 },
        declaredSize: { type: 'integer', minimum: 1, maximum: 52428800 },
        declaredMime: { type: 'string', minLength: 1, maxLength: 127 },
        declaredSha256: { type: 'string', pattern: '^[0-9a-fA-F]{64}$' },
        clientRef: { type: 'string', maxLength: 128 },
      },
      required: ['filename', 'declaredSize', 'declaredMime'],
    },
    response: {
      201: {
        description: 'Upload session created and token issued',
        type: 'object',
        properties: {
          sessionId: { type: 'string', format: 'uuid' },
          uploadToken: { type: 'string' },
          tokenJti: { type: 'string', format: 'uuid' },
          expiresAt: { type: 'string', format: 'date-time' },
          expiresInSeconds: { type: 'integer', example: 600 },
          quarantineKey: { type: 'string' },
          policy: {
            type: 'object',
            properties: {
              id: { type: 'string', format: 'uuid' },
              version: { type: 'integer' },
              documentSha256: { type: 'string' },
            },
          },
          precheck: {
            type: 'object',
            properties: {
              allowed: { type: 'boolean' },
              normalizedFilename: { type: 'string' },
            },
          },
        },
      },
      400: { description: 'Precheck validation error', ...problemDetailsSchema },
      401: { description: 'Unauthorized', ...problemDetailsSchema },
      403: { description: 'Forbidden', ...problemDetailsSchema },
      409: { description: 'No active policy', ...problemDetailsSchema },
    },
  };

  // POST /api/v1/upload/session & /upload/session
  app.post('/api/v1/upload/session', {
    preHandler: [authHook, scopeHook, tenantHook],
    schema: uploadSessionSchema,
    handler: handleCreateSession,
  });

  app.post('/api/v1/upload-sessions', {
    preHandler: [authHook, scopeHook, tenantHook],
    schema: {
      ...uploadSessionSchema,
      hide: true,
    },
    handler: handleCreateSession,
  });

  app.post('/upload/session', {
    preHandler: [authHook, scopeHook, tenantHook],
    schema: {
      ...uploadSessionSchema,
      hide: true,
    },
    handler: handleCreateSession,
  });

  // POST /api/v1/upload/session/:id/claim & /upload/session/:id/claim
  app.post('/api/v1/upload/session/:id/claim', {
    schema: {
      tags: ['Upload Session'],
      summary: 'Claim upload session',
      description: 'Single-use atomic claim of an upload session via short-lived upload JWT.',
      params: {
        type: 'object',
        properties: { id: { type: 'string', format: 'uuid' } },
        required: ['id'],
      },
      response: {
        200: {
          type: 'object',
          properties: {
            claimed: { type: 'boolean', example: true },
            sessionId: { type: 'string', format: 'uuid' },
            status: { type: 'string', example: 'UPLOADING' },
          },
        },
        401: { description: 'Unauthorized token', ...problemDetailsSchema },
        403: { description: 'Forbidden', ...problemDetailsSchema },
        404: { description: 'Not found', ...problemDetailsSchema },
        409: { description: 'Already claimed', ...problemDetailsSchema },
        410: { description: 'Expired session', ...problemDetailsSchema },
      },
    },
    handler: handleClaimSession,
  });

  app.post('/upload/session/:id/claim', {
    schema: { hide: true },
    handler: handleClaimSession,
  });
};
