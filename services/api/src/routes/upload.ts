import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { Readable } from 'node:stream';
import type { ApiKeyService } from '../auth/service.js';
import { StreamingUploadService } from '../upload/streaming-service.js';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import { verifyUploadToken } from '../upload/upload-token.js';
import { StreamLimitExceededError, StreamTimeoutError } from '../upload/counting-stream.js';
import { UploadSessionError } from '../upload/session-service.js';
import { AlreadyExists } from '@sug/storage';

export interface UploadRouteOptions {
  apiKeyService: ApiKeyService;
  streamingUploadService: StreamingUploadService;
  jwtPublicKeyPem: string;
}

const problemDetailsSchema = {
  type: 'object' as const,
  properties: {
    type: { type: 'string', example: 'urn:sug:error:validation' },
    title: { type: 'string', example: 'Validation Error' },
    status: { type: 'integer', example: 400 },
    detail: { type: 'string', example: 'Invalid parameter' },
    instance: { type: 'string', example: '/upload/018f3a5e-7a42-7000-8000-000000000001' },
    requestId: { type: 'string', example: '018f3a5e-7a42-7000-8000-000000000001' },
  },
  required: ['type', 'title', 'status', 'detail', 'instance', 'requestId'],
};

export const uploadRoutes: FastifyPluginAsync<UploadRouteOptions> = async (app, options) => {
  const { apiKeyService, streamingUploadService, jwtPublicKeyPem } = options;

  // Custom content type parser for zero-buffering raw streaming
  app.addContentTypeParser('*', (request, payload, done) => {
    const contentType = request.headers['content-type'] || '';
    if (contentType.toLowerCase().includes('multipart/')) {
      const err = new Error(
        'Multipart uploads are not permitted; stream raw bytes with application/octet-stream',
      );
      (err as unknown as { statusCode: number }).statusCode = 415;
      done(err);
      return;
    }
    // Pass raw stream directly without buffering in memory
    done(null, payload);
  });

  // Handler for streaming PUT /upload/:id
  async function handleStreamingPut(request: FastifyRequest, reply: FastifyReply) {
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
    const requestStream =
      request.body && typeof (request.body as { on?: unknown }).on === 'function'
        ? (request.body as Readable)
        : Buffer.isBuffer(request.body) || typeof request.body === 'string'
          ? Readable.from(request.body)
          : request.raw;

    try {
      const result = await streamingUploadService.handleStreamingUpload({
        sessionId: params.id,
        tokenPayload,
        requestStream,
        rawContentLength: request.headers['content-length'],
        clientIp: request.ip,
        requestId: request.id,
      });

      return reply.status(202).send({
        fileId: result.fileId,
        fileVersionId: result.fileVersionId,
        scanJobId: result.scanJobId,
        status: result.status,
        versionId: result.versionId,
        size: result.size,
        sha256: result.sha256,
        identity: result.identity,
      });
    } catch (err: unknown) {
      // 1. Limit Exceeded -> 413 Payload Too Large
      if (err instanceof StreamLimitExceededError) {
        if (typeof requestStream.resume === 'function') {
          requestStream.resume();
        }
        const problem = createProblemDetails(
          request,
          413,
          'Payload Too Large',
          err.message,
          'urn:sug:error:payload-too-large',
          { limit: err.limit, bytesReceived: err.bytesReceived },
        );
        return reply.status(413).send(problem);
      }

      // 2. Stream Idle Timeout -> 408 Request Timeout
      if (err instanceof StreamTimeoutError) {
        if (typeof requestStream.resume === 'function') {
          requestStream.resume();
        }
        const problem = createProblemDetails(
          request,
          408,
          'Request Timeout',
          err.message,
          'urn:sug:error:timeout',
        );
        return reply.status(408).send(problem);
      }

      // 3. Storage collision / AlreadyExists -> 409 Conflict
      if (err instanceof AlreadyExists) {
        const problem = createProblemDetails(
          request,
          409,
          'Conflict',
          'Quarantine object already exists for this session',
          'urn:sug:error:conflict',
        );
        return reply.status(409).send(problem);
      }

      // 4. UploadSessionError -> mapped status code
      if (err instanceof UploadSessionError) {
        let errorType: string = ErrorTypes.VALIDATION;
        let errorTitle = 'Validation Error';

        if (err.statusCode === 409) {
          errorType = 'urn:sug:error:conflict';
          errorTitle = 'Conflict';
        } else if (err.statusCode === 410) {
          errorType = 'urn:sug:error:expired';
          errorTitle = 'Gone';
        } else if (err.statusCode === 403) {
          errorType = ErrorTypes.FORBIDDEN;
          errorTitle = 'Forbidden';
        } else if (err.statusCode === 404) {
          errorType = ErrorTypes.NOT_FOUND;
          errorTitle = 'Not Found';
        }

        const problem = createProblemDetails(
          request,
          err.statusCode,
          errorTitle,
          err.message,
          errorType,
          err.details as Record<string, unknown> | undefined,
        );
        return reply.status(err.statusCode).send(problem);
      }

      // Generic error handling
      const problem = createProblemDetails(
        request,
        500,
        'Internal Server Error',
        err instanceof Error ? err.message : 'Upload processing failed',
        ErrorTypes.INTERNAL,
      );
      return reply.status(500).send(problem);
    }
  }

  // Handler for GET /upload/:id/status
  async function handleGetStatus(request: FastifyRequest, reply: FastifyReply) {
    const authHeader = request.headers.authorization;
    if (!authHeader || typeof authHeader !== 'string') {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authorization header required',
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
        'Invalid authorization scheme; expected Bearer token',
        ErrorTypes.UNAUTHORIZED,
      );
      return reply.status(401).send(problem);
    }

    const rawToken = trimmed.slice(7).trim();
    let applicationId: string | null = null;

    // Check if upload JWT
    try {
      const payload = await verifyUploadToken(rawToken, jwtPublicKeyPem);
      applicationId = payload.sub;
    } catch {
      // Not an upload JWT; attempt API key authentication
      const apiKeyResult = await apiKeyService.verifyApiKey(rawToken, {
        ip: request.ip,
        requestId: request.id,
      });
      if (apiKeyResult.isValid && apiKeyResult.app && apiKeyResult.app.scopes.includes('upload')) {
        applicationId = apiKeyResult.app.applicationId;
      }
    }

    if (!applicationId) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Invalid upload token or API key',
        ErrorTypes.UNAUTHORIZED,
      );
      return reply.status(401).send(problem);
    }

    const params = request.params as { id: string };
    const statusResult = await streamingUploadService.getUploadStatus(params.id, applicationId);

    if (!statusResult) {
      const problem = createProblemDetails(
        request,
        404,
        'Not Found',
        'Upload session not found',
        ErrorTypes.NOT_FOUND,
      );
      return reply.status(404).send(problem);
    }

    return reply.status(200).send(statusResult);
  }

  const streamingPutSchema = {
    tags: ['Upload Ingestion'],
    summary: 'Raw HTTP streaming upload into quarantine',
    description:
      'Pipes raw incoming bytes directly into quarantine storage with zero disk buffering. Enforces effectiveLimit = min(policy.maxFileSize, declaredSize), 30s idle timeout, and atomic session claim.',
    params: {
      type: 'object',
      properties: { id: { type: 'string', format: 'uuid' } },
      required: ['id'],
    },
    response: {
      202: {
        description: 'Upload accepted into quarantine and scan job queued',
        type: 'object',
        properties: {
          fileId: { type: 'string', format: 'uuid' },
          fileVersionId: { type: 'string', format: 'uuid' },
          scanJobId: { type: 'string', format: 'uuid' },
          status: { type: 'string', example: 'QUARANTINED' },
          versionId: { type: 'string' },
          size: { type: 'integer' },
          sha256: { type: 'string' },
          identity: {
            type: 'object',
            properties: {
              bucket: { type: 'string' },
              objectKey: { type: 'string' },
              versionId: { type: 'string' },
              sha256: { type: 'string', pattern: '^[0-9a-f]{64}$' },
              sizeBytes: { type: 'integer', minimum: 0 },
            },
            required: ['bucket', 'objectKey', 'versionId', 'sha256', 'sizeBytes'],
          },
        },
      },
      400: { description: 'Validation error', ...problemDetailsSchema },
      401: { description: 'Unauthorized', ...problemDetailsSchema },
      403: { description: 'Forbidden', ...problemDetailsSchema },
      404: { description: 'Not found', ...problemDetailsSchema },
      409: { description: 'Conflict (already claimed)', ...problemDetailsSchema },
      410: { description: 'Expired session', ...problemDetailsSchema },
      413: { description: 'Payload too large', ...problemDetailsSchema },
      415: { description: 'Unsupported media type (multipart rejected)', ...problemDetailsSchema },
    },
  };

  const getStatusSchema = {
    tags: ['Upload Ingestion'],
    summary: 'Get upload session status',
    description: 'Retrieves current status and file metadata for an upload session.',
    params: {
      type: 'object',
      properties: { id: { type: 'string', format: 'uuid' } },
      required: ['id'],
    },
    response: {
      200: {
        description: 'Upload status retrieved',
        type: 'object',
        properties: {
          sessionId: { type: 'string', format: 'uuid' },
          status: { type: 'string' },
          fileId: { type: 'string', format: 'uuid', nullable: true },
          fileStatus: { type: 'string', nullable: true },
          identity: {
            type: 'object',
            nullable: true,
            properties: {
              bucket: { type: 'string' },
              objectKey: { type: 'string' },
              versionId: { type: 'string' },
              sha256: { type: 'string', pattern: '^[0-9a-f]{64}$' },
              sizeBytes: { type: 'integer', minimum: 0 },
            },
            required: ['bucket', 'objectKey', 'versionId', 'sha256', 'sizeBytes'],
          },
          createdAt: { type: 'string' },
          completedAt: { type: 'string', nullable: true },
          expiresAt: { type: 'string', nullable: true },
        },
      },
      401: { description: 'Unauthorized', ...problemDetailsSchema },
      404: { description: 'Not found', ...problemDetailsSchema },
    },
  };

  // PUT /upload/:id & PUT /api/v1/upload/:id
  app.put('/upload/:id', {
    bodyLimit: 52_428_800,
    schema: streamingPutSchema,
    handler: handleStreamingPut,
  });

  app.put('/api/v1/upload/:id', {
    bodyLimit: 52_428_800,
    schema: {
      ...streamingPutSchema,
      hide: true,
    },
    handler: handleStreamingPut,
  });

  // GET /upload/:id/status & GET /api/v1/upload/:id/status
  app.get('/upload/:id/status', {
    schema: getStatusSchema,
    handler: handleGetStatus,
  });

  app.get('/api/v1/upload/:id/status', {
    schema: {
      ...getStatusSchema,
      hide: true,
    },
    handler: handleGetStatus,
  });
};
