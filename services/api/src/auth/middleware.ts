import type { FastifyReply, FastifyRequest } from 'fastify';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import type { ApiKeyService } from './service.js';
import type { AuthenticatedApplication } from './types.js';

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthenticatedApplication | undefined;
  }
}

export interface AuthenticateApiKeyOptions {
  requiredScopes?: string[] | undefined;
}

/**
 * Fastify pre-handler hook that enforces API key authentication.
 * Extracts "Authorization: Bearer <sug_prefix_secret>", verifies the HMAC in constant time,
 * and attaches authenticated application context to the request.
 *
 * Rejects missing, malformed, invalid, expired, or revoked keys with generic RFC 7807/9457 401 errors.
 */
export function authenticateApiKey(
  service: ApiKeyService,
  options: AuthenticateApiKeyOptions = {},
) {
  return async function preHandler(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const rawHeader = request.headers.authorization;

    // 1. Missing header
    if (!rawHeader) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Missing or invalid authorization header',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).type('application/problem+json; charset=utf-8').send(problem);
      return;
    }

    // 2. Reject duplicate authorization headers (array format or comma-separated concatenation by HTTP parser)
    if (Array.isArray(rawHeader) || (typeof rawHeader === 'string' && rawHeader.includes(','))) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Duplicate or ambiguous authorization headers',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).type('application/problem+json; charset=utf-8').send(problem);
      return;
    }

    // 3. Scheme check (must be Bearer)
    if (!rawHeader.startsWith('Bearer ') && !rawHeader.startsWith('bearer ')) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Invalid authorization scheme, Bearer scheme required',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).type('application/problem+json; charset=utf-8').send(problem);
      return;
    }

    const token = rawHeader.slice(7).trim();

    // 4. Token validation
    if (!token || /[\r\n\t]/.test(token)) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authentication failed',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).type('application/problem+json; charset=utf-8').send(problem);
      return;
    }

    // 5. Verify against database and compute HMAC in constant time
    const result = await service.verifyApiKey(token, {
      ip: request.ip,
      requestId: request.id,
    });

    if (!result.isValid || !result.app) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authentication failed',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).type('application/problem+json; charset=utf-8').send(problem);
      return;
    }

    // 6. Enforce required scopes if specified
    if (options.requiredScopes && options.requiredScopes.length > 0) {
      const hasAllScopes = options.requiredScopes.every((scope) =>
        result.app?.scopes.includes(scope),
      );
      if (!hasAllScopes) {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'Insufficient API key scopes',
          ErrorTypes.FORBIDDEN,
        );
        reply.status(403).type('application/problem+json; charset=utf-8').send(problem);
        return;
      }
    }

    // 7. Attach safe context to request
    request.auth = result.app;
  };
}
