import type { FastifyReply, FastifyRequest } from 'fastify';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';

/**
 * Fastify pre-handler hook that enforces strict tenant/application isolation.
 * Verifies that any client-supplied application ID in params, query, or body strictly
 * matches the authenticated application ID from the API key context.
 *
 * Prevents client-side application ID spoofing and horizontal privilege escalation.
 */
export function enforceApplicationOwnership() {
  return async function preHandler(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const auth = request.auth;
    if (!auth) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authentication required',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).type('application/problem+json; charset=utf-8').send(problem);
      return;
    }

    const params = (request.params as Record<string, unknown> | undefined) ?? {};
    const query = (request.query as Record<string, unknown> | undefined) ?? {};
    const body = (request.body as Record<string, unknown> | undefined) ?? {};

    const suppliedAppId =
      (params.applicationId as string | undefined) ??
      (params.appId as string | undefined) ??
      (query.applicationId as string | undefined) ??
      (body.applicationId as string | undefined);

    if (suppliedAppId !== undefined && suppliedAppId !== null) {
      const normalizedSupplied = String(suppliedAppId).trim().toLowerCase();
      const normalizedAuth = auth.applicationId.trim().toLowerCase();

      if (normalizedSupplied !== normalizedAuth) {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'Access denied: client application ID does not match authenticated credential context',
          ErrorTypes.FORBIDDEN,
        );
        reply.status(403).type('application/problem+json; charset=utf-8').send(problem);
        return;
      }
    }
  };
}

/**
 * Fastify pre-handler hook that enforces presence of a specific permission scope.
 */
export function requireScope(requiredScope: string) {
  return async function preHandler(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const auth = request.auth;
    if (!auth) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authentication required',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).type('application/problem+json; charset=utf-8').send(problem);
      return;
    }

    // Check if the API key holds the required scope or a wildcard/admin scope
    const hasScope =
      auth.scopes.includes(requiredScope) ||
      auth.scopes.includes('*') ||
      auth.scopes.includes('admin');

    if (!hasScope) {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        `Access denied: API key lacks required scope '${requiredScope}'`,
        ErrorTypes.FORBIDDEN,
      );
      reply.status(403).type('application/problem+json; charset=utf-8').send(problem);
      return;
    }
  };
}
