import type { FastifyRequest, FastifyReply, preHandlerHookHandler } from 'fastify';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import { verifyDashboardToken } from './jwt.js';
import type { SafeUser, UserRole } from './user-types.js';

declare module 'fastify' {
  interface FastifyRequest {
    user?: SafeUser | undefined;
  }
}

/**
 * Creates a Fastify preHandler hook for verifying dashboard user EdDSA JWT access tokens.
 *
 * Security Invariants:
 * 1. Checks Authorization header for valid Bearer token.
 * 2. Rejects missing, malformed, or multiple authorization headers.
 * 3. Validates EdDSA signature against public key, strictly enforcing aud=sug-dashboard and iss=sug-api.
 * 4. Attaches strongly-typed request.user context.
 * 5. Returns generic 401 Problem Details on any validation failure.
 */
export function createAuthenticateUserHook(publicKeyPem: string): preHandlerHookHandler {
  return async function authenticateUser(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const authHeader = request.headers.authorization;

    if (!authHeader) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authentication required',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return reply.status(401).send(problem);
    }

    if (Array.isArray(authHeader) || authHeader.includes(',')) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Duplicate or multiple authorization headers detected',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.header('WWW-Authenticate', 'Bearer error="invalid_token"');
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
      reply.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return reply.status(401).send(problem);
    }

    const token = trimmed.slice(7).trim();
    if (!token) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Empty bearer token supplied',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return reply.status(401).send(problem);
    }

    try {
      const payload = await verifyDashboardToken(token, publicKeyPem);

      request.user = {
        id: payload.sub,
        email: payload.email,
        role: payload.role,
      };
    } catch {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Invalid or expired token',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      return reply.status(401).send(problem);
    }
  };
}

/**
 * Reusable RBAC authorization guard enforcing role ceiling.
 * Must be executed after authenticateUser.
 *
 * Example:
 *   preHandler: [authenticateUser, requireRole('admin')]
 *   preHandler: [authenticateUser, requireRole('admin', 'analyst')]
 */
export function requireRole(...allowedRoles: UserRole[]): preHandlerHookHandler {
  const allowedSet = new Set<UserRole>(allowedRoles);

  return async function checkRole(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    if (!request.user) {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authentication required',
        ErrorTypes.UNAUTHORIZED,
      );
      return reply.status(401).send(problem);
    }

    if (!allowedSet.has(request.user.role)) {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        `Access denied: role '${request.user.role}' is not authorized for this resource`,
        ErrorTypes.FORBIDDEN,
      );
      return reply.status(403).send(problem);
    }
  };
}
