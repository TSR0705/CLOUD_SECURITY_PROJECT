import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from 'fastify';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import type { UserService } from '../auth/user-service.js';
import { createDashboardToken, derivePublicKeyPem } from '../auth/jwt.js';
import { createAuthenticateUserHook, requireRole } from '../auth/rbac.js';
import type { LoginRequestBody } from '../auth/user-types.js';

export const REFRESH_COOKIE_NAME = 'sug_refresh_token';

export interface UserAuthRouteOptions {
  userService: UserService;
  jwtPrivateKeyPem: string;
  isProduction?: boolean;
}

export const userAuthRoutes: FastifyPluginAsync<UserAuthRouteOptions> = async (
  fastify,
  options,
) => {
  const { userService, jwtPrivateKeyPem, isProduction = false } = options;
  const publicKeyPem = derivePublicKeyPem(jwtPrivateKeyPem);
  const authenticateUser = createAuthenticateUserHook(publicKeyPem);

  const cookieOptions = {
    path: '/api/v1/auth',
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict' as const,
    maxAge: 7 * 24 * 60 * 60, // 7 days
  };

  /**
   * POST /api/v1/auth/login
   * Authenticates dashboard user and returns short-lived EdDSA JWT and HttpOnly refresh cookie.
   */
  fastify.post<{ Body: LoginRequestBody }>(
    '/api/v1/auth/login',
    {
      schema: {
        summary: 'Dashboard User Login',
        description:
          'Authenticates a dashboard user using Argon2id, issues a short-lived EdDSA JWT, and sets an HttpOnly refresh cookie.',
        tags: ['Authentication'],
        body: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string', minLength: 1 },
          },
          additionalProperties: false,
        },
        response: {
          200: {
            type: 'object',
            properties: {
              accessToken: { type: 'string' },
              tokenType: { type: 'string', example: 'Bearer' },
              expiresIn: { type: 'integer', example: 900 },
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string', format: 'uuid' },
                  email: { type: 'string', format: 'email' },
                  role: { type: 'string', enum: ['admin', 'analyst', 'auditor'] },
                },
              },
            },
          },
          401: {
            type: 'object',
            properties: {
              type: { type: 'string' },
              title: { type: 'string' },
              status: { type: 'integer' },
              detail: { type: 'string' },
              instance: { type: 'string' },
              requestId: { type: 'string' },
            },
          },
          423: {
            type: 'object',
            properties: {
              type: { type: 'string' },
              title: { type: 'string' },
              status: { type: 'integer' },
              detail: { type: 'string' },
              instance: { type: 'string' },
              requestId: { type: 'string' },
            },
          },
        },
      },
    },
    async (request: FastifyRequest<{ Body: LoginRequestBody }>, reply: FastifyReply) => {
      const { email, password } = request.body || {};

      const authResult = await userService.authenticate(email, password, request.ip, request.id);

      if (!authResult.success) {
        if (authResult.locked) {
          const problem = createProblemDetails(
            request,
            423,
            'Locked',
            'Account is temporarily locked due to consecutive failed login attempts. Try again later.',
            'urn:sug:error:locked',
          );
          return reply.status(423).send(problem);
        }

        const problem = createProblemDetails(
          request,
          401,
          'Unauthorized',
          'Invalid credentials',
          ErrorTypes.UNAUTHORIZED,
        );
        reply.header('WWW-Authenticate', 'Bearer error="invalid_credentials"');
        return reply.status(401).send(problem);
      }

      const user = authResult.user!;

      // 1. Issue short-lived EdDSA access token (15 mins)
      const accessToken = await createDashboardToken(user, jwtPrivateKeyPem);

      // 2. Issue long-lived high-entropy refresh token (7 days)
      const { rawToken } = await userService.createRefreshToken(user.id);

      // 3. Set refresh token in HttpOnly; Secure; SameSite=Strict cookie
      reply.setCookie(REFRESH_COOKIE_NAME, rawToken, cookieOptions);

      return reply.status(200).send({
        accessToken,
        tokenType: 'Bearer',
        expiresIn: 900,
        user,
      });
    },
  );

  /**
   * POST /api/v1/auth/refresh
   * Rotates refresh token and issues a new access token.
   */
  fastify.post(
    '/api/v1/auth/refresh',
    {
      schema: {
        summary: 'Rotate Refresh Token',
        description:
          'Validates the HttpOnly refresh token cookie, rotates the token, and issues a new access token.',
        tags: ['Authentication'],
        response: {
          200: {
            type: 'object',
            properties: {
              accessToken: { type: 'string' },
              tokenType: { type: 'string', example: 'Bearer' },
              expiresIn: { type: 'integer', example: 900 },
            },
          },
          401: {
            type: 'object',
            properties: {
              type: { type: 'string' },
              title: { type: 'string' },
              status: { type: 'integer' },
              detail: { type: 'string' },
              instance: { type: 'string' },
              requestId: { type: 'string' },
            },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const rawToken = request.cookies[REFRESH_COOKIE_NAME];

      if (!rawToken) {
        const problem = createProblemDetails(
          request,
          401,
          'Unauthorized',
          'Missing refresh token cookie',
          ErrorTypes.UNAUTHORIZED,
        );
        return reply.status(401).send(problem);
      }

      const rotateResult = await userService.rotateRefreshToken(rawToken, request.id);

      if (!rotateResult.success) {
        reply.clearCookie(REFRESH_COOKIE_NAME, { path: cookieOptions.path });

        const detail = rotateResult.reuseDetected
          ? 'Refresh token reuse detected; all active sessions revoked'
          : 'Invalid or expired refresh token';

        const problem = createProblemDetails(
          request,
          401,
          'Unauthorized',
          detail,
          ErrorTypes.UNAUTHORIZED,
        );
        return reply.status(401).send(problem);
      }

      // Rotate cookie with new raw token
      reply.setCookie(REFRESH_COOKIE_NAME, rotateResult.newRawToken!, cookieOptions);

      // Issue new access token
      const accessToken = await createDashboardToken(rotateResult.user!, jwtPrivateKeyPem);

      return reply.status(200).send({
        accessToken,
        tokenType: 'Bearer',
        expiresIn: 900,
      });
    },
  );

  /**
   * POST /api/v1/auth/logout
   * Revokes refresh token in database and clears cookie.
   */
  fastify.post(
    '/api/v1/auth/logout',
    {
      schema: {
        summary: 'User Logout',
        description: 'Revokes the active refresh token and clears the authentication cookie.',
        tags: ['Authentication'],
        response: {
          200: {
            type: 'object',
            properties: {
              message: { type: 'string' },
            },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const rawToken = request.cookies[REFRESH_COOKIE_NAME];

      if (rawToken) {
        await userService.revokeRefreshToken(rawToken, request.id);
      }

      reply.clearCookie(REFRESH_COOKIE_NAME, { path: cookieOptions.path });

      return reply.status(200).send({ message: 'Logged out successfully' });
    },
  );

  /**
   * GET /api/v1/auth/me
   * Returns current authenticated user context.
   */
  fastify.get(
    '/api/v1/auth/me',
    {
      preHandler: [authenticateUser],
      schema: {
        summary: 'Get Current User Profile',
        description: 'Returns profile of currently authenticated dashboard user.',
        tags: ['Authentication'],
        security: [{ UserAuth: [] }],
        response: {
          200: {
            type: 'object',
            properties: {
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string', format: 'uuid' },
                  email: { type: 'string', format: 'email' },
                  role: { type: 'string', enum: ['admin', 'analyst', 'auditor'] },
                },
              },
            },
          },
        },
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      return reply.status(200).send({ user: request.user });
    },
  );

  /**
   * RBAC Probe Endpoints for Verification & Testing
   */
  fastify.get(
    '/api/v1/auth/admin-only',
    {
      preHandler: [authenticateUser, requireRole('admin')],
      schema: {
        summary: 'Admin-Only Route Guard Probe',
        tags: ['RBAC Verification'],
        security: [{ UserAuth: [] }],
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      return reply.status(200).send({ message: 'Admin access granted', role: request.user?.role });
    },
  );

  fastify.get(
    '/api/v1/auth/analyst-only',
    {
      preHandler: [authenticateUser, requireRole('admin', 'analyst')],
      schema: {
        summary: 'Analyst Route Guard Probe',
        tags: ['RBAC Verification'],
        security: [{ UserAuth: [] }],
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      return reply
        .status(200)
        .send({ message: 'Analyst access granted', role: request.user?.role });
    },
  );

  fastify.get(
    '/api/v1/auth/auditor-only',
    {
      preHandler: [authenticateUser, requireRole('admin', 'auditor')],
      schema: {
        summary: 'Auditor Route Guard Probe',
        tags: ['RBAC Verification'],
        security: [{ UserAuth: [] }],
      },
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      return reply
        .status(200)
        .send({ message: 'Auditor access granted', role: request.user?.role });
    },
  );
};
