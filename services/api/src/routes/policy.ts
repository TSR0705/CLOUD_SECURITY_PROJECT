import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { ApiKeyService } from '../auth/service.js';
import { PolicyService } from '../policy/policy-service.js';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import { verifyDashboardToken } from '../auth/jwt.js';

export interface PolicyRouteOptions {
  apiKeyService: ApiKeyService;
  policyService: PolicyService;
  jwtPublicKeyPem: string;
}

const problemDetailsSchema = {
  type: 'object' as const,
  properties: {
    type: { type: 'string', example: 'urn:sug:error:validation' },
    title: { type: 'string', example: 'Validation Error' },
    status: { type: 'integer', example: 400 },
    detail: { type: 'string', example: 'Invalid parameter' },
    instance: { type: 'string', example: '/api/v1/policies' },
    requestId: { type: 'string', example: '018f3a5e-7a42-7000-8000-000000000001' },
  },
  required: ['type', 'title', 'status', 'detail', 'instance', 'requestId'],
};

const policyResponseSchema = {
  type: 'object' as const,
  properties: {
    id: { type: 'string', format: 'uuid' },
    applicationId: { type: 'string', format: 'uuid' },
    version: { type: 'integer', example: 1 },
    schema: { type: 'string', example: 'sug.policy/v1' },
    document: { type: 'object', additionalProperties: true },
    documentSha256: { type: 'string', example: '0123456789abcdef...' },
    isActive: { type: 'boolean', example: true },
    createdAt: { type: 'string', format: 'date-time' },
  },
  required: [
    'id',
    'applicationId',
    'version',
    'schema',
    'document',
    'documentSha256',
    'isActive',
    'createdAt',
  ],
};

export const policyRoutes: FastifyPluginAsync<PolicyRouteOptions> = async (app, options) => {
  const { apiKeyService, policyService, jwtPublicKeyPem } = options;

  /**
   * Dual authenticator supporting either P6 API keys or P7 Dashboard JWTs.
   */
  async function authenticatePolicyCaller(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<boolean> {
    const authHeader = request.headers.authorization;
    if (!authHeader || typeof authHeader !== 'string') {
      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Authentication required (API key or dashboard user token)',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).send(problem);
      return false;
    }

    const trimmed = authHeader.trim();

    // 1. Try API Key authentication
    if (
      trimmed.startsWith('sug_') ||
      trimmed.startsWith('Bearer sug_') ||
      trimmed.startsWith('bearer sug_')
    ) {
      const rawKey = trimmed.replace(/^Bearer\s+/i, '').trim();
      const authResult = await apiKeyService.verifyApiKey(rawKey, {
        ip: request.ip,
        requestId: request.id,
      });

      if (authResult.isValid && authResult.app) {
        request.auth = authResult.app;
        return true;
      }

      const problem = createProblemDetails(
        request,
        401,
        'Unauthorized',
        'Invalid or revoked API key',
        ErrorTypes.UNAUTHORIZED,
      );
      reply.status(401).send(problem);
      return false;
    }

    // 2. Try User JWT authentication
    if (trimmed.startsWith('Bearer ') || trimmed.startsWith('bearer ')) {
      const token = trimmed.slice(7).trim();
      try {
        const payload = await verifyDashboardToken(token, jwtPublicKeyPem);
        request.user = {
          id: payload.sub,
          email: payload.email,
          role: payload.role,
        };
        return true;
      } catch (err) {
        const problem = createProblemDetails(
          request,
          401,
          'Unauthorized',
          `Invalid access token: ${err instanceof Error ? err.message : String(err)}`,
          ErrorTypes.UNAUTHORIZED,
        );
        reply.status(401).send(problem);
        return false;
      }
    }

    const problem = createProblemDetails(
      request,
      401,
      'Unauthorized',
      'Unrecognized authorization scheme',
      ErrorTypes.UNAUTHORIZED,
    );
    reply.status(401).send(problem);
    return false;
  }

  // Handler for creating a policy
  async function handleCreatePolicy(request: FastifyRequest, reply: FastifyReply) {
    const authenticated = await authenticatePolicyCaller(request, reply);
    if (!authenticated) return;

    const body = (request.body ?? {}) as Record<string, unknown>;

    // Resolve application context and creator
    let targetAppId: string;
    let createdBy: string;

    if (request.auth) {
      targetAppId = request.auth.applicationId;
      createdBy = request.auth.apiKeyId;

      // Tenant isolation: caller cannot specify another application
      if (
        body.applicationId &&
        String(body.applicationId).toLowerCase() !== targetAppId.toLowerCase()
      ) {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'Access denied: client application ID does not match authenticated credential context',
          ErrorTypes.FORBIDDEN,
        );
        return reply.status(403).send(problem);
      }
    } else if (request.user) {
      if (request.user.role !== 'admin') {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'Only admin users can create security policies',
          ErrorTypes.FORBIDDEN,
        );
        return reply.status(403).send(problem);
      }

      if (!body.applicationId || typeof body.applicationId !== 'string') {
        const problem = createProblemDetails(
          request,
          400,
          'Validation Error',
          'applicationId is required when creating policy as admin user',
          ErrorTypes.VALIDATION,
        );
        return reply.status(400).send(problem);
      }

      targetAppId = String(body.applicationId);
      createdBy = request.user.id;
    } else {
      return;
    }

    // Determine policy document body
    const docInput = body.document ? body.document : body;
    const setActive = body.setActive === undefined ? true : Boolean(body.setActive);

    try {
      const created = await policyService.createPolicy({
        applicationId: targetAppId,
        document: docInput,
        setActive,
        createdBy,
        requestId: request.id,
      });

      return reply.status(201).send(created);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const problem = createProblemDetails(
        request,
        400,
        'Validation Error',
        `Policy validation failed: ${message}`,
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }
  }

  // Handler for fetching a policy by ID
  async function handleGetPolicy(request: FastifyRequest, reply: FastifyReply) {
    const authenticated = await authenticatePolicyCaller(request, reply);
    if (!authenticated) return;

    const params = request.params as { id: string };
    const callerAppId = request.auth ? request.auth.applicationId : undefined;

    const policy = await policyService.getPolicyById(params.id, callerAppId);
    if (!policy) {
      const problem = createProblemDetails(
        request,
        404,
        'Not Found',
        `Security policy '${params.id}' was not found`,
        ErrorTypes.NOT_FOUND,
      );
      return reply.status(404).send(problem);
    }

    return reply.status(200).send(policy);
  }

  // Handler for updating a policy (creates new immutable version)
  async function handleUpdatePolicy(request: FastifyRequest, reply: FastifyReply) {
    const authenticated = await authenticatePolicyCaller(request, reply);
    if (!authenticated) return;

    const params = request.params as { id: string };
    const body = (request.body ?? {}) as Record<string, unknown>;

    let updatedBy: string;
    let callerAppId: string | undefined;

    if (request.auth) {
      callerAppId = request.auth.applicationId;
      updatedBy = request.auth.apiKeyId;

      if (
        body.applicationId &&
        String(body.applicationId).toLowerCase() !== callerAppId.toLowerCase()
      ) {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'Access denied: client application ID does not match authenticated credential context',
          ErrorTypes.FORBIDDEN,
        );
        return reply.status(403).send(problem);
      }
    } else if (request.user) {
      if (request.user.role !== 'admin') {
        const problem = createProblemDetails(
          request,
          403,
          'Forbidden',
          'Only admin users can update security policies',
          ErrorTypes.FORBIDDEN,
        );
        return reply.status(403).send(problem);
      }
      updatedBy = request.user.id;
    } else {
      return;
    }

    const docInput = body.document ? body.document : body;

    try {
      const updated = await policyService.updatePolicy(params.id, {
        document: docInput,
        callerAppId,
        updatedBy,
        requestId: request.id,
      });

      if (!updated) {
        const problem = createProblemDetails(
          request,
          404,
          'Not Found',
          `Security policy '${params.id}' was not found or belongs to another application`,
          ErrorTypes.NOT_FOUND,
        );
        return reply.status(404).send(problem);
      }

      return reply.status(200).send(updated);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const problem = createProblemDetails(
        request,
        400,
        'Validation Error',
        `Policy update failed: ${message}`,
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }
  }

  const policyRouteSchema = {
    tags: ['Policies'],
    security: [{ ApiKeyAuth: [] }, { UserAuth: [] }],
  };

  // POST /api/v1/policies & /policies
  app.post('/api/v1/policies', {
    schema: {
      ...policyRouteSchema,
      summary: 'Create security policy version',
      description: 'Creates a new versioned, canonicalized security policy document.',
      response: {
        201: { description: 'Policy created successfully', ...policyResponseSchema },
        400: { description: 'Validation error', ...problemDetailsSchema },
        401: { description: 'Unauthorized', ...problemDetailsSchema },
        403: { description: 'Forbidden', ...problemDetailsSchema },
      },
    },
    handler: handleCreatePolicy,
  });

  app.post('/policies', {
    schema: {
      ...policyRouteSchema,
      hide: true,
    },
    handler: handleCreatePolicy,
  });

  // GET /api/v1/policies/:id & /policies/:id
  app.get('/api/v1/policies/:id', {
    schema: {
      ...policyRouteSchema,
      summary: 'Get security policy by ID',
      description: 'Fetches policy version metadata and document, enforcing tenant isolation.',
      params: {
        type: 'object',
        properties: { id: { type: 'string', format: 'uuid' } },
        required: ['id'],
      },
      response: {
        200: { description: 'Policy retrieved successfully', ...policyResponseSchema },
        401: { description: 'Unauthorized', ...problemDetailsSchema },
        404: { description: 'Not found', ...problemDetailsSchema },
      },
    },
    handler: handleGetPolicy,
  });

  app.get('/policies/:id', {
    schema: {
      ...policyRouteSchema,
      hide: true,
    },
    handler: handleGetPolicy,
  });

  // PUT /api/v1/policies/:id & /policies/:id
  app.put('/api/v1/policies/:id', {
    schema: {
      ...policyRouteSchema,
      summary: 'Update security policy (creates new immutable version)',
      description:
        'Increments policy version (v1 -> v2) without modifying previous immutable versions.',
      params: {
        type: 'object',
        properties: { id: { type: 'string', format: 'uuid' } },
        required: ['id'],
      },
      response: {
        200: { description: 'New policy version created', ...policyResponseSchema },
        400: { description: 'Validation error', ...problemDetailsSchema },
        401: { description: 'Unauthorized', ...problemDetailsSchema },
        403: { description: 'Forbidden', ...problemDetailsSchema },
        404: { description: 'Not found', ...problemDetailsSchema },
      },
    },
    handler: handleUpdatePolicy,
  });

  app.put('/policies/:id', {
    schema: {
      ...policyRouteSchema,
      hide: true,
    },
    handler: handleUpdatePolicy,
  });
};
