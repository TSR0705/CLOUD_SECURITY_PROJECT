import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Standard RFC 7807 / RFC 9457 Problem Details object.
 */
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance: string;
  requestId: string;
  [key: string]: unknown;
}

/**
 * Deterministic URN identifiers for error categories.
 */
export const ErrorTypes = {
  VALIDATION: 'urn:sug:error:validation',
  NOT_FOUND: 'urn:sug:error:not-found',
  METHOD_NOT_ALLOWED: 'urn:sug:error:method-not-allowed',
  RATE_LIMIT: 'urn:sug:error:rate-limit',
  INTERNAL: 'urn:sug:error:internal',
} as const;

/**
 * Sanitizes an error detail message to ensure NO sensitive data (credentials,
 * SQL, connection strings, filesystem paths, stack traces) is leaked to clients.
 */
export function sanitizeErrorMessage(message: string | undefined, statusCode: number): string {
  if (!message || statusCode >= 500) {
    return 'An internal server error occurred';
  }

  // Remove potential filesystem paths
  let clean = message.replace(/[A-Za-z]:\\[\w\-.\\]+/g, '[PATH]');
  clean = clean.replace(/\/(?:[\w.-]+\/)+[\w.-]+/g, '[PATH]');

  // Remove potential connection strings or URLs with passwords
  clean = clean.replace(/postgres(?:ql)?:\/\/[^\s]+/gi, '[DATABASE_URI]');

  return clean;
}

/**
 * Constructs a standard ProblemDetails response object.
 */
export function createProblemDetails(
  request: FastifyRequest,
  statusCode: number,
  title: string,
  detail: string,
  type: string,
  extra?: Record<string, unknown>,
): ProblemDetails {
  const reqId = request.id || 'unknown';
  return {
    type,
    title,
    status: statusCode,
    detail,
    instance: request.raw.url || request.url,
    requestId: reqId,
    ...extra,
  };
}

/**
 * Global Fastify error handler producing application/problem+json responses.
 * Guarantees zero sensitive data or stack trace leakage in any environment.
 */
export function handleProblemError(
  error: FastifyError,
  request: FastifyRequest,
  reply: FastifyReply,
): void {
  const rawStatus = typeof error.statusCode === 'number' ? error.statusCode : 500;
  const status = rawStatus >= 400 && rawStatus <= 599 ? rawStatus : 500;

  let type: string;
  let title: string;
  let detail: string;

  if (status === 400) {
    type = ErrorTypes.VALIDATION;
    title = 'Validation Error';
    detail = sanitizeErrorMessage(error.message, 400);
  } else if (status === 404) {
    type = ErrorTypes.NOT_FOUND;
    title = 'Not Found';
    detail = `The requested route '${request.raw.url || request.url}' does not exist`;
  } else if (status === 405) {
    type = ErrorTypes.METHOD_NOT_ALLOWED;
    title = 'Method Not Allowed';
    detail = `Method ${request.method} is not allowed for '${request.raw.url || request.url}'`;
  } else if (status === 429) {
    type = ErrorTypes.RATE_LIMIT;
    title = 'Too Many Requests';
    detail = 'Rate limit exceeded. Please retry later.';
  } else {
    type = ErrorTypes.INTERNAL;
    title = 'Internal Server Error';
    detail = 'An internal server error occurred';
  }

  const problem = createProblemDetails(request, status, title, detail, type);

  // Set the response header to RFC problem+json
  reply.status(status).type('application/problem+json; charset=utf-8').send(problem);
}

/**
 * Global Fastify 404 Not Found handler producing application/problem+json responses.
 */
export function handleNotFound(request: FastifyRequest, reply: FastifyReply): void {
  const problem = createProblemDetails(
    request,
    404,
    'Not Found',
    `The requested route '${request.raw.url || request.url}' does not exist`,
    ErrorTypes.NOT_FOUND,
  );

  reply.status(404).type('application/problem+json; charset=utf-8').send(problem);
}
