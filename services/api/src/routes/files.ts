/**
 * @sug/service-api/routes/files
 * Authenticated File Download and Deletion API Routes for Phase P20.
 *
 * Implements:
 * - GET /api/v1/files/:id (and alias /files/:id):
 *   - Dual authentication (tenant-isolated API key or authorized dashboard JWT).
 *   - Verifies file is PROMOTED.
 *   - Fetches ciphertext from trusted clean storage.
 *   - Decrypts via verify-before-release: AES-GCM tag authentication and plaintext digest verification.
 *   - Emits strict, safe download headers (nosniff, CSP sandbox, attachment, no-store).
 *   - Appends FILE_DOWNLOADED audit event.
 * - DELETE /api/v1/files/:id (and alias /files/:id):
 *   - Dual authentication (tenant-isolated API key with upload scope or admin JWT).
 *   - Soft-deletes file (status = 'DELETED', deleted_at = now()).
 *   - Appends FILE_DELETED audit event.
 */

import { Buffer } from 'node:buffer';
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { ApiKeyDatabase } from '../auth/types.js';
import type { ApiKeyService } from '../auth/service.js';
import { createProblemDetails, ErrorTypes } from '../errors/problem.js';
import { verifyDashboardToken } from '../auth/jwt.js';
import type { StorageProvider } from '@sug/storage';
import { decryptBuffer, type KeyProvider } from '@sug/crypto';

export interface FilesRouteOptions {
  db: ApiKeyDatabase;
  apiKeyService: ApiKeyService;
  storageProvider: StorageProvider;
  keyProvider: KeyProvider;
  jwtPublicKeyPem: string;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const problemDetailsSchema = {
  type: 'object' as const,
  properties: {
    type: { type: 'string', example: 'urn:sug:error:validation' },
    title: { type: 'string', example: 'Validation Error' },
    status: { type: 'integer', example: 400 },
    detail: { type: 'string', example: 'Invalid parameter' },
    instance: { type: 'string', example: '/api/v1/files/018f3a5e-7a42-7000-8000-000000000001' },
    requestId: { type: 'string', example: '018f3a5e-7a42-7000-8000-000000000001' },
  },
  required: ['type', 'title', 'status', 'detail', 'instance', 'requestId'],
};

export const filesRoutes: FastifyPluginAsync<FilesRouteOptions> = async (app, options) => {
  const { db, apiKeyService, storageProvider, keyProvider, jwtPublicKeyPem } = options;

  async function authenticateCaller(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<boolean> {
    const authHeader = request.headers.authorization;
    if (!authHeader) {
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

    // 1. API Key authentication
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

    // 2. Dashboard User JWT authentication
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
      'Unsupported authorization scheme',
      ErrorTypes.UNAUTHORIZED,
    );
    reply.status(401).send(problem);
    return false;
  }

  // Route handler for downloading a file
  async function handleDownload(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply,
  ) {
    const isAuthed = await authenticateCaller(request, reply);
    if (!isAuthed) return;

    const fileId = request.params.id;
    if (!UUID_REGEX.test(fileId)) {
      const problem = createProblemDetails(
        request,
        400,
        'Invalid File Identifier',
        `File ID '${fileId}' is not a valid UUID`,
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    // Query file metadata, current file version, and clean cloud object
    const fileQuery = `
      SELECT
        f.id,
        f.application_id,
        f.display_filename,
        f.status,
        f.deleted_at,
        fv.id AS file_version_id,
        fv.storage_version_id,
        fv.size_bytes,
        fv.sha256_ingest,
        co.id AS cloud_object_id,
        co.bucket,
        co.object_key,
        co.storage_version_id AS clean_storage_version_id,
        co.size_bytes AS clean_size_bytes,
        co.sha256_plain,
        co.sha256_cipher,
        co.kek_id
      FROM files f
      LEFT JOIN file_versions fv ON f.current_version_id = fv.id
      LEFT JOIN cloud_objects co ON co.file_version_id = fv.id AND co.zone = 'clean'
      WHERE f.id = $1
    `;

    const res = await db.query<{
      id: string;
      application_id: string;
      display_filename: string;
      status: string;
      deleted_at: Date | null;
      file_version_id: string | null;
      storage_version_id: string | null;
      size_bytes: string | number | null;
      sha256_ingest: Buffer | string | null;
      cloud_object_id: string | null;
      bucket: string | null;
      object_key: string | null;
      clean_storage_version_id: string | null;
      clean_size_bytes: string | number | null;
      sha256_plain: Buffer | string | null;
      sha256_cipher: Buffer | string | null;
      kek_id: string | null;
    }>(fileQuery, [fileId]);

    if (res.rows.length === 0) {
      const problem = createProblemDetails(
        request,
        404,
        'File Not Found',
        `File with ID '${fileId}' does not exist`,
        ErrorTypes.NOT_FOUND,
      );
      return reply.status(404).send(problem);
    }

    const row = res.rows[0]!;

    if (row.deleted_at || row.status === 'DELETED') {
      const problem = createProblemDetails(
        request,
        404,
        'File Deleted',
        `File with ID '${fileId}' has been deleted`,
        ErrorTypes.NOT_FOUND,
      );
      return reply.status(404).send(problem);
    }

    // Tenant Isolation (authz-07): If caller is using an API key, it must match application_id
    if (request.auth && request.auth.applicationId !== row.application_id) {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        'Access denied: file belongs to another application',
        ErrorTypes.FORBIDDEN,
      );
      return reply.status(403).send(problem);
    }

    // API Key Scope Check: Must include 'read' scope if present
    if (request.auth && Array.isArray(request.auth.scopes)) {
      if (!request.auth.scopes.includes('read') && !request.auth.scopes.includes('*')) {
        const problem = createProblemDetails(
          request,
          403,
          'Insufficient Scope',
          "API key lacks required 'read' scope for file download",
          ErrorTypes.FORBIDDEN,
        );
        return reply.status(403).send(problem);
      }
    }

    // Verify file promotion status
    if (row.status !== 'PROMOTED' || !row.cloud_object_id || !row.clean_storage_version_id) {
      const problem = createProblemDetails(
        request,
        400,
        'File Not Available',
        `File with ID '${fileId}' is in status '${row.status}' and has not been promoted to trusted storage`,
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    // Retrieve ciphertext from clean storage
    let ciphertextBuffer: Buffer;
    try {
      const getRes = await storageProvider.getByVersion({
        bucket: row.bucket!,
        key: row.object_key!,
        versionId: row.clean_storage_version_id,
      });

      const chunks: Buffer[] = [];
      for await (const chunk of getRes.body) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      ciphertextBuffer = Buffer.concat(chunks);
    } catch (err) {
      const problem = createProblemDetails(
        request,
        502,
        'Storage Gateway Error',
        `Failed to retrieve promoted ciphertext from clean storage: ${(err as Error).message}`,
        ErrorTypes.INTERNAL,
      );
      return reply.status(502).send(problem);
    }

    // Verify-before-release decryption via @sug/crypto
    const plainShaHex = Buffer.isBuffer(row.sha256_plain)
      ? row.sha256_plain.toString('hex').toLowerCase()
      : Buffer.isBuffer(row.sha256_ingest)
        ? row.sha256_ingest.toString('hex').toLowerCase()
        : String(row.sha256_plain || row.sha256_ingest || '')
            .replace(/^(?:0x|\\x)/i, '')
            .toLowerCase();

    let plaintext: Buffer;
    try {
      plaintext = await decryptBuffer(ciphertextBuffer, {
        keyProvider,
        aad: {
          appId: row.application_id,
          fileId: row.id,
          storageVersionId: row.storage_version_id!,
          sha256Plaintext: plainShaHex,
        },
        keyReference: row.kek_id ?? undefined,
      });
    } catch {
      const problem = createProblemDetails(
        request,
        500,
        'Decryption Failed',
        'Ciphertext verification failed or payload tampered; plaintext rejected before release',
        ErrorTypes.INTERNAL,
      );
      return reply.status(500).send(problem);
    }

    // Append FILE_DOWNLOADED audit event
    const actorType = request.user ? 'user' : 'api_key';
    const actorId = request.user ? request.user.id : (request.auth?.apiKeyId ?? 'unknown');

    try {
      await db.query(`SELECT audit_append($1, $2, 'FILE_DOWNLOADED', $3::jsonb, $4::jsonb)`, [
        actorType,
        actorId,
        JSON.stringify({
          application_id: row.application_id,
          file_id: row.id,
          file_version_id: row.file_version_id,
        }),
        JSON.stringify({
          size_bytes: plaintext.length,
          sha256: plainShaHex,
          ip: request.ip,
        }),
      ]);
    } catch {
      // Non-blocking audit log failure for download read
    }

    // Sanitize filename for safe Content-Disposition
    const safeFilename = (row.display_filename || 'download')
      .replace(/[\r\n\0"/\\]/g, '_')
      .slice(0, 255);

    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', `attachment; filename="${safeFilename}"`);
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Content-Security-Policy', "default-src 'none'; sandbox");
    reply.header('Cache-Control', 'no-store, private');
    reply.header('Content-Length', plaintext.length);
    reply.header('x-payload-sha256', plainShaHex);

    return reply.send(plaintext);
  }

  // Route handler for deleting a file
  async function handleDelete(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply,
  ) {
    const isAuthed = await authenticateCaller(request, reply);
    if (!isAuthed) return;

    // RBAC: If user JWT, only 'admin' role can delete files
    if (request.user && request.user.role !== 'admin') {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        `Role '${request.user.role}' is not authorized to delete files (admin required)`,
        ErrorTypes.FORBIDDEN,
      );
      return reply.status(403).send(problem);
    }

    const fileId = request.params.id;
    if (!UUID_REGEX.test(fileId)) {
      const problem = createProblemDetails(
        request,
        400,
        'Invalid File Identifier',
        `File ID '${fileId}' is not a valid UUID`,
        ErrorTypes.VALIDATION,
      );
      return reply.status(400).send(problem);
    }

    // Query file
    const fileRes = await db.query<{ id: string; application_id: string; status: string }>(
      `SELECT id, application_id, status FROM files WHERE id = $1`,
      [fileId],
    );

    if (fileRes.rows.length === 0) {
      const problem = createProblemDetails(
        request,
        404,
        'File Not Found',
        `File with ID '${fileId}' does not exist`,
        ErrorTypes.NOT_FOUND,
      );
      return reply.status(404).send(problem);
    }

    const file = fileRes.rows[0]!;

    // Tenant Isolation (authz-07): API key must match application_id
    if (request.auth && request.auth.applicationId !== file.application_id) {
      const problem = createProblemDetails(
        request,
        403,
        'Forbidden',
        'Access denied: cannot delete file belonging to another application',
        ErrorTypes.FORBIDDEN,
      );
      return reply.status(403).send(problem);
    }

    // If already deleted, return 204 idempotently
    if (file.status === 'DELETED') {
      return reply.status(204).send();
    }

    // Soft-delete file
    await db.query(`UPDATE files SET status = 'DELETED', deleted_at = now() WHERE id = $1`, [
      fileId,
    ]);

    // Audit event
    const actorType = request.user ? 'user' : 'api_key';
    const actorId = request.user ? request.user.id : (request.auth?.apiKeyId ?? 'unknown');

    try {
      await db.query(`SELECT audit_append($1, $2, 'FILE_DELETED', $3::jsonb, $4::jsonb)`, [
        actorType,
        actorId,
        JSON.stringify({
          application_id: file.application_id,
          file_id: file.id,
        }),
        JSON.stringify({
          previous_status: file.status,
          ip: request.ip,
        }),
      ]);
    } catch {
      // Non-blocking audit failure
    }

    return reply.status(204).send();
  }

  // Register routes with schema definitions
  const downloadSchema = {
    tags: ['Files'],
    summary: 'Download a promoted clean file',
    description:
      'Retrieves and decrypts a promoted artifact from trusted clean storage with verify-before-release integrity checks.',
    params: {
      type: 'object',
      properties: {
        id: { type: 'string', format: 'uuid', description: 'File UUID' },
      },
      required: ['id'],
    },
    response: {
      400: problemDetailsSchema,
      401: problemDetailsSchema,
      403: problemDetailsSchema,
      404: problemDetailsSchema,
      500: problemDetailsSchema,
      502: problemDetailsSchema,
    },
  };

  const deleteSchema = {
    tags: ['Files'],
    summary: 'Delete a file',
    description: 'Soft-deletes a file record and appends a FILE_DELETED audit event.',
    params: {
      type: 'object',
      properties: {
        id: { type: 'string', format: 'uuid', description: 'File UUID' },
      },
      required: ['id'],
    },
    response: {
      204: { type: 'null', description: 'File deleted successfully' },
      400: problemDetailsSchema,
      401: problemDetailsSchema,
      403: problemDetailsSchema,
      404: problemDetailsSchema,
    },
  };

  app.get<{ Params: { id: string } }>(
    '/api/v1/files/:id',
    { schema: downloadSchema },
    handleDownload,
  );
  app.get<{ Params: { id: string } }>('/files/:id', { schema: downloadSchema }, handleDownload);

  app.delete<{ Params: { id: string } }>(
    '/api/v1/files/:id',
    { schema: deleteSchema },
    handleDelete,
  );
  app.delete<{ Params: { id: string } }>('/files/:id', { schema: deleteSchema }, handleDelete);
};
