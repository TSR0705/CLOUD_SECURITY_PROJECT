import crypto from 'node:crypto';
import type { Readable } from 'node:stream';
import type { ApiKeyDatabase } from '../auth/types.js';
import type { StorageProvider } from '@sug/storage';
import { buildQuarantineKey } from '@sug/storage';
import { PolicyService } from '../policy/policy-service.js';
import { UploadSessionService, UploadSessionError } from './session-service.js';
import type { UploadJwtPayload } from './upload-token.js';
import { CountingHashStream, StreamLimitExceededError } from './counting-stream.js';
import { createArtifactIdentity, type ArtifactIdentity } from '@sug/shared';

function toSafeUuid(id?: string | null): string | null {
  if (!id) return null;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(id) ? id : null;
}

export interface StreamingUploadServiceOptions {
  db: ApiKeyDatabase;
  storageProvider: StorageProvider;
  policyService: PolicyService;
  uploadSessionService: UploadSessionService;
  quarantineBucket: string;
}

export interface StreamingUploadInput {
  sessionId: string;
  tokenPayload: UploadJwtPayload;
  requestStream: Readable;
  rawContentLength?: string | undefined;
  clientIp?: string | undefined;
  requestId?: string | undefined;
}

export interface StreamingUploadResult {
  fileId: string;
  fileVersionId: string;
  scanJobId: string;
  status: 'QUARANTINED';
  versionId: string;
  size: number;
  sha256: string;
  identity?: ArtifactIdentity;
}

export interface UploadStatusResult {
  sessionId: string;
  status: string;
  fileId?: string | null;
  fileStatus?: string | null;
  identity?: ArtifactIdentity | null;
  createdAt: Date | string;
  completedAt?: Date | string | null;
  expiresAt?: Date | string | null;
}

export class StreamingUploadService {
  private readonly db: ApiKeyDatabase;
  private readonly storageProvider: StorageProvider;
  private readonly policyService: PolicyService;
  private readonly uploadSessionService: UploadSessionService;
  private readonly quarantineBucket: string;

  constructor(options: StreamingUploadServiceOptions) {
    this.db = options.db;
    this.storageProvider = options.storageProvider;
    this.policyService = options.policyService;
    this.uploadSessionService = options.uploadSessionService;
    this.quarantineBucket = options.quarantineBucket;
  }

  private async getClient() {
    if (typeof (this.db as unknown as { connect: () => Promise<unknown> }).connect === 'function') {
      const client = await (
        this.db as unknown as {
          connect: () => Promise<{
            query: ApiKeyDatabase['query'];
            release: () => void;
          }>;
        }
      ).connect();
      return client;
    }
    return {
      query: this.db.query.bind(this.db),
      release: () => {},
    };
  }

  /**
   * Processes a raw HTTP request-body streaming upload into quarantine storage.
   *
   * Invariants enforced:
   * 1. Atomic upload-session claim: token cannot be reused across concurrent attempts.
   * 2. Effective limit enforcement: effectiveLimit = min(policy.maxFileSize, declaredSize).
   * 3. Flat memory profile (RSS): bytes stream directly to S3 via CountingHashStream with zero disk buffering.
   * 4. Aborts immediately if stream exceeds permitted limit or hits 30s idle timeout.
   * 5. Captures non-empty S3 VersionId from P9 StorageProvider.
   * 6. Transactionally creates files, file_versions, and scan_jobs rows.
   */
  async handleStreamingUpload(input: StreamingUploadInput): Promise<StreamingUploadResult> {
    const { sessionId, tokenPayload, requestStream, rawContentLength, requestId } = input;

    // 1. Verify token sid matches requested sessionId
    if (sessionId.toLowerCase() !== tokenPayload.sid.toLowerCase()) {
      throw new UploadSessionError(
        'Upload token sid claim does not match target session ID',
        403,
        'FORBIDDEN_TOKEN',
      );
    }

    // 2. Atomically claim upload session (CREATED -> UPLOADING)
    const claimResult = await this.uploadSessionService.claimSession(
      sessionId,
      tokenPayload.sub,
      tokenPayload.jti,
      requestId,
    );

    if (!claimResult.success) {
      if (claimResult.reason === 'ALREADY_CLAIMED') {
        throw new UploadSessionError(
          'Upload session has already been claimed or uploaded',
          409,
          'ALREADY_CLAIMED',
        );
      }
      if (claimResult.reason === 'SESSION_EXPIRED') {
        throw new UploadSessionError('Upload session has expired', 410, 'SESSION_EXPIRED');
      }
      if (claimResult.reason === 'SESSION_NOT_FOUND') {
        throw new UploadSessionError('Upload session not found', 404, 'SESSION_NOT_FOUND');
      }
      throw new UploadSessionError('Failed to claim upload session', 400, 'CLAIM_FAILED');
    }

    const session = claimResult.session;

    // 3. Resolve pinned security policy
    const policy = await this.policyService.getPolicyById(session.policy_id);
    if (!policy) {
      throw new UploadSessionError('Pinned security policy not found', 409, 'POLICY_NOT_FOUND');
    }

    // 4. Calculate effectiveLimit = min(policy.maxFileSize, declared content length)
    const policyMaxBytes = policy.document.maxFileSize;
    const declaredSizeBytes = Number(session.declared_size);
    let effectiveLimit = Math.min(policyMaxBytes, declaredSizeBytes);

    let parsedContentLength: number | undefined;
    if (rawContentLength !== undefined) {
      parsedContentLength = parseInt(rawContentLength, 10);
      if (Number.isNaN(parsedContentLength) || parsedContentLength < 0) {
        throw new UploadSessionError(
          'Invalid Content-Length header value',
          400,
          'INVALID_CONTENT_LENGTH',
        );
      }
      // If declared Content-Length in headers already exceeds limit, reject immediately with 413
      if (parsedContentLength > effectiveLimit) {
        throw new StreamLimitExceededError(effectiveLimit, parsedContentLength);
      }
      effectiveLimit = Math.min(effectiveLimit, parsedContentLength);
    }

    // 5. Construct server-controlled quarantine object key
    const quarantineKey = buildQuarantineKey(session.application_id, session.id);

    // 6. Set up zero-buffering pass-through counting and hashing stream
    const abortController = new AbortController();
    let streamError: Error | null = null;

    const countingStream = new CountingHashStream({
      limit: effectiveLimit,
      idleTimeoutMs: 30_000,
      abortController,
    });

    countingStream.on('error', (err) => {
      if (!streamError) streamError = err;
      abortController.abort(err);
      requestStream.unpipe(countingStream);
      requestStream.resume();
    });

    requestStream.on('error', (err) => {
      if (!streamError) streamError = err;
      abortController.abort(err);
      countingStream.destroy(err);
    });

    requestStream.pipe(countingStream);

    let putResult;
    try {
      putResult = await this.storageProvider.putIfAbsent({
        bucket: this.quarantineBucket,
        key: quarantineKey,
        body: countingStream,
        contentLength: parsedContentLength,
        contentType: session.declared_mime,
        abortSignal: abortController.signal,
      });
    } catch (storageErr) {
      // Mark session as FAILED upon upload error or limit breach
      try {
        await this.db.query(
          `UPDATE upload_sessions SET status = 'FAILED', completed_at = now() WHERE id = $1`,
          [session.id],
        );
      } catch {
        // Suppress secondary DB update error
      }
      if (streamError) {
        throw streamError;
      }
      const bytesReceived = countingStream.getBytesReceived();
      if (parsedContentLength !== undefined && bytesReceived < parsedContentLength) {
        throw new UploadSessionError(
          `Stream ended prematurely: received ${bytesReceived} bytes but expected ${parsedContentLength}`,
          400,
          'TRUNCATED_STREAM',
        );
      }
      throw storageErr;
    }

    // 7. Verify byte count and hash integrity
    const bytesReceived = countingStream.getBytesReceived();
    if (bytesReceived === 0) {
      await this.db.query(
        `UPDATE upload_sessions SET status = 'FAILED', completed_at = now() WHERE id = $1`,
        [session.id],
      );
      throw new UploadSessionError('Uploaded file body is empty', 400, 'EMPTY_FILE');
    }

    if (parsedContentLength !== undefined && bytesReceived !== parsedContentLength) {
      await this.db.query(
        `UPDATE upload_sessions SET status = 'FAILED', completed_at = now() WHERE id = $1`,
        [session.id],
      );
      throw new UploadSessionError(
        `Stream ended prematurely: received ${bytesReceived} bytes but expected ${parsedContentLength}`,
        400,
        'TRUNCATED_STREAM',
      );
    }

    const computedSha256 = countingStream.getFinalSha256Hex();
    if (session.declared_sha256) {
      const declaredHex = Buffer.from(session.declared_sha256).toString('hex').toLowerCase();
      if (computedSha256.toLowerCase() !== declaredHex) {
        await this.db.query(
          `UPDATE upload_sessions SET status = 'FAILED', completed_at = now() WHERE id = $1`,
          [session.id],
        );
        throw new UploadSessionError(
          `Calculated SHA-256 digest '${computedSha256}' does not match declared digest '${declaredHex}'`,
          400,
          'CHECKSUM_MISMATCH',
        );
      }
    }

    // 8. Transactionally create: files, file_versions, and scan_jobs
    const fileId = crypto.randomUUID();
    const fileVersionId = crypto.randomUUID();
    const scanJobId = crypto.randomUUID();
    const sha256Buffer = Buffer.from(computedSha256, 'hex');

    const client = await this.getClient();
    try {
      await client.query('BEGIN');

      // 8a. Insert files row
      await client.query(
        `INSERT INTO files (id, application_id, upload_session_id, display_filename, status, current_version_id)
         VALUES ($1, $2, $3, $4, 'QUARANTINED', NULL)`,
        [fileId, session.application_id, session.id, session.original_filename],
      );

      // 8b. Insert file_versions row with exact storage_version_id
      await client.query(
        `INSERT INTO file_versions (
           id, file_id, version_no, provider, bucket, object_key, storage_version_id, etag, size_bytes, sha256_ingest
         ) VALUES ($1, $2, 1, 'aws', $3, $4, $5, $6, $7, $8)`,
        [
          fileVersionId,
          fileId,
          this.quarantineBucket,
          quarantineKey,
          putResult.versionId,
          putResult.etag ?? null,
          bytesReceived,
          sha256Buffer,
        ],
      );

      // 8c. Link files.current_version_id
      await client.query(`UPDATE files SET current_version_id = $1 WHERE id = $2`, [
        fileVersionId,
        fileId,
      ]);

      // 8d. Enqueue scan_jobs row
      await client.query(
        `INSERT INTO scan_jobs (id, file_version_id, status)
         VALUES ($1, $2, 'QUEUED')`,
        [scanJobId, fileVersionId],
      );

      // 8e. Mark upload_sessions as UPLOADED
      await client.query(
        `UPDATE upload_sessions SET status = 'UPLOADED', completed_at = now() WHERE id = $1`,
        [session.id],
      );

      // 8f. Record tamper-evident audit event
      const safeReqId = toSafeUuid(requestId);
      await client.query(`SELECT audit_append($1, $2, $3, $4::jsonb, $5::jsonb)`, [
        'service',
        'api_gateway',
        'upload.completed',
        JSON.stringify({
          application_id: session.application_id,
          file_id: fileId,
          file_version_id: fileVersionId,
          ...(safeReqId ? { request_id: safeReqId } : {}),
        }),
        JSON.stringify({
          session_id: session.id,
          size_bytes: bytesReceived,
          sha256: computedSha256,
          storage_version_id: putResult.versionId,
        }),
      ]);

      await client.query('COMMIT');
    } catch (txErr) {
      await client.query('ROLLBACK');
      throw txErr;
    } finally {
      client.release();
    }

    const identity = createArtifactIdentity({
      bucket: this.quarantineBucket,
      objectKey: quarantineKey,
      versionId: putResult.versionId,
      sha256: computedSha256,
      sizeBytes: bytesReceived,
    });

    return {
      fileId,
      fileVersionId,
      scanJobId,
      status: 'QUARANTINED',
      versionId: putResult.versionId,
      size: bytesReceived,
      sha256: computedSha256,
      identity,
    };
  }

  /**
   * Retrieves the current upload/file status for an upload session.
   */
  async getUploadStatus(
    sessionId: string,
    applicationId: string,
  ): Promise<UploadStatusResult | null> {
    const sessionRes = await this.db.query<{
      id: string;
      application_id: string;
      status: string;
      created_at: Date;
      completed_at: Date | null;
      expires_at: Date;
    }>(
      `SELECT id, application_id, status, created_at, completed_at, expires_at
       FROM upload_sessions
       WHERE id = $1 AND application_id = $2`,
      [sessionId, applicationId],
    );

    const session = sessionRes.rows[0];
    if (!session) {
      return null;
    }

    if (session.status === 'UPLOADED') {
      const fileRes = await this.db.query<{
        id: string;
        status: string;
        bucket: string | null;
        object_key: string | null;
        storage_version_id: string | null;
        size_bytes: string | number | null;
        sha256_ingest: Buffer | string | null;
      }>(
        `SELECT f.id, f.status, fv.bucket, fv.object_key, fv.storage_version_id, fv.size_bytes, fv.sha256_ingest
         FROM files f
         LEFT JOIN file_versions fv ON fv.id = f.current_version_id
         WHERE f.upload_session_id = $1`,
        [sessionId],
      );
      const file = fileRes.rows[0];

      let identity: ArtifactIdentity | null = null;
      if (
        file &&
        file.bucket &&
        file.object_key &&
        file.storage_version_id &&
        file.sha256_ingest !== null &&
        file.sha256_ingest !== undefined &&
        file.size_bytes !== null &&
        file.size_bytes !== undefined
      ) {
        try {
          identity = createArtifactIdentity({
            bucket: file.bucket,
            objectKey: file.object_key,
            versionId: file.storage_version_id,
            sha256: file.sha256_ingest,
            sizeBytes: file.size_bytes,
          });
        } catch {
          identity = null;
        }
      }

      return {
        sessionId: session.id,
        status: session.status,
        fileId: file?.id ?? null,
        fileStatus: file?.status ?? null,
        identity,
        createdAt: session.created_at,
        completedAt: session.completed_at,
      };
    }

    return {
      sessionId: session.id,
      status: session.status,
      identity: null,
      createdAt: session.created_at,
      expiresAt: session.expires_at,
    };
  }
}
