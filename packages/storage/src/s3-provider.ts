import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  type PutObjectCommandInput,
  type GetObjectCommandInput,
  type HeadObjectCommandInput,
  type S3ClientConfig,
} from '@aws-sdk/client-s3';
import { Readable } from 'node:stream';
import { createHash } from 'node:crypto';
import type {
  StorageProvider,
  PutObjectParams,
  PutObjectResult,
  GetObjectParams,
  GetObjectResult,
  HeadObjectParams,
  HeadObjectResult,
} from './types.js';
import {
  StorageError,
  AlreadyExists,
  VersionMissing,
  NotFound,
  InvalidRequest,
  StorageUnavailable,
  PermissionDenied,
  sanitizeMessage,
} from './errors.js';

export interface S3ProviderOptions {
  endpoint?: string | undefined;
  region?: string | undefined;
  credentials?:
    | {
        accessKeyId: string;
        secretAccessKey: string;
        sessionToken?: string | undefined;
      }
    | undefined;
  forcePathStyle?: boolean | undefined;
  s3Client?: S3Client | undefined;
}

export class S3Provider implements StorageProvider {
  private readonly client: S3Client;

  constructor(options: S3ProviderOptions = {}) {
    if (options.s3Client) {
      this.client = options.s3Client;
    } else {
      const config: S3ClientConfig = {
        region: options.region || 'us-east-1',
        requestChecksumCalculation: 'WHEN_REQUIRED',
        ...(options.endpoint ? { endpoint: options.endpoint } : {}),
        ...(options.credentials
          ? {
              credentials: {
                accessKeyId: options.credentials.accessKeyId,
                secretAccessKey: options.credentials.secretAccessKey,
                ...(options.credentials.sessionToken
                  ? { sessionToken: options.credentials.sessionToken }
                  : {}),
              },
            }
          : {}),
        ...(options.forcePathStyle !== undefined ? { forcePathStyle: options.forcePathStyle } : {}),
      };
      this.client = new S3Client(config);
    }
  }

  /**
   * Write-once object creation.
   * Sends If-None-Match: * and computes/verifies SHA-256.
   * Returns exact VersionId from S3 versioning.
   */
  async putIfAbsent(params: PutObjectParams): Promise<PutObjectResult> {
    if (!params.bucket || typeof params.bucket !== 'string' || params.bucket.trim() === '') {
      throw new InvalidRequest('bucket name is required and cannot be empty');
    }
    if (!params.key || typeof params.key !== 'string' || params.key.trim() === '') {
      throw new InvalidRequest('key is required and cannot be empty');
    }
    if (params.body === undefined || params.body === null) {
      throw new InvalidRequest('body is required for putIfAbsent');
    }

    let checksumBase64: string | undefined;
    let expectedHexSha256: string | undefined;

    if (params.checksumSha256) {
      const raw = params.checksumSha256.trim();
      if (/^[a-fA-F0-9]{64}$/.test(raw)) {
        expectedHexSha256 = raw.toLowerCase();
        checksumBase64 = Buffer.from(raw, 'hex').toString('base64');
      } else if (/^[A-Za-z0-9+/]{43}=*$/.test(raw)) {
        checksumBase64 = raw;
        expectedHexSha256 = Buffer.from(raw, 'base64').toString('hex').toLowerCase();
      } else {
        throw new InvalidRequest(
          'checksumSha256 must be a 64-character hex string or 44-character base64 string',
          { bucket: params.bucket, key: params.key },
        );
      }
    } else if (Buffer.isBuffer(params.body) || typeof params.body === 'string') {
      const buf = Buffer.isBuffer(params.body) ? params.body : Buffer.from(params.body);
      expectedHexSha256 = createHash('sha256').update(buf).digest('hex');
      checksumBase64 = Buffer.from(expectedHexSha256, 'hex').toString('base64');
    }

    type NonNullableBody = NonNullable<PutObjectCommandInput['Body']>;
    const isStream =
      typeof (params.body as { pipe?: unknown })?.pipe === 'function' ||
      typeof (params.body as { getReader?: unknown })?.getReader === 'function';

    const input: PutObjectCommandInput = {
      Bucket: params.bucket,
      Key: params.key,
      Body: params.body as NonNullableBody,
      IfNoneMatch: '*',
      ...(!isStream || params.contentLength !== undefined
        ? { ChecksumAlgorithm: 'SHA256' as const }
        : {}),
      ...(checksumBase64 ? { ChecksumSHA256: checksumBase64 } : {}),
      ...(params.contentType ? { ContentType: params.contentType } : {}),
      ...(params.contentLength !== undefined ? { ContentLength: params.contentLength } : {}),
      ...(params.metadata ? { Metadata: params.metadata } : {}),
    };

    try {
      const res = await this.client.send(
        new PutObjectCommand(input),
        params.abortSignal ? { abortSignal: params.abortSignal } : undefined,
      );

      const versionId = res.VersionId;
      if (!versionId || typeof versionId !== 'string' || versionId.trim() === '') {
        throw new StorageError(
          'S3 provider did not return a valid VersionId. Ensure object versioning is enabled on the bucket.',
          {
            code: 'STORAGE_UNAVAILABLE',
            statusCode: 500,
            bucket: params.bucket,
            key: params.key,
          },
        );
      }

      let hexSha256 = expectedHexSha256;
      if (!hexSha256 && res.ChecksumSHA256) {
        hexSha256 = Buffer.from(res.ChecksumSHA256, 'base64').toString('hex').toLowerCase();
      }

      const size =
        params.contentLength !== undefined
          ? params.contentLength
          : Buffer.isBuffer(params.body)
            ? params.body.byteLength
            : typeof params.body === 'string'
              ? Buffer.byteLength(params.body)
              : undefined;

      return {
        bucket: params.bucket,
        key: params.key,
        versionId,
        etag: res.ETag ? res.ETag.replace(/^"|"$/g, '') : undefined,
        sha256: hexSha256,
        size,
      };
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw err;
      }
      throw this.normalizeError(err, params.bucket, params.key);
    }
  }

  /**
   * Retrieves object content for a specific, exact VersionId.
   * Strict validation ensures empty or missing versionId is rejected.
   */
  async getByVersion(params: GetObjectParams): Promise<GetObjectResult> {
    if (!params.bucket || typeof params.bucket !== 'string' || params.bucket.trim() === '') {
      throw new InvalidRequest('bucket name is required and cannot be empty');
    }
    if (!params.key || typeof params.key !== 'string' || params.key.trim() === '') {
      throw new InvalidRequest('key is required and cannot be empty');
    }
    if (
      !params.versionId ||
      typeof params.versionId !== 'string' ||
      params.versionId.trim() === ''
    ) {
      throw new InvalidRequest('versionId is required and cannot be empty for getByVersion', {
        bucket: params.bucket,
        key: params.key,
      });
    }

    const input: GetObjectCommandInput = {
      Bucket: params.bucket,
      Key: params.key,
      VersionId: params.versionId,
    };

    try {
      const res = await this.client.send(new GetObjectCommand(input));

      let body: Readable;
      if (res.Body instanceof Readable) {
        body = res.Body;
      } else if (res.Body && typeof (res.Body as { pipe?: unknown }).pipe === 'function') {
        body = res.Body as unknown as Readable;
      } else if (
        res.Body &&
        typeof (res.Body as { transformToWebStream?: unknown }).transformToWebStream === 'function'
      ) {
        const webStream = (
          res.Body as { transformToWebStream: () => ReadableStream }
        ).transformToWebStream();
        body = Readable.fromWeb(webStream as Parameters<typeof Readable.fromWeb>[0]);
      } else {
        throw new StorageError('Unexpected response body stream from S3', {
          code: 'STORAGE_UNAVAILABLE',
          statusCode: 500,
          bucket: params.bucket,
          key: params.key,
          versionId: params.versionId,
        });
      }

      return {
        bucket: params.bucket,
        key: params.key,
        versionId: res.VersionId ?? params.versionId,
        body,
        contentType: res.ContentType,
        contentLength: res.ContentLength,
        etag: res.ETag ? res.ETag.replace(/^"|"$/g, '') : undefined,
        metadata: res.Metadata,
      };
    } catch (err) {
      throw this.normalizeError(err, params.bucket, params.key, params.versionId);
    }
  }

  /**
   * Retrieves metadata / head information for a specific key and optional versionId.
   */
  async head(params: HeadObjectParams): Promise<HeadObjectResult> {
    if (!params.bucket || typeof params.bucket !== 'string' || params.bucket.trim() === '') {
      throw new InvalidRequest('bucket name is required and cannot be empty');
    }
    if (!params.key || typeof params.key !== 'string' || params.key.trim() === '') {
      throw new InvalidRequest('key is required and cannot be empty');
    }
    if (params.versionId !== undefined) {
      if (typeof params.versionId !== 'string' || params.versionId.trim() === '') {
        throw new InvalidRequest('versionId cannot be empty when specified for head', {
          bucket: params.bucket,
          key: params.key,
        });
      }
    }

    const input: HeadObjectCommandInput = {
      Bucket: params.bucket,
      Key: params.key,
      ...(params.versionId ? { VersionId: params.versionId } : {}),
    };

    try {
      const res = await this.client.send(new HeadObjectCommand(input));

      return {
        bucket: params.bucket,
        key: params.key,
        versionId: res.VersionId ?? params.versionId,
        contentLength: res.ContentLength ?? 0,
        contentType: res.ContentType,
        etag: res.ETag ? res.ETag.replace(/^"|"$/g, '') : undefined,
        metadata: res.Metadata,
      };
    } catch (err) {
      throw this.normalizeError(err, params.bucket, params.key, params.versionId);
    }
  }

  /**
   * Normalizes raw S3 / AWS SDK errors into deterministic typed StorageErrors.
   * Ensures no credentials or sensitive tokens are exposed in error messages.
   */
  private normalizeError(
    err: unknown,
    bucket?: string | undefined,
    key?: string | undefined,
    versionId?: string | undefined,
  ): StorageError {
    if (err instanceof StorageError) {
      return err;
    }

    const s3Err =
      typeof err === 'object' && err !== null
        ? (err as {
            name?: string;
            message?: string;
            $metadata?: { httpStatusCode?: number };
            code?: string;
          })
        : {};

    const status = s3Err.$metadata?.httpStatusCode;
    const name = s3Err.name || s3Err.code;
    const rawMsg = s3Err.message || 'S3 operation failed';
    const sanitized = sanitizeMessage(rawMsg);

    // HTTP 412 Precondition Failed -> AlreadyExists
    if (status === 412 || name === 'PreconditionFailed') {
      return new AlreadyExists(bucket ?? 'unknown', key ?? 'unknown', err);
    }

    // Version Missing
    if (name === 'NoSuchVersion' || (status === 404 && versionId)) {
      return new VersionMissing(bucket ?? 'unknown', key ?? 'unknown', versionId ?? 'unknown', err);
    }

    // Object Not Found
    if (status === 404 || name === 'NoSuchKey' || name === 'NotFound') {
      return new NotFound(bucket ?? 'unknown', key ?? 'unknown', err);
    }

    // Permission Denied
    if (status === 403 || name === 'AccessDenied') {
      return new PermissionDenied(
        `Access denied to bucket "${bucket}" key "${key}": ${sanitized}`,
        err,
      );
    }

    // Invalid Request
    if (status === 400 || name === 'InvalidArgument' || name === 'InvalidRequest') {
      return new InvalidRequest(sanitized, { bucket, key, versionId, cause: err });
    }

    // Storage Unavailable / Network Failure / Service 5xx
    if (
      status === 503 ||
      status === 500 ||
      status === 502 ||
      status === 504 ||
      name === 'TimeoutError' ||
      name === 'EndpointError' ||
      name === 'ECONNREFUSED' ||
      name === 'ENOTFOUND'
    ) {
      return new StorageUnavailable(`Storage provider unavailable: ${sanitized}`, err);
    }

    return new StorageError(sanitized, {
      code: 'UNKNOWN',
      statusCode: status ?? 500,
      bucket,
      key,
      versionId,
      cause: err,
    });
  }
}

/**
 * Factory helper for creating an S3Provider instance
 */
export function createS3Provider(options: S3ProviderOptions = {}): S3Provider {
  return new S3Provider(options);
}
