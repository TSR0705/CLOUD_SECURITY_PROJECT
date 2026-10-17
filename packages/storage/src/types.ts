import type { Readable } from 'node:stream';

export type StorageBody =
  Buffer | Uint8Array | string | Readable | NodeJS.ReadableStream | ReadableStream;

export interface PutObjectParams {
  bucket: string;
  key: string;
  body: StorageBody;
  contentType?: string | undefined;
  contentLength?: number | undefined;
  metadata?: Record<string, string> | undefined;
  /**
   * Optional pre-computed SHA-256 digest (in 64-char hex or 44-char base64 format).
   */
  checksumSha256?: string | undefined;
  /**
   * Optional AbortSignal to abort upload in-flight
   */
  abortSignal?: AbortSignal | undefined;
}

export interface PutObjectResult {
  bucket: string;
  key: string;
  versionId: string;
  etag?: string | undefined;
  sha256?: string | undefined;
  size?: number | undefined;
}

export interface GetObjectParams {
  bucket: string;
  key: string;
  /**
   * Exact VersionId to retrieve. Empty string is strictly rejected.
   */
  versionId: string;
}

export interface GetObjectResult {
  bucket: string;
  key: string;
  versionId: string;
  body: Readable;
  contentType?: string | undefined;
  contentLength?: number | undefined;
  etag?: string | undefined;
  metadata?: Record<string, string> | undefined;
}

export interface HeadObjectParams {
  bucket: string;
  key: string;
  versionId?: string | undefined;
}

export interface HeadObjectResult {
  bucket: string;
  key: string;
  versionId?: string | undefined;
  contentLength: number;
  contentType?: string | undefined;
  etag?: string | undefined;
  metadata?: Record<string, string> | undefined;
}

export interface StorageProvider {
  /**
   * Write-once object put. Enforces If-None-Match: * and records VersionId and SHA-256.
   * Rejects duplicate writes on an existing key with AlreadyExists.
   */
  putIfAbsent(params: PutObjectParams): Promise<PutObjectResult>;

  /**
   * Retrieves object content for a specific, exact VersionId.
   * Empty versionId is rejected with InvalidRequest.
   * Missing version is rejected with VersionMissing. Never falls back to latest version.
   */
  getByVersion(params: GetObjectParams): Promise<GetObjectResult>;

  /**
   * Retrieves object metadata/head information for a specific key and optional versionId.
   */
  head(params: HeadObjectParams): Promise<HeadObjectResult>;
}
