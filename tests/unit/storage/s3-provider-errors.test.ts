import { describe, it, expect, vi } from 'vitest';
import {
  S3Provider,
  createS3Provider,
  AlreadyExists,
  VersionMissing,
  NotFound,
  PermissionDenied,
  InvalidRequest,
  StorageUnavailable,
  StorageError,
  sanitizeMessage,
} from '@sug/storage';
import type { S3Client } from '@aws-sdk/client-s3';

describe('S3Provider Error Normalization and Sanitization (@sug/storage)', () => {
  describe('Credential Sanitization', () => {
    it('redacts AWS Access Key IDs (AKIA / ASIA)', () => {
      const msg = 'Failed request with key AKIAIOSFODNN7EXAMPLE in header';
      expect(sanitizeMessage(msg)).toBe('Failed request with key [REDACTED] in header');
    });

    it('redacts secretAccessKey and password literals', () => {
      const msg1 = 'secretAccessKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
      expect(sanitizeMessage(msg1)).toBe('[REDACTED]');

      const msg2 = 'password: "super-secret-password-123"';
      expect(sanitizeMessage(msg2)).toBe('[REDACTED]');
    });

    it('redacts Bearer tokens and Authorization headers', () => {
      const msg = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID';
      expect(sanitizeMessage(msg)).toBe('[REDACTED]');
    });

    it('handles empty or non-string inputs safely', () => {
      expect(sanitizeMessage('')).toBe('Unknown storage error');
      expect(sanitizeMessage(null as unknown as string)).toBe('Unknown storage error');
    });
  });

  describe('Parameter Validation in S3Provider', () => {
    const provider = createS3Provider({ region: 'us-east-1' });

    it('putIfAbsent rejects missing or empty bucket', async () => {
      await expect(
        provider.putIfAbsent({ bucket: '', key: 'k', body: Buffer.from('x') }),
      ).rejects.toThrow(InvalidRequest);
      await expect(
        provider.putIfAbsent({ bucket: '   ', key: 'k', body: Buffer.from('x') }),
      ).rejects.toThrow(InvalidRequest);
    });

    it('putIfAbsent rejects missing or empty key', async () => {
      await expect(
        provider.putIfAbsent({ bucket: 'b', key: '', body: Buffer.from('x') }),
      ).rejects.toThrow(InvalidRequest);
      await expect(
        provider.putIfAbsent({ bucket: 'b', key: '   ', body: Buffer.from('x') }),
      ).rejects.toThrow(InvalidRequest);
    });

    it('putIfAbsent rejects null or undefined body', async () => {
      await expect(
        provider.putIfAbsent({
          bucket: 'b',
          key: 'k',
          body: null as unknown as Buffer,
        }),
      ).rejects.toThrow(InvalidRequest);
      await expect(
        provider.putIfAbsent({
          bucket: 'b',
          key: 'k',
          body: undefined as unknown as Buffer,
        }),
      ).rejects.toThrow(InvalidRequest);
    });

    it('putIfAbsent rejects invalid checksum format', async () => {
      await expect(
        provider.putIfAbsent({
          bucket: 'b',
          key: 'k',
          body: Buffer.from('x'),
          checksumSha256: 'not-a-valid-checksum',
        }),
      ).rejects.toThrow(InvalidRequest);
    });

    it('getByVersion strictly rejects missing, null, or whitespace-only versionId', async () => {
      await expect(provider.getByVersion({ bucket: 'b', key: 'k', versionId: '' })).rejects.toThrow(
        InvalidRequest,
      );

      await expect(
        provider.getByVersion({ bucket: 'b', key: 'k', versionId: '   ' }),
      ).rejects.toThrow(InvalidRequest);

      await expect(
        provider.getByVersion({
          bucket: 'b',
          key: 'k',
          versionId: null as unknown as string,
        }),
      ).rejects.toThrow(InvalidRequest);
    });

    it('head rejects empty versionId when specified', async () => {
      await expect(provider.head({ bucket: 'b', key: 'k', versionId: '' })).rejects.toThrow(
        InvalidRequest,
      );
      await expect(provider.head({ bucket: 'b', key: 'k', versionId: '   ' })).rejects.toThrow(
        InvalidRequest,
      );
    });
  });

  describe('Mocked S3 Error Normalization', () => {
    it('normalizes HTTP 412 / PreconditionFailed to AlreadyExists', async () => {
      const mockS3 = {
        send: vi.fn().mockRejectedValue({
          name: 'PreconditionFailed',
          $metadata: { httpStatusCode: 412 },
          message: 'At least one of the pre-conditions you specified did not hold',
        }),
      } as unknown as S3Client;

      const provider = new S3Provider({ s3Client: mockS3 });

      await expect(
        provider.putIfAbsent({ bucket: 'my-bucket', key: 'my-key', body: Buffer.from('data') }),
      ).rejects.toThrow(AlreadyExists);
    });

    it('normalizes NoSuchVersion / 404 with versionId to VersionMissing', async () => {
      const mockS3 = {
        send: vi.fn().mockRejectedValue({
          name: 'NoSuchVersion',
          $metadata: { httpStatusCode: 404 },
          message: 'The specified version does not exist.',
        }),
      } as unknown as S3Client;

      const provider = new S3Provider({ s3Client: mockS3 });

      try {
        await provider.getByVersion({ bucket: 'my-bucket', key: 'my-key', versionId: 'v123' });
        expect.unreachable('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(VersionMissing);
        expect((err as VersionMissing).code).toBe('VERSION_MISSING');
        expect((err as VersionMissing).statusCode).toBe(404);
        expect((err as VersionMissing).versionId).toBe('v123');
      }
    });

    it('normalizes NoSuchKey / 404 to NotFound', async () => {
      const mockS3 = {
        send: vi.fn().mockRejectedValue({
          name: 'NoSuchKey',
          $metadata: { httpStatusCode: 404 },
          message: 'The specified key does not exist.',
        }),
      } as unknown as S3Client;

      const provider = new S3Provider({ s3Client: mockS3 });

      await expect(provider.head({ bucket: 'my-bucket', key: 'nonexistent-key' })).rejects.toThrow(
        NotFound,
      );
    });

    it('normalizes AccessDenied / 403 to PermissionDenied', async () => {
      const mockS3 = {
        send: vi.fn().mockRejectedValue({
          name: 'AccessDenied',
          $metadata: { httpStatusCode: 403 },
          message: 'Access Denied',
        }),
      } as unknown as S3Client;

      const provider = new S3Provider({ s3Client: mockS3 });

      await expect(
        provider.putIfAbsent({ bucket: 'locked-bucket', key: 'key', body: Buffer.from('x') }),
      ).rejects.toThrow(PermissionDenied);
    });

    it('normalizes timeout and network errors to StorageUnavailable', async () => {
      const mockS3 = {
        send: vi.fn().mockRejectedValue({
          name: 'TimeoutError',
          message: 'Connection timed out',
        }),
      } as unknown as S3Client;

      const provider = new S3Provider({ s3Client: mockS3 });

      await expect(
        provider.putIfAbsent({ bucket: 'b', key: 'k', body: Buffer.from('x') }),
      ).rejects.toThrow(StorageUnavailable);
    });

    it('throws StorageError if S3 put succeeds but returns no VersionId', async () => {
      const mockS3 = {
        send: vi.fn().mockResolvedValue({
          ETag: '"12345"',
          // VersionId is missing
        }),
      } as unknown as S3Client;

      const provider = new S3Provider({ s3Client: mockS3 });

      await expect(
        provider.putIfAbsent({ bucket: 'unversioned-bucket', key: 'k', body: Buffer.from('x') }),
      ).rejects.toThrow(StorageError);
    });
  });
});
