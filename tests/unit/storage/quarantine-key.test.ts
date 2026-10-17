import { describe, it, expect } from 'vitest';
import {
  buildQuarantineKey,
  isValidQuarantineIdentifier,
  parseQuarantineKey,
  InvalidRequest,
  StorageError,
} from '@sug/storage';
import { randomUUID } from 'node:crypto';

describe('Quarantine Key Scheme (@sug/storage)', () => {
  describe('buildQuarantineKey', () => {
    it('constructs key with format incoming/<applicationId>/<uploadId> for valid UUIDs', () => {
      const appId = randomUUID();
      const uploadId = randomUUID();
      const key = buildQuarantineKey(appId, uploadId);

      expect(key).toBe(`incoming/${appId}/${uploadId}`);
      expect(key.startsWith('incoming/')).toBe(true);
    });

    it('constructs key for valid alphanumeric identifiers with hyphens and underscores', () => {
      const appId = 'app_sales-portal_01';
      const uploadId = 'upload_session-12345';
      const key = buildQuarantineKey(appId, uploadId);

      expect(key).toBe('incoming/app_sales-portal_01/upload_session-12345');
    });

    it('rejects path traversal in applicationId', () => {
      const traversalAttempts = [
        '../traversal',
        '../../etc/passwd',
        '..',
        '../',
        '..\\',
        'app/subpath',
        'app\\subpath',
      ];

      for (const badApp of traversalAttempts) {
        expect(
          () => buildQuarantineKey(badApp, randomUUID()),
          `Should reject applicationId: ${badApp}`,
        ).toThrow(InvalidRequest);
      }
    });

    it('rejects path traversal in uploadId', () => {
      const traversalAttempts = [
        '../traversal',
        '../../secret.key',
        '..',
        '../',
        '..\\',
        'upload/123',
        'upload\\123',
      ];

      for (const badUpload of traversalAttempts) {
        expect(
          () => buildQuarantineKey(randomUUID(), badUpload),
          `Should reject uploadId: ${badUpload}`,
        ).toThrow(InvalidRequest);
      }
    });

    it('rejects special characters, spaces, and null bytes', () => {
      const malicious = [
        'app with space',
        'app\0null',
        'app%2e%2e%2f',
        'app$dollar',
        'app;semi',
        'app:colon',
        'app*star',
        'app<tag>',
        'app!excl',
      ];

      for (const bad of malicious) {
        expect(() => buildQuarantineKey(bad, randomUUID())).toThrow(InvalidRequest);
        expect(() => buildQuarantineKey(randomUUID(), bad)).toThrow(InvalidRequest);
      }
    });

    it('rejects empty or excessively long identifiers', () => {
      expect(() => buildQuarantineKey('', randomUUID())).toThrow(InvalidRequest);
      expect(() => buildQuarantineKey(randomUUID(), '')).toThrow(InvalidRequest);

      const longId = 'a'.repeat(129);
      expect(() => buildQuarantineKey(longId, randomUUID())).toThrow(InvalidRequest);
      expect(() => buildQuarantineKey(randomUUID(), longId)).toThrow(InvalidRequest);
    });

    it('thrown error is instance of StorageError and has code INVALID_REQUEST', () => {
      try {
        buildQuarantineKey('../bad', 'valid-id');
        expect.unreachable('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(StorageError);
        expect(err).toBeInstanceOf(InvalidRequest);
        expect((err as InvalidRequest).code).toBe('INVALID_REQUEST');
        expect((err as InvalidRequest).statusCode).toBe(400);
      }
    });
  });

  describe('isValidQuarantineIdentifier', () => {
    it('returns true for valid identifiers', () => {
      expect(isValidQuarantineIdentifier('test-app')).toBe(true);
      expect(isValidQuarantineIdentifier('app_123')).toBe(true);
      expect(isValidQuarantineIdentifier(randomUUID())).toBe(true);
      expect(isValidQuarantineIdentifier('A-Z_0-9')).toBe(true);
    });

    it('returns false for invalid inputs', () => {
      expect(isValidQuarantineIdentifier('')).toBe(false);
      expect(isValidQuarantineIdentifier(null)).toBe(false);
      expect(isValidQuarantineIdentifier(undefined)).toBe(false);
      expect(isValidQuarantineIdentifier(123)).toBe(false);
      expect(isValidQuarantineIdentifier('..')).toBe(false);
      expect(isValidQuarantineIdentifier('a/b')).toBe(false);
      expect(isValidQuarantineIdentifier('a\\b')).toBe(false);
      expect(isValidQuarantineIdentifier('a b')).toBe(false);
      expect(isValidQuarantineIdentifier('a'.repeat(129))).toBe(false);
    });
  });

  describe('parseQuarantineKey', () => {
    it('correctly parses a valid quarantine key', () => {
      const appId = randomUUID();
      const uploadId = randomUUID();
      const key = `incoming/${appId}/${uploadId}`;

      const parsed = parseQuarantineKey(key);
      expect(parsed).toEqual({
        applicationId: appId,
        uploadId: uploadId,
      });
    });

    it('returns null for invalid keys', () => {
      expect(parseQuarantineKey('outgoing/app/upload')).toBeNull();
      expect(parseQuarantineKey('incoming/app')).toBeNull();
      expect(parseQuarantineKey('incoming/app/upload/extra')).toBeNull();
      expect(parseQuarantineKey('incoming/app/../traversal')).toBeNull();
      expect(parseQuarantineKey('')).toBeNull();
      expect(parseQuarantineKey(null as unknown as string)).toBeNull();
    });
  });
});
