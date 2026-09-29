import { describe, it, expect } from 'vitest';
import {
  ArtifactIdentity,
  ArtifactIdentityError,
  createArtifactIdentity,
  validateArtifactIdentity,
  isArtifactIdentity,
  isValidSha256,
  normalizeSha256,
  toCanonicalSha256,
  timingSafeSha256Equal,
  compareArtifactIdentities,
} from '@sug/shared';

describe('ArtifactIdentity Unit Tests (P12)', () => {
  const validShaHex = 'a'.repeat(64);
  const validShaHex2 = 'b'.repeat(64);
  const validShaBuffer = Buffer.from(validShaHex, 'hex');

  describe('SHA-256 Utilities', () => {
    it('isValidSha256 accepts valid 64-char lowercase, uppercase, and prefixed hex', () => {
      expect(isValidSha256(validShaHex)).toBe(true);
      expect(isValidSha256(validShaHex.toUpperCase())).toBe(true);
      expect(isValidSha256(`0x${validShaHex}`)).toBe(true);
      expect(isValidSha256(`\\x${validShaHex}`)).toBe(true);
      expect(isValidSha256(`  ${validShaHex}  `)).toBe(true);
    });

    it('isValidSha256 rejects invalid sha256 strings', () => {
      expect(isValidSha256('')).toBe(false);
      expect(isValidSha256('a'.repeat(63))).toBe(false);
      expect(isValidSha256('a'.repeat(65))).toBe(false);
      expect(isValidSha256('g'.repeat(64))).toBe(false);
      expect(isValidSha256(null)).toBe(false);
      expect(isValidSha256(undefined)).toBe(false);
      expect(isValidSha256(12345)).toBe(false);
      expect(isValidSha256({})).toBe(false);
    });

    it('normalizeSha256 normalizes uppercase and prefixes to lowercase 64-char hex', () => {
      const upper = 'ABCDEF1234567890'.repeat(4);
      expect(normalizeSha256(upper)).toBe(upper.toLowerCase());
      expect(normalizeSha256(`0x${upper}`)).toBe(upper.toLowerCase());
      expect(normalizeSha256(`\\x${upper}`)).toBe(upper.toLowerCase());
    });

    it('normalizeSha256 throws ArtifactIdentityError on invalid string', () => {
      expect(() => normalizeSha256('short')).toThrow(ArtifactIdentityError);
      expect(() => normalizeSha256('not-hex!'.repeat(8))).toThrow(ArtifactIdentityError);
      // @ts-expect-error test non-string
      expect(() => normalizeSha256(null)).toThrow(ArtifactIdentityError);
    });

    it('toCanonicalSha256 handles string, Buffer, and Uint8Array', () => {
      expect(toCanonicalSha256(validShaHex)).toBe(validShaHex);
      expect(toCanonicalSha256(validShaBuffer)).toBe(validShaHex);
      expect(toCanonicalSha256(new Uint8Array(validShaBuffer))).toBe(validShaHex);

      // Invalid Buffer length throws
      expect(() => toCanonicalSha256(Buffer.alloc(31))).toThrow(ArtifactIdentityError);
      expect(() => toCanonicalSha256(Buffer.alloc(33))).toThrow(ArtifactIdentityError);
    });
  });

  describe('createArtifactIdentity', () => {
    it('creates an immutable ArtifactIdentity with valid string, buffer, number, and bigint inputs', () => {
      const id1 = createArtifactIdentity({
        bucket: 'sug-quarantine-bucket',
        objectKey: 'quarantine/app-1/session-1.bin',
        versionId: 'ver-s3-12345',
        sha256: validShaHex,
        sizeBytes: 1048576,
      });

      expect(id1.bucket).toBe('sug-quarantine-bucket');
      expect(id1.objectKey).toBe('quarantine/app-1/session-1.bin');
      expect(id1.versionId).toBe('ver-s3-12345');
      expect(id1.sha256).toBe(validShaHex);
      expect(id1.sizeBytes).toBe(1048576);
      expect(Object.isFrozen(id1)).toBe(true);

      // With Buffer sha256 and bigint sizeBytes
      const id2 = createArtifactIdentity({
        bucket: 'sug-quarantine-bucket',
        objectKey: 'quarantine/app-1/session-1.bin',
        versionId: 'ver-s3-12345',
        sha256: validShaBuffer,
        sizeBytes: BigInt(2048),
      });
      expect(id2.sha256).toBe(validShaHex);
      expect(id2.sizeBytes).toBe(2048);

      // With numeric string sizeBytes
      const id3 = createArtifactIdentity({
        bucket: 'sug-quarantine-bucket',
        objectKey: 'quarantine/app-1/session-1.bin',
        versionId: 'ver-s3-12345',
        sha256: validShaHex,
        sizeBytes: '4096',
      });
      expect(id3.sizeBytes).toBe(4096);
    });

    it('rejects empty or whitespace bucket', () => {
      expect(() =>
        createArtifactIdentity({
          bucket: '',
          objectKey: 'key',
          versionId: 'ver-1',
          sha256: validShaHex,
          sizeBytes: 100,
        }),
      ).toThrow(ArtifactIdentityError);

      expect(() =>
        createArtifactIdentity({
          bucket: '   ',
          objectKey: 'key',
          versionId: 'ver-1',
          sha256: validShaHex,
          sizeBytes: 100,
        }),
      ).toThrow(ArtifactIdentityError);
    });

    it('rejects empty or whitespace objectKey', () => {
      expect(() =>
        createArtifactIdentity({
          bucket: 'bucket',
          objectKey: '',
          versionId: 'ver-1',
          sha256: validShaHex,
          sizeBytes: 100,
        }),
      ).toThrow(ArtifactIdentityError);

      expect(() =>
        createArtifactIdentity({
          bucket: 'bucket',
          objectKey: '   ',
          versionId: 'ver-1',
          sha256: validShaHex,
          sizeBytes: 100,
        }),
      ).toThrow(ArtifactIdentityError);
    });

    it('rejects empty, null, or latest versionId', () => {
      expect(() =>
        createArtifactIdentity({
          bucket: 'bucket',
          objectKey: 'key',
          versionId: '',
          sha256: validShaHex,
          sizeBytes: 100,
        }),
      ).toThrow(ArtifactIdentityError);

      expect(() =>
        createArtifactIdentity({
          bucket: 'bucket',
          objectKey: 'key',
          versionId: 'null',
          sha256: validShaHex,
          sizeBytes: 100,
        }),
      ).toThrow(ArtifactIdentityError);

      expect(() =>
        createArtifactIdentity({
          bucket: 'bucket',
          objectKey: 'key',
          versionId: 'latest',
          sha256: validShaHex,
          sizeBytes: 100,
        }),
      ).toThrow(ArtifactIdentityError);
    });

    it('rejects negative, non-integer, or invalid sizeBytes', () => {
      expect(() =>
        createArtifactIdentity({
          bucket: 'bucket',
          objectKey: 'key',
          versionId: 'ver-1',
          sha256: validShaHex,
          sizeBytes: -1,
        }),
      ).toThrow(ArtifactIdentityError);

      expect(() =>
        createArtifactIdentity({
          bucket: 'bucket',
          objectKey: 'key',
          versionId: 'ver-1',
          sha256: validShaHex,
          sizeBytes: 10.5,
        }),
      ).toThrow(ArtifactIdentityError);

      expect(() =>
        createArtifactIdentity({
          bucket: 'bucket',
          objectKey: 'key',
          versionId: 'ver-1',
          sha256: validShaHex,
          sizeBytes: 'not-a-number',
        }),
      ).toThrow(ArtifactIdentityError);
    });
  });

  describe('validateArtifactIdentity & isArtifactIdentity', () => {
    it('validates a correct ArtifactIdentity', () => {
      const valid = {
        bucket: 'bucket-a',
        objectKey: 'quarantine/k1',
        versionId: 'v123',
        sha256: validShaHex,
        sizeBytes: 500,
      };

      const res = validateArtifactIdentity(valid);
      expect(res.valid).toBe(true);
      expect(res.issues).toEqual([]);
      expect(isArtifactIdentity(valid)).toBe(true);
    });

    it('returns structured issues for invalid objects', () => {
      const invalid = {
        bucket: '',
        objectKey: '',
        versionId: 'latest',
        sha256: 'bad-sha',
        sizeBytes: -5,
      };

      const res = validateArtifactIdentity(invalid);
      expect(res.valid).toBe(false);
      expect(res.issues.length).toBe(5);
      expect(res.issues).toContain('bucket must be a non-empty string');
      expect(res.issues).toContain('objectKey must be a non-empty string');
      expect(res.issues.some((i) => i.includes('versionId'))).toBe(true);
      expect(res.issues.some((i) => i.includes('sha256'))).toBe(true);
      expect(res.issues).toContain('sizeBytes must be a non-negative integer');
      expect(isArtifactIdentity(invalid)).toBe(false);
    });

    it('handles null, undefined, or non-object gracefully', () => {
      expect(validateArtifactIdentity(null).valid).toBe(false);
      expect(validateArtifactIdentity(undefined).valid).toBe(false);
      expect(validateArtifactIdentity('string').valid).toBe(false);
      expect(isArtifactIdentity(null)).toBe(false);
    });
  });

  describe('timingSafeSha256Equal', () => {
    it('returns true for matching hashes in lowercase, uppercase, and prefixes', () => {
      expect(timingSafeSha256Equal(validShaHex, validShaHex)).toBe(true);
      expect(timingSafeSha256Equal(validShaHex, validShaHex.toUpperCase())).toBe(true);
      expect(timingSafeSha256Equal(`0x${validShaHex}`, validShaHex)).toBe(true);
      expect(timingSafeSha256Equal(`\\x${validShaHex}`, validShaHex)).toBe(true);
    });

    it('returns false for different 64-char hashes', () => {
      expect(timingSafeSha256Equal(validShaHex, validShaHex2)).toBe(false);
    });

    it('safely returns false without throwing for length mismatches, malformed strings, or nulls', () => {
      expect(timingSafeSha256Equal(validShaHex, 'short')).toBe(false);
      expect(timingSafeSha256Equal('short', validShaHex)).toBe(false);
      expect(timingSafeSha256Equal('short', 'short')).toBe(false);
      expect(timingSafeSha256Equal(validShaHex, null)).toBe(false);
      expect(timingSafeSha256Equal(null, validShaHex)).toBe(false);
      expect(timingSafeSha256Equal(undefined, undefined)).toBe(false);
      expect(timingSafeSha256Equal('g'.repeat(64), validShaHex)).toBe(false);
    });
  });

  describe('compareArtifactIdentities (T-ID-01 through T-ID-10)', () => {
    const baseIdentity: ArtifactIdentity = {
      bucket: 'sug-quarantine-bucket',
      objectKey: 'quarantine/app-1/file-1.bin',
      versionId: 'v-1001',
      sha256: validShaHex,
      sizeBytes: 1024,
    };

    // T-ID-01: Same key, same version, same hash, same size -> EQUAL
    it('T-ID-01: Same key, same version, same hash, same size -> EQUAL', () => {
      const clone = { ...baseIdentity };
      const result = compareArtifactIdentities(baseIdentity, clone);
      expect(result.equal).toBe(true);
      expect(result.mismatches).toEqual([]);
    });

    // T-ID-02: Same key, different version -> MISMATCH / version_id
    it('T-ID-02: Same key, different version -> MISMATCH / version_id', () => {
      const candidate = { ...baseIdentity, versionId: 'v-1002' };
      const result = compareArtifactIdentities(baseIdentity, candidate);
      expect(result.equal).toBe(false);
      expect(result.mismatches).toEqual(['version_id']);
    });

    // T-ID-03: Same version, different hash -> MISMATCH / sha256
    it('T-ID-03: Same version, different hash -> MISMATCH / sha256', () => {
      const candidate = { ...baseIdentity, sha256: validShaHex2 };
      const result = compareArtifactIdentities(baseIdentity, candidate);
      expect(result.equal).toBe(false);
      expect(result.mismatches).toEqual(['sha256']);
    });

    // T-ID-04: Same hash, different size -> MISMATCH / size_bytes
    it('T-ID-04: Same hash, different size -> MISMATCH / size_bytes', () => {
      const candidate = { ...baseIdentity, sizeBytes: 2048 };
      const result = compareArtifactIdentities(baseIdentity, candidate);
      expect(result.equal).toBe(false);
      expect(result.mismatches).toEqual(['size_bytes']);
    });

    // T-ID-05: Different bucket -> MISMATCH / bucket
    it('T-ID-05: Different bucket -> MISMATCH / bucket', () => {
      const candidate = { ...baseIdentity, bucket: 'sug-other-bucket' };
      const result = compareArtifactIdentities(baseIdentity, candidate);
      expect(result.equal).toBe(false);
      expect(result.mismatches).toEqual(['bucket']);
    });

    // T-ID-06: Different object key -> MISMATCH / object_key
    it('T-ID-06: Different object key -> MISMATCH / object_key', () => {
      const candidate = { ...baseIdentity, objectKey: 'quarantine/app-2/file-2.bin' };
      const result = compareArtifactIdentities(baseIdentity, candidate);
      expect(result.equal).toBe(false);
      expect(result.mismatches).toEqual(['object_key']);
    });

    // T-ID-07: Malformed SHA-256 -> INVALID / MISMATCH
    it('T-ID-07: Malformed SHA-256 -> INVALID / MISMATCH', () => {
      const candidate = { ...baseIdentity, sha256: 'malformed_sha' };
      const result = compareArtifactIdentities(baseIdentity, candidate);
      expect(result.equal).toBe(false);
      expect(result.mismatches).toContain('sha256');
    });

    // T-ID-08: Empty / null / latest VersionId -> INVALID / MISMATCH
    it('T-ID-08: Empty / null / latest VersionId -> INVALID / MISMATCH', () => {
      const candidateNullVer = { ...baseIdentity, versionId: 'null' };
      const resNull = compareArtifactIdentities(baseIdentity, candidateNullVer);
      expect(resNull.equal).toBe(false);
      expect(resNull.mismatches).toContain('version_id');

      const candidateLatestVer = { ...baseIdentity, versionId: 'latest' };
      const resLatest = compareArtifactIdentities(baseIdentity, candidateLatestVer);
      expect(resLatest.equal).toBe(false);
      expect(resLatest.mismatches).toContain('version_id');

      const candidateEmptyVer = { ...baseIdentity, versionId: '' };
      const resEmpty = compareArtifactIdentities(baseIdentity, candidateEmptyVer);
      expect(resEmpty.equal).toBe(false);
      expect(resEmpty.mismatches).toContain('version_id');
    });

    // T-ID-09: Different hash lengths -> safe mismatch without throwing
    it('T-ID-09: Different hash lengths -> safe mismatch without throwing', () => {
      const candidateShortHash = { ...baseIdentity, sha256: 'a'.repeat(32) };
      const result = compareArtifactIdentities(baseIdentity, candidateShortHash);
      expect(result.equal).toBe(false);
      expect(result.mismatches).toContain('sha256');
    });

    // T-ID-10: Multiple fields differ -> all relevant mismatch classes returned
    it('T-ID-10: Multiple fields differ -> all relevant mismatch classes returned', () => {
      const completelyDifferent: ArtifactIdentity = {
        bucket: 'diff-bucket',
        objectKey: 'diff-key',
        versionId: 'diff-ver',
        sha256: validShaHex2,
        sizeBytes: 9999,
      };

      const result = compareArtifactIdentities(baseIdentity, completelyDifferent);
      expect(result.equal).toBe(false);
      expect(result.mismatches).toEqual([
        'bucket',
        'object_key',
        'version_id',
        'sha256',
        'size_bytes',
      ]);
    });

    it('returns all 5 mismatches if candidate is null or undefined without throwing', () => {
      const resNull = compareArtifactIdentities(baseIdentity, null);
      expect(resNull.equal).toBe(false);
      expect(resNull.mismatches).toEqual([
        'bucket',
        'object_key',
        'version_id',
        'sha256',
        'size_bytes',
      ]);

      const resUndef = compareArtifactIdentities(undefined, baseIdentity);
      expect(resUndef.equal).toBe(false);
      expect(resUndef.mismatches).toEqual([
        'bucket',
        'object_key',
        'version_id',
        'sha256',
        'size_bytes',
      ]);
    });
  });
});
