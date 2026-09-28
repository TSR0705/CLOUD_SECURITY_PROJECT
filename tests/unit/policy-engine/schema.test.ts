import { describe, it, expect } from 'vitest';
import {
  parsePolicyDocument,
  safeParsePolicyDocument,
  POLICY_SCHEMA_VERSION,
  MAX_POLICY_FILE_SIZE_BYTES,
} from '@sug/policy-engine';

describe('Policy Schema (sug.policy/v1)', () => {
  const validPolicy = {
    schemaVersion: POLICY_SCHEMA_VERSION,
    name: 'test-policy',
    description: 'Unit testing policy',
    maxFileSize: 10 * 1024 * 1024,
    allowedExtensions: ['.jpg', '.png'],
    allowedMimeTypes: ['image/jpeg', 'image/png'],
    blockedExtensions: ['.exe', '.sh'],
    blockedMimeTypes: ['application/x-executable'],
    requireMimeMatch: true,
    allowArchives: false,
    maxArchiveDepth: 0,
    maxArchiveFiles: 0,
  };

  it('successfully parses a strictly valid sug.policy/v1 document', () => {
    const parsed = parsePolicyDocument(validPolicy);
    expect(parsed.schemaVersion).toBe('sug.policy/v1');
    expect(parsed.name).toBe('test-policy');
    expect(parsed.maxFileSize).toBe(10 * 1024 * 1024);
    expect(parsed.allowedExtensions).toEqual(['.jpg', '.png']);
    expect(parsed.allowedMimeTypes).toEqual(['image/jpeg', 'image/png']);
  });

  it('rejects unknown schema versions', () => {
    const invalidVersion = { ...validPolicy, schemaVersion: 'sug.policy/v2' };
    const res = safeParsePolicyDocument(invalidVersion);
    expect(res.success).toBe(false);
  });

  it('strictly rejects documents with unknown / injected fields', () => {
    const injected = { ...validPolicy, maliciousField: 'bypass-auth' };
    const res = safeParsePolicyDocument(injected);
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(res.error.issues[0]?.message).toMatch(/Unrecognized key/i);
    }
  });

  it('rejects non-positive or impossible maxFileSize', () => {
    expect(safeParsePolicyDocument({ ...validPolicy, maxFileSize: 0 }).success).toBe(false);
    expect(safeParsePolicyDocument({ ...validPolicy, maxFileSize: -100 }).success).toBe(false);
    expect(
      safeParsePolicyDocument({ ...validPolicy, maxFileSize: MAX_POLICY_FILE_SIZE_BYTES + 1 })
        .success,
    ).toBe(false);
    expect(safeParsePolicyDocument({ ...validPolicy, maxFileSize: 10.5 }).success).toBe(false);
  });

  it('rejects empty or malformed allowedExtensions', () => {
    expect(safeParsePolicyDocument({ ...validPolicy, allowedExtensions: [] }).success).toBe(false);
    expect(safeParsePolicyDocument({ ...validPolicy, allowedExtensions: ['pdf'] }).success).toBe(
      false,
    ); // missing dot
    expect(safeParsePolicyDocument({ ...validPolicy, allowedExtensions: ['.'] }).success).toBe(
      false,
    );
    expect(
      safeParsePolicyDocument({ ...validPolicy, allowedExtensions: ['.pdf with spaces'] }).success,
    ).toBe(false);
  });

  it('rejects malformed allowedMimeTypes', () => {
    expect(safeParsePolicyDocument({ ...validPolicy, allowedMimeTypes: [] }).success).toBe(false);
    expect(
      safeParsePolicyDocument({ ...validPolicy, allowedMimeTypes: ['invalid-mime'] }).success,
    ).toBe(false);
    expect(safeParsePolicyDocument({ ...validPolicy, allowedMimeTypes: ['image/'] }).success).toBe(
      false,
    );
  });

  it('rejects contradictory extension rules (extension simultaneously allowed and blocked)', () => {
    const contradictory = {
      ...validPolicy,
      allowedExtensions: ['.jpg', '.png'],
      blockedExtensions: ['.png', '.exe'],
    };
    const res = safeParsePolicyDocument(contradictory);
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(
        res.error.issues.some((i) =>
          i.message.includes("Extension '.png' cannot be simultaneously allowed and blocked"),
        ),
      ).toBe(true);
    }
  });

  it('rejects contradictory MIME rules (MIME simultaneously allowed and blocked)', () => {
    const contradictory = {
      ...validPolicy,
      allowedMimeTypes: ['image/jpeg', 'image/png'],
      blockedMimeTypes: ['image/jpeg'],
    };
    const res = safeParsePolicyDocument(contradictory);
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(
        res.error.issues.some((i) =>
          i.message.includes("MIME type 'image/jpeg' cannot be simultaneously allowed and blocked"),
        ),
      ).toBe(true);
    }
  });

  it('rejects invalid archive settings when allowArchives is false', () => {
    const invalidDepth = { ...validPolicy, allowArchives: false, maxArchiveDepth: 2 };
    expect(safeParsePolicyDocument(invalidDepth).success).toBe(false);

    const invalidFiles = { ...validPolicy, allowArchives: false, maxArchiveFiles: 50 };
    expect(safeParsePolicyDocument(invalidFiles).success).toBe(false);
  });

  it('rejects invalid archive settings when allowArchives is true', () => {
    const invalid = {
      ...validPolicy,
      allowArchives: true,
      maxArchiveDepth: 0,
      maxArchiveFiles: 0,
    };
    expect(safeParsePolicyDocument(invalid).success).toBe(false);
  });
});
