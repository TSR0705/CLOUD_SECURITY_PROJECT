import { describe, it, expect } from 'vitest';
import {
  parsePolicyDocument,
  safeParsePolicyDocument,
  POLICY_SCHEMA,
  MAX_POLICY_FILE_SIZE_BYTES,
} from '@sug/policy-engine';

describe('Policy Schema (sug.policy/v1)', () => {
  const validCanonicalPolicy = {
    schema: POLICY_SCHEMA,
    name: 'test-policy',
    description: 'Unit testing policy',
    maxFileSize: 10 * 1024 * 1024,
    allowedExtensions: ['.jpg', '.png'],
    allowedMimeTypes: ['image/jpeg', 'image/png'],
    blockedExtensions: ['.exe', '.sh'],
    blockedMimeTypes: ['application/x-executable'],
    scanRequired: true,
    requiredChecks: [
      'filename.safe',
      'extension.allowed',
      'magic.detect',
      'type.consistency',
      'size.limit',
      'clamav.instream',
      'yara.rules',
      'polyglot.basic',
    ],
    archiveAllowed: false,
    archive: {
      maxCompressedSize: 10 * 1024 * 1024,
      maxUncompressedSize: 20 * 1024 * 1024,
      maxEntries: 100,
      maxDepth: 2,
      maxRatio: 10,
      maxExtractionMs: 5000,
      maxMemoryBytes: 67108864,
    },
    pdf: {
      allowActiveContent: false,
      allowEncrypted: false,
      allowEmbeddedFiles: false,
    },
    office: {
      allowMacros: false,
    },
    image: {
      maxPixels: 25_000_000,
      reencode: false,
    },
    cdrRequired: false,
    onSuspicious: 'QUARANTINE' as const,
    manualReviewThreshold: 50,
    scanTimeoutMs: 30000,
    retention: {
      quarantineDays: 7,
    },
    replicate: true,
  };

  it('successfully parses a strictly valid canonical sug.policy/v1 document', () => {
    const parsed = parsePolicyDocument(validCanonicalPolicy);
    expect(parsed.schema).toBe('sug.policy/v1');
    expect(parsed.name).toBe('test-policy');
    expect(parsed.maxFileSize).toBe(10 * 1024 * 1024);
    expect(parsed.allowedExtensions).toEqual(['.jpg', '.png']);
    expect(parsed.allowedMimeTypes).toEqual(['image/jpeg', 'image/png']);
    expect(parsed.archiveAllowed).toBe(false);
    expect(parsed.archive.maxRatio).toBe(10);
    expect(parsed.pdf.allowActiveContent).toBe(false);
    expect(parsed.office.allowMacros).toBe(false);
    expect(parsed.onSuspicious).toBe('QUARANTINE');
    expect(parsed.retention.quarantineDays).toBe(7);
  });

  it('fills safe canonical defaults when optional blocks are omitted', () => {
    const minimal = {
      schema: 'sug.policy/v1',
      name: 'minimal-policy',
      maxFileSize: 5 * 1024 * 1024,
      allowedExtensions: ['.pdf'],
      allowedMimeTypes: ['application/pdf'],
    };

    const parsed = parsePolicyDocument(minimal);
    expect(parsed.schema).toBe('sug.policy/v1');
    expect(parsed.scanRequired).toBe(true);
    expect(parsed.archiveAllowed).toBe(false);
    expect(parsed.requiredChecks.length).toBeGreaterThanOrEqual(8);
    expect(parsed.archive.maxCompressedSize).toBeDefined();
    expect(parsed.pdf.allowActiveContent).toBe(false);
    expect(parsed.office.allowMacros).toBe(false);
    expect(parsed.image.maxPixels).toBe(25_000_000);
    expect(parsed.onSuspicious).toBe('QUARANTINE');
    expect(parsed.retention.quarantineDays).toBe(7);
    expect(parsed.replicate).toBe(true);
  });

  it('rejects unknown schema versions', () => {
    const invalidVersion = { ...validCanonicalPolicy, schema: 'sug.policy/v2' };
    const res = safeParsePolicyDocument(invalidVersion);
    expect(res.success).toBe(false);
  });

  it('rejects legacy schemaVersion property as unknown key (.strict())', () => {
    const legacy = {
      schemaVersion: 'sug.policy/v1',
      name: 'legacy-key',
      maxFileSize: 1024 * 1024,
      allowedExtensions: ['.pdf'],
      allowedMimeTypes: ['application/pdf'],
    };
    const res = safeParsePolicyDocument(legacy);
    expect(res.success).toBe(false);
  });

  it('strictly rejects documents with unknown / injected top-level fields', () => {
    const injected = { ...validCanonicalPolicy, maliciousField: 'bypass-auth' };
    const res = safeParsePolicyDocument(injected);
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(res.error.issues[0]?.message).toMatch(/Unrecognized key/i);
    }
  });

  it('strictly rejects unknown fields inside nested policy blocks', () => {
    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        archive: { ...validCanonicalPolicy.archive, evilOption: true },
      }).success,
    ).toBe(false);

    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        pdf: { ...validCanonicalPolicy.pdf, allowScriptExecution: true },
      }).success,
    ).toBe(false);

    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        office: { ...validCanonicalPolicy.office, bypassVbaScan: true },
      }).success,
    ).toBe(false);

    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        image: { ...validCanonicalPolicy.image, ignoreTrailingBytes: true },
      }).success,
    ).toBe(false);

    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        retention: { ...validCanonicalPolicy.retention, deleteImmediately: true },
      }).success,
    ).toBe(false);
  });

  it('rejects non-positive or impossible maxFileSize', () => {
    expect(safeParsePolicyDocument({ ...validCanonicalPolicy, maxFileSize: 0 }).success).toBe(
      false,
    );
    expect(safeParsePolicyDocument({ ...validCanonicalPolicy, maxFileSize: -100 }).success).toBe(
      false,
    );
    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        maxFileSize: MAX_POLICY_FILE_SIZE_BYTES + 1,
      }).success,
    ).toBe(false);
    expect(safeParsePolicyDocument({ ...validCanonicalPolicy, maxFileSize: 10.5 }).success).toBe(
      false,
    );
  });

  it('rejects empty or malformed allowedExtensions', () => {
    expect(
      safeParsePolicyDocument({ ...validCanonicalPolicy, allowedExtensions: [] }).success,
    ).toBe(false);
    expect(
      safeParsePolicyDocument({ ...validCanonicalPolicy, allowedExtensions: ['pdf'] }).success,
    ).toBe(false);
    expect(
      safeParsePolicyDocument({ ...validCanonicalPolicy, allowedExtensions: ['.'] }).success,
    ).toBe(false);
    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        allowedExtensions: ['.pdf with spaces'],
      }).success,
    ).toBe(false);
  });

  it('rejects malformed allowedMimeTypes', () => {
    expect(safeParsePolicyDocument({ ...validCanonicalPolicy, allowedMimeTypes: [] }).success).toBe(
      false,
    );
    expect(
      safeParsePolicyDocument({ ...validCanonicalPolicy, allowedMimeTypes: ['invalid-mime'] })
        .success,
    ).toBe(false);
    expect(
      safeParsePolicyDocument({ ...validCanonicalPolicy, allowedMimeTypes: ['image/'] }).success,
    ).toBe(false);
  });

  it('rejects contradictory extension rules (extension simultaneously allowed and blocked)', () => {
    const contradictory = {
      ...validCanonicalPolicy,
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
      ...validCanonicalPolicy,
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

  it('rejects invalid check identifiers in requiredChecks', () => {
    const invalidCheck = {
      ...validCanonicalPolicy,
      requiredChecks: ['filename.safe', 'invalid.custom.check'],
    };
    expect(safeParsePolicyDocument(invalidCheck).success).toBe(false);
  });

  it('rejects duplicate check identifiers in requiredChecks', () => {
    const duplicateCheck = {
      ...validCanonicalPolicy,
      requiredChecks: ['filename.safe', 'extension.allowed', 'filename.safe'],
    };
    const res = safeParsePolicyDocument(duplicateCheck);
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(
        res.error.issues.some((i) =>
          i.message.includes('requiredChecks cannot contain duplicate check identifiers'),
        ),
      ).toBe(true);
    }
  });

  it('rejects invalid onSuspicious action values', () => {
    expect(
      safeParsePolicyDocument({ ...validCanonicalPolicy, onSuspicious: 'ALLOW' }).success,
    ).toBe(false);
    expect(
      safeParsePolicyDocument({ ...validCanonicalPolicy, onSuspicious: 'UNKNOWN' }).success,
    ).toBe(false);
  });

  it('rejects out-of-bound archive limits', () => {
    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        archive: { ...validCanonicalPolicy.archive, maxRatio: 0 },
      }).success,
    ).toBe(false);

    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        archive: { ...validCanonicalPolicy.archive, maxDepth: 0 },
      }).success,
    ).toBe(false);

    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        archive: {
          ...validCanonicalPolicy.archive,
          maxCompressedSize: 20 * 1024 * 1024,
          maxUncompressedSize: 10 * 1024 * 1024, // uncompressed < compressed
        },
      }).success,
    ).toBe(false);
  });

  it('rejects archive extensions/MIME types when archiveAllowed is false', () => {
    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        archiveAllowed: false,
        allowedExtensions: ['.zip'],
      }).success,
    ).toBe(false);

    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        archiveAllowed: false,
        allowedMimeTypes: ['application/zip'],
      }).success,
    ).toBe(false);
  });

  it('rejects archive.maxCompressedSize exceeding policy maxFileSize when archiveAllowed is true', () => {
    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        archiveAllowed: true,
        maxFileSize: 10 * 1024 * 1024,
        allowedExtensions: ['.zip'],
        allowedMimeTypes: ['application/zip'],
        archive: {
          ...validCanonicalPolicy.archive,
          maxCompressedSize: 20 * 1024 * 1024, // > 10 MB maxFileSize
          maxUncompressedSize: 40 * 1024 * 1024,
        },
      }).success,
    ).toBe(false);
  });

  it('rejects out-of-bound retention quarantineDays', () => {
    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        retention: { quarantineDays: 0 },
      }).success,
    ).toBe(false);

    expect(
      safeParsePolicyDocument({
        ...validCanonicalPolicy,
        retention: { quarantineDays: 366 },
      }).success,
    ).toBe(false);
  });
});
