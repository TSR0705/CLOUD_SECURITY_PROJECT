import { describe, it, expect } from 'vitest';
import {
  toCanonicalJson,
  computePolicyHash,
  computePolicyHashHex,
  createDocumentsPreset,
  createArchivesStrictPreset,
} from '@sug/policy-engine';

describe('Canonical JSON and Policy Hashing', () => {
  it('sorts keys recursively in alphabetical order', () => {
    const objA = {
      z: 1,
      b: { d: 4, c: 3 },
      a: [{ y: 2, x: 1 }],
    };

    const objB = {
      a: [{ x: 1, y: 2 }],
      z: 1,
      b: { c: 3, d: 4 },
    };

    expect(toCanonicalJson(objA)).toBe(toCanonicalJson(objB));
    expect(toCanonicalJson(objA)).toBe('{"a":[{"x":1,"y":2}],"b":{"c":3,"d":4},"z":1}');
  });

  it('produces identical SHA-256 hashes regardless of initial top-level and nested key order', () => {
    const policyDoc1 = {
      schema: 'sug.policy/v1',
      name: 'canonical-test',
      maxFileSize: 5000000,
      allowedExtensions: ['.pdf'],
      allowedMimeTypes: ['application/pdf'],
      archive: {
        maxRatio: 10,
        maxDepth: 2,
        maxCompressedSize: 5000000,
        maxUncompressedSize: 10000000,
        maxEntries: 100,
        maxExtractionMs: 5000,
        maxMemoryBytes: 67108864,
      },
      pdf: {
        allowActiveContent: false,
        allowEncrypted: false,
        allowEmbeddedFiles: false,
      },
    };

    const policyDoc2 = {
      pdf: {
        allowEmbeddedFiles: false,
        allowActiveContent: false,
        allowEncrypted: false,
      },
      allowedMimeTypes: ['application/pdf'],
      archive: {
        maxMemoryBytes: 67108864,
        maxExtractionMs: 5000,
        maxEntries: 100,
        maxUncompressedSize: 10000000,
        maxCompressedSize: 5000000,
        maxDepth: 2,
        maxRatio: 10,
      },
      name: 'canonical-test',
      allowedExtensions: ['.pdf'],
      maxFileSize: 5000000,
      schema: 'sug.policy/v1',
    };

    const hash1 = computePolicyHashHex(toCanonicalJson(policyDoc1));
    const hash2 = computePolicyHashHex(toCanonicalJson(policyDoc2));

    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(hash1)).toBe(true);

    const bufHash1 = computePolicyHash(toCanonicalJson(policyDoc1));
    const bufHash2 = computePolicyHash(toCanonicalJson(policyDoc2));
    expect(bufHash1).toEqual(bufHash2);
    expect(bufHash1.length).toBe(32);
  });

  it('produces different hashes when policy contents differ', () => {
    const policyA = {
      schema: 'sug.policy/v1',
      name: 'policy-a',
      maxFileSize: 5000000,
    };
    const policyB = {
      schema: 'sug.policy/v1',
      name: 'policy-b',
      maxFileSize: 5000000,
    };

    const hashA = computePolicyHashHex(toCanonicalJson(policyA));
    const hashB = computePolicyHashHex(toCanonicalJson(policyB));

    expect(hashA).not.toBe(hashB);
  });

  it('produces a different hash when security-relevant nested archive.maxRatio changes', () => {
    const base = createArchivesStrictPreset();
    const modified = {
      ...base,
      archive: {
        ...base.archive,
        maxRatio: base.archive.maxRatio + 5,
      },
    };

    const hashBase = computePolicyHashHex(toCanonicalJson(base));
    const hashModified = computePolicyHashHex(toCanonicalJson(modified));

    expect(hashBase).not.toBe(hashModified);
  });

  it('produces a different hash when security-relevant nested pdf or office permissions change', () => {
    const base = createDocumentsPreset();
    const withActiveContent = {
      ...base,
      pdf: {
        ...base.pdf,
        allowActiveContent: true,
      },
    };
    const withMacros = {
      ...base,
      office: {
        ...base.office,
        allowMacros: true,
      },
    };

    const hashBase = computePolicyHashHex(toCanonicalJson(base));
    const hashActive = computePolicyHashHex(toCanonicalJson(withActiveContent));
    const hashMacros = computePolicyHashHex(toCanonicalJson(withMacros));

    expect(hashBase).not.toBe(hashActive);
    expect(hashBase).not.toBe(hashMacros);
    expect(hashActive).not.toBe(hashMacros);
  });

  it('produces a different hash when requiredChecks list changes', () => {
    const base = createDocumentsPreset();
    const modifiedChecks = {
      ...base,
      requiredChecks: base.requiredChecks.filter((c) => c !== 'polyglot.basic'),
    };

    const hashBase = computePolicyHashHex(toCanonicalJson(base));
    const hashModified = computePolicyHashHex(toCanonicalJson(modifiedChecks));

    expect(hashBase).not.toBe(hashModified);
  });

  it('produces a different hash when onSuspicious action changes', () => {
    const base = createDocumentsPreset();
    const modified = {
      ...base,
      onSuspicious: 'BLOCK' as const,
    };

    const hashBase = computePolicyHashHex(toCanonicalJson(base));
    const hashModified = computePolicyHashHex(toCanonicalJson(modified));

    expect(hashBase).not.toBe(hashModified);
  });

  it('strips undefined properties consistently', () => {
    const withUndefined = { a: 1, b: undefined };
    const withoutUndefined = { a: 1 };

    expect(toCanonicalJson(withUndefined)).toBe(toCanonicalJson(withoutUndefined));
  });
});
