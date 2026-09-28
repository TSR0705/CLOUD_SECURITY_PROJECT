import { describe, it, expect } from 'vitest';
import { toCanonicalJson, computePolicyHash, computePolicyHashHex } from '@sug/policy-engine';

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

  it('produces identical SHA-256 hashes regardless of initial key order', () => {
    const policyDoc1 = {
      schemaVersion: 'sug.policy/v1',
      name: 'canonical-test',
      maxFileSize: 5000000,
      allowedExtensions: ['.pdf'],
      allowedMimeTypes: ['application/pdf'],
    };

    const policyDoc2 = {
      allowedMimeTypes: ['application/pdf'],
      name: 'canonical-test',
      allowedExtensions: ['.pdf'],
      maxFileSize: 5000000,
      schemaVersion: 'sug.policy/v1',
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
      schemaVersion: 'sug.policy/v1',
      name: 'policy-a',
      maxFileSize: 5000000,
    };
    const policyB = {
      schemaVersion: 'sug.policy/v1',
      name: 'policy-b',
      maxFileSize: 5000000,
    };

    const hashA = computePolicyHashHex(toCanonicalJson(policyA));
    const hashB = computePolicyHashHex(toCanonicalJson(policyB));

    expect(hashA).not.toBe(hashB);
  });

  it('strips undefined properties consistently', () => {
    const withUndefined = { a: 1, b: undefined };
    const withoutUndefined = { a: 1 };

    expect(toCanonicalJson(withUndefined)).toBe(toCanonicalJson(withoutUndefined));
  });
});
