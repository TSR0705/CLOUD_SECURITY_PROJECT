import { describe, it, expect } from 'vitest';
import { validateFileSize } from '@sug/security-engine';

describe('DoD: val-12 — File Size Validation Rule', () => {
  const policyMax = 10 * 1024 * 1024; // 10 MB

  it('accepts file size within policy limit and matching declared size', () => {
    const res = validateFileSize({
      actualSizeBytes: 1024 * 500, // 500 KB
      declaredSizeBytes: 1024 * 500,
      policyMaxBytes: policyMax,
    });

    expect(res.valid).toBe(true);
    expect(res.reasonCode).toBe('SIZE_VALID');
    expect(res.actualSize).toBe(1024 * 500);
  });

  it('accepts file size within policy limit when declared size is omitted', () => {
    const res = validateFileSize({
      actualSizeBytes: 1024 * 500,
      policyMaxBytes: policyMax,
    });

    expect(res.valid).toBe(true);
    expect(res.reasonCode).toBe('SIZE_VALID');
  });

  it('rejects file size <= 0 with INVALID_SIZE', () => {
    const resZero = validateFileSize({
      actualSizeBytes: 0,
      policyMaxBytes: policyMax,
    });
    expect(resZero.valid).toBe(false);
    expect(resZero.reasonCode).toBe('INVALID_SIZE');

    const resNeg = validateFileSize({
      actualSizeBytes: -100,
      policyMaxBytes: policyMax,
    });
    expect(resNeg.valid).toBe(false);
    expect(resNeg.reasonCode).toBe('INVALID_SIZE');
  });

  it('rejects non-integer file size with INVALID_SIZE', () => {
    const res = validateFileSize({
      actualSizeBytes: 1234.56,
      policyMaxBytes: policyMax,
    });
    expect(res.valid).toBe(false);
    expect(res.reasonCode).toBe('INVALID_SIZE');
  });

  it('rejects file size exceeding policy maxFileSize with SIZE_EXCEEDS_POLICY', () => {
    const res = validateFileSize({
      actualSizeBytes: 15 * 1024 * 1024, // 15 MB > 10 MB policy
      declaredSizeBytes: 15 * 1024 * 1024,
      policyMaxBytes: policyMax,
    });

    expect(res.valid).toBe(false);
    expect(res.reasonCode).toBe('SIZE_EXCEEDS_POLICY');
    expect(res.reason).toContain('exceeds policy maximum limit');
  });

  it('rejects file size exceeding global gateway ceiling of 50 MB with SIZE_EXCEEDS_GLOBAL_LIMIT', () => {
    const res = validateFileSize({
      actualSizeBytes: 55 * 1024 * 1024, // 55 MB > 50 MB
      policyMaxBytes: 100 * 1024 * 1024, // Policy allows 100 MB, but gateway caps at 50 MB
    });

    expect(res.valid).toBe(false);
    expect(res.reasonCode).toBe('SIZE_EXCEEDS_GLOBAL_LIMIT');
    expect(res.reason).toContain('gateway maximum ceiling');
  });

  it('rejects mismatch between actual streamed size and declared size with SIZE_MISMATCH', () => {
    const res = validateFileSize({
      actualSizeBytes: 1000,
      declaredSizeBytes: 500, // Client lied or truncated
      policyMaxBytes: policyMax,
    });

    expect(res.valid).toBe(false);
    expect(res.reasonCode).toBe('SIZE_MISMATCH');
    expect(res.reason).toContain('does not match declared size');
  });

  it('rejects invalid declared size (<= 0 or non-integer) with INVALID_SIZE', () => {
    const res = validateFileSize({
      actualSizeBytes: 1000,
      declaredSizeBytes: -1,
      policyMaxBytes: policyMax,
    });

    expect(res.valid).toBe(false);
    expect(res.reasonCode).toBe('INVALID_SIZE');
  });
});
