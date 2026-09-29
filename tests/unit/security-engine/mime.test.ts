import { describe, it, expect } from 'vitest';
import { parseAndNormalizeMime, validateDeclaredMime } from '@sug/security-engine';

describe('Deterministic Declared MIME Validator & Normalizer', () => {
  describe('parseAndNormalizeMime', () => {
    it('normalizes casing and trims whitespace', () => {
      const res = parseAndNormalizeMime('  Application/PDF  ');
      expect(res.isValid).toBe(true);
      expect(res.baseMime).toBe('application/pdf');
    });

    it('parses and strips parameters from base MIME', () => {
      const res = parseAndNormalizeMime('text/plain; charset=UTF-8; format=flowed');
      expect(res.isValid).toBe(true);
      expect(res.baseMime).toBe('text/plain');
      expect(res.parameters['charset']).toBe('UTF-8');
      expect(res.parameters['format']).toBe('flowed');
    });

    it('unquotes parameter values', () => {
      const res = parseAndNormalizeMime('multipart/form-data; boundary="---12345---"');
      expect(res.isValid).toBe(true);
      expect(res.baseMime).toBe('multipart/form-data');
      expect(res.parameters['boundary']).toBe('---12345---');
    });

    it('rejects malformed MIME types without slash', () => {
      const res = parseAndNormalizeMime('applicationpdf');
      expect(res.isValid).toBe(false);
      expect(res.baseMime).toBe('');
    });

    it('rejects malformed MIME types with multiple slashes', () => {
      const res = parseAndNormalizeMime('application/pdf/extra');
      expect(res.isValid).toBe(false);
    });

    it('rejects control characters and null bytes in MIME', () => {
      const res1 = parseAndNormalizeMime('application/pdf\x00');
      expect(res1.isValid).toBe(false);
      const res2 = parseAndNormalizeMime('application/\x01pdf');
      expect(res2.isValid).toBe(false);
    });

    it('handles empty or null/undefined values', () => {
      expect(parseAndNormalizeMime('').isValid).toBe(false);
      expect(parseAndNormalizeMime(null).isValid).toBe(false);
      expect(parseAndNormalizeMime(undefined).isValid).toBe(false);
    });
  });

  describe('validateDeclaredMime', () => {
    const allowed = ['application/pdf', 'image/jpeg', 'image/png'];
    const blocked = ['application/x-executable', 'application/x-msdownload'];

    it('accepts allowed MIME type', () => {
      const res = validateDeclaredMime('application/pdf', allowed, blocked);
      expect(res.allowed).toBe(true);
      expect(res.reasonCode).toBe('MIME_ALLOWED');
      expect(res.normalizedMime).toBe('application/pdf');
    });

    it('accepts allowed MIME type with parameters (e.g. charset)', () => {
      const res = validateDeclaredMime('application/pdf; charset=binary', allowed, blocked);
      expect(res.allowed).toBe(true);
      expect(res.reasonCode).toBe('MIME_ALLOWED');
      expect(res.normalizedMime).toBe('application/pdf');
    });

    it('rejects MIME type explicitly in blocked list (MIME_BLOCKED)', () => {
      const res = validateDeclaredMime('application/x-executable', allowed, blocked);
      expect(res.allowed).toBe(false);
      expect(res.reasonCode).toBe('MIME_BLOCKED');
      expect(res.reason).toContain('explicitly blocked');
    });

    it('rejects MIME type not permitted in allowlist (MIME_NOT_ALLOWED)', () => {
      const res = validateDeclaredMime('video/mp4', allowed, blocked);
      expect(res.allowed).toBe(false);
      expect(res.reasonCode).toBe('MIME_NOT_ALLOWED');
      expect(res.reason).toContain('not permitted');
    });

    it('rejects missing or empty MIME type (MIME_MISSING)', () => {
      const res = validateDeclaredMime('', allowed, blocked);
      expect(res.allowed).toBe(false);
      expect(res.reasonCode).toBe('MIME_MISSING');
    });

    it('rejects malformed MIME type (MIME_MALFORMED)', () => {
      const res = validateDeclaredMime('not-a-mime', allowed, blocked);
      expect(res.allowed).toBe(false);
      expect(res.reasonCode).toBe('MIME_MALFORMED');
    });
  });
});
