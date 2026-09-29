import { describe, it, expect } from 'vitest';
import { extractExtension, validateExtension } from '@sug/security-engine';

describe('Deterministic Extension Extraction & Policy Allowlist Validator', () => {
  describe('canonical extension extraction behaviors', () => {
    const extractionTestCases = [
      {
        input: 'report.pdf',
        expectedExt: '.pdf',
        expectedCompound: '.pdf',
        hasExtension: true,
        isDotfile: false,
      },
      {
        input: 'report.tar.gz',
        expectedExt: '.gz',
        expectedCompound: '.tar.gz',
        hasExtension: true,
        isDotfile: false,
      },
      {
        input: 'report.exe',
        expectedExt: '.exe',
        expectedCompound: '.exe',
        hasExtension: true,
        isDotfile: false,
      },
      {
        input: 'report',
        expectedExt: '',
        expectedCompound: '',
        hasExtension: false,
        isDotfile: false,
      },
      {
        input: '.hidden',
        expectedExt: '',
        expectedCompound: '',
        hasExtension: false,
        isDotfile: true,
      },
      {
        input: '.gitignore',
        expectedExt: '',
        expectedCompound: '',
        hasExtension: false,
        isDotfile: true,
      },
      {
        input: 'foo.',
        expectedExt: '',
        expectedCompound: '',
        hasExtension: false,
        isDotfile: false,
      },
      {
        input: 'foo..pdf',
        expectedExt: '.pdf',
        expectedCompound: '.pdf',
        hasExtension: true,
        isDotfile: false,
      },
      {
        input: 'archive.TAR.GZ',
        expectedExt: '.gz',
        expectedCompound: '.tar.gz',
        hasExtension: true,
        isDotfile: false,
      },
      {
        input: 'document.PDF',
        expectedExt: '.pdf',
        expectedCompound: '.pdf',
        hasExtension: true,
        isDotfile: false,
      },
    ];

    for (const tc of extractionTestCases) {
      it(`extracts extension for "${tc.input}" -> primary: "${tc.expectedExt}", compound: "${tc.expectedCompound}"`, () => {
        const res = extractExtension(tc.input);
        expect(res.extension).toBe(tc.expectedExt);
        expect(res.compoundExtension).toBe(tc.expectedCompound);
        expect(res.hasExtension).toBe(tc.hasExtension);
        expect(res.isDotfile).toBe(tc.isDotfile);
      });
    }
  });

  describe('policy extension validation', () => {
    const allowed = ['.pdf', '.docx', '.jpg', '.tar.gz'];
    const blocked = ['.exe', '.sh', '.bat'];

    it('permits valid extension in allowlist (case-insensitive)', () => {
      const res = validateExtension('report.PDF', allowed, blocked);
      expect(res.allowed).toBe(true);
      expect(res.reasonCode).toBe('EXTENSION_ALLOWED');
      expect(res.extension).toBe('.pdf');
    });

    it('permits recognized compound extension in allowlist (.tar.gz)', () => {
      const res = validateExtension('backup.tar.gz', allowed, blocked);
      expect(res.allowed).toBe(true);
      expect(res.reasonCode).toBe('EXTENSION_ALLOWED');
    });

    it('rejects extension explicitly in blocked list (EXTENSION_BLOCKED)', () => {
      const res = validateExtension('malware.exe', allowed, blocked);
      expect(res.allowed).toBe(false);
      expect(res.reasonCode).toBe('EXTENSION_BLOCKED');
      expect(res.reason).toContain('explicitly blocked');
    });

    it('rejects extension not in allowlist (EXTENSION_NOT_ALLOWED)', () => {
      const res = validateExtension('music.mp3', allowed, blocked);
      expect(res.allowed).toBe(false);
      expect(res.reasonCode).toBe('EXTENSION_NOT_ALLOWED');
      expect(res.reason).toContain('not permitted');
    });

    it('rejects file without extension (EXTENSION_MISSING)', () => {
      const res = validateExtension('noextension', allowed, blocked);
      expect(res.allowed).toBe(false);
      expect(res.reasonCode).toBe('EXTENSION_MISSING');
    });

    it('handles empty allowlist returning EXTENSION_UNDETERMINED', () => {
      const res = validateExtension('file.pdf', [], []);
      expect(res.allowed).toBe(false);
      expect(res.reasonCode).toBe('EXTENSION_UNDETERMINED');
    });
  });
});
