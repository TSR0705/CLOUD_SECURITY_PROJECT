import { describe, it, expect } from 'vitest';
import { validateFilename, sanitizeFilename } from '@sug/security-engine';

describe('DoD: val-08 — Filename Safety & Path Traversal Rejection', () => {
  describe('table-driven dangerous path & traversal rejection', () => {
    const dangerousTestCases = [
      {
        input: '../evil.txt',
        expectedCode: 'PATH_TRAVERSAL_DETECTED',
        desc: 'Relative parent directory traversal (Unix)',
      },
      {
        input: '..\\evil.txt',
        expectedCode: 'PATH_TRAVERSAL_DETECTED',
        desc: 'Relative parent directory traversal (Windows)',
      },
      {
        input: '/absolute/path.txt',
        expectedCode: 'PATH_SEPARATOR_FORBIDDEN',
        desc: 'Absolute Unix path with leading slash',
      },
      {
        input: '\\absolute\\path.txt',
        expectedCode: 'PATH_SEPARATOR_FORBIDDEN',
        desc: 'Absolute Windows path with leading backslash',
      },
      {
        input: 'foo/../../bar.txt',
        expectedCode: 'PATH_TRAVERSAL_DETECTED',
        desc: 'Embedded parent directory traversal (Unix)',
      },
      {
        input: 'foo\\..\\bar.txt',
        expectedCode: 'PATH_TRAVERSAL_DETECTED',
        desc: 'Embedded parent directory traversal (Windows)',
      },
      {
        input: 'foo%2fbar.txt',
        expectedCode: 'ENCODED_TRAVERSAL_DETECTED',
        desc: 'URL-encoded forward slash (%2f)',
      },
      {
        input: 'foo%5cbar.txt',
        expectedCode: 'ENCODED_TRAVERSAL_DETECTED',
        desc: 'URL-encoded backslash (%5c)',
      },
      {
        input: 'foo%2e%2ebar.txt',
        expectedCode: 'ENCODED_TRAVERSAL_DETECTED',
        desc: 'URL-encoded double dots (%2e%2e)',
      },
      {
        input: 'foo%252fbar.txt',
        expectedCode: 'ENCODED_TRAVERSAL_DETECTED',
        desc: 'Double URL-encoded slash (%252f)',
      },
      {
        input: 'evil\0.txt',
        expectedCode: 'NULL_BYTE_DETECTED',
        desc: 'Embedded raw null byte (0x00)',
      },
      {
        input: 'evil%00.txt',
        expectedCode: 'NULL_BYTE_DETECTED',
        desc: 'URL-encoded null byte (%00)',
      },
      {
        input: 'report\x01\x02.pdf',
        expectedCode: 'CONTROL_CHARACTERS_DETECTED',
        desc: 'Embedded control characters (0x01, 0x02)',
      },
      {
        input: 'invoice\u202Efdp.exe',
        expectedCode: 'RTL_OVERRIDE_DETECTED',
        desc: 'Unicode Right-to-Left Override spoofing character (U+202E)',
      },
      {
        input: 'CON.txt',
        expectedCode: 'RESERVED_DEVICE_NAME',
        desc: 'Windows reserved device name CON',
      },
      {
        input: 'aux.pdf',
        expectedCode: 'RESERVED_DEVICE_NAME',
        desc: 'Windows reserved device name AUX (case-insensitive)',
      },
      {
        input: 'NUL',
        expectedCode: 'RESERVED_DEVICE_NAME',
        desc: 'Windows reserved device name NUL without extension',
      },
      {
        input: 'COM1.dat',
        expectedCode: 'RESERVED_DEVICE_NAME',
        desc: 'Windows reserved device name COM1',
      },
      {
        input: 'LPT9.log',
        expectedCode: 'RESERVED_DEVICE_NAME',
        desc: 'Windows reserved device name LPT9',
      },
      {
        input: '',
        expectedCode: 'FILENAME_EMPTY',
        desc: 'Empty string filename',
      },
      {
        input: '   ',
        expectedCode: 'FILENAME_EMPTY',
        desc: 'Whitespace-only filename',
      },
    ];

    for (const tc of dangerousTestCases) {
      it(`rejects ${tc.desc} (${tc.input}) with reasonCode ${tc.expectedCode}`, () => {
        const result = validateFilename(tc.input);
        expect(result.valid).toBe(false);
        expect(result.reasonCode).toBe(tc.expectedCode);
        expect(result.sanitized).toBeDefined();
        expect(typeof result.sanitized).toBe('string');
        expect(result.sanitized.length).toBeGreaterThan(0);
        // Sanitized output must never retain traversals, null bytes, or slashes
        expect(result.sanitized).not.toContain('..');
        expect(result.sanitized).not.toContain('/');
        expect(result.sanitized).not.toContain('\\');
        expect(result.sanitized).not.toContain('\0');
      });
    }
  });

  describe('valid safe filenames', () => {
    const validTestCases = [
      'document.pdf',
      'photo_2026-09-29.jpg',
      'Financial Report (Q3).xlsx',
      'archive-backup.tar.gz',
      'unicode_résumé_2026.docx',
      'space separated document.pdf',
    ];

    for (const filename of validTestCases) {
      it(`accepts valid safe filename: ${filename}`, () => {
        const result = validateFilename(filename);
        expect(result.valid).toBe(true);
        expect(result.reasonCode).toBe('VALID');
        expect(result.hasTraversalAttempt).toBe(false);
        expect(result.hasDangerousCharacters).toBe(false);
        expect(result.hasRtlOverride).toBe(false);
        expect(result.hasReservedName).toBe(false);
        expect(result.sanitized).toBe(filename);
      });
    }
  });

  describe('length clamping and bounds', () => {
    it('rejects raw filename exceeding maximum raw limit of 1024 characters', () => {
      const longName = `${'a'.repeat(1025)}.pdf`;
      const result = validateFilename(longName);
      expect(result.valid).toBe(false);
      expect(result.reasonCode).toBe('NAME_TOO_LONG');
    });

    it('sanitizes long filenames to at most 255 characters while preserving extension', () => {
      const longName = `${'a'.repeat(300)}.pdf`;
      const sanitized = sanitizeFilename(longName);
      expect(sanitized.length).toBe(255);
      expect(sanitized.endsWith('.pdf')).toBe(true);
    });
  });

  describe('reserved device name sanitization', () => {
    it('prefixes reserved device names with safe_ prefix upon sanitization', () => {
      const sanitized = sanitizeFilename('CON.txt');
      expect(sanitized).toBe('safe_CON.txt');
    });
  });
});
