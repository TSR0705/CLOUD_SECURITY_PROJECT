import { describe, it, expect } from 'vitest';
import { validateDoubleExtension } from '@sug/security-engine';

describe('DoD: val-03 — Double-Extension Protection & Masquerade Detection', () => {
  describe('table-driven dangerous double-extension rejection', () => {
    const dangerousTestCases = [
      {
        filename: 'invoice.pdf.exe',
        expectedCode: 'DOUBLE_EXTENSION_DETECTED',
        desc: 'PDF document disguised with .exe executable suffix',
      },
      {
        filename: 'photo.jpg.exe',
        expectedCode: 'DOUBLE_EXTENSION_DETECTED',
        desc: 'JPEG image disguised with .exe executable suffix',
      },
      {
        filename: 'report.docx.js',
        expectedCode: 'DOUBLE_EXTENSION_DETECTED',
        desc: 'Word document disguised with .js script suffix',
      },
      {
        filename: 'document.pdf.php',
        expectedCode: 'DOUBLE_EXTENSION_DETECTED',
        desc: 'PDF document disguised with .php script suffix',
      },
      {
        filename: 'backup.sql.vbs',
        expectedCode: 'DOUBLE_EXTENSION_DETECTED',
        desc: 'SQL file disguised with .vbs script suffix',
      },
      {
        filename: 'test.pdf.scr',
        expectedCode: 'DOUBLE_EXTENSION_DETECTED',
        desc: 'PDF document disguised with .scr screensaver executable',
      },
      {
        filename: 'invoice.pdf.bat',
        expectedCode: 'DOUBLE_EXTENSION_DETECTED',
        desc: 'PDF document disguised with .bat batch file',
      },
      {
        filename: 'payload.png.ps1',
        expectedCode: 'DOUBLE_EXTENSION_DETECTED',
        desc: 'PNG image disguised with .ps1 PowerShell script',
      },
      {
        filename: 'archive.zip.jar',
        expectedCode: 'DOUBLE_EXTENSION_DETECTED',
        desc: 'ZIP archive disguised with .jar Java executable',
      },
      {
        filename: 'invoice.exe.pdf',
        expectedCode: 'HIDDEN_EXECUTABLE_EXTENSION',
        desc: 'Executable .exe hidden as inner extension before .pdf',
      },
      {
        filename: 'malware.sh.png',
        expectedCode: 'HIDDEN_EXECUTABLE_EXTENSION',
        desc: 'Shell script .sh hidden as inner extension before .png',
      },
      {
        filename: 'trojan.dll.docx',
        expectedCode: 'HIDDEN_EXECUTABLE_EXTENSION',
        desc: 'DLL binary hidden as inner extension before .docx',
      },
    ];

    for (const tc of dangerousTestCases) {
      it(`rejects ${tc.desc} ("${tc.filename}") with reasonCode ${tc.expectedCode}`, () => {
        const res = validateDoubleExtension(tc.filename);
        expect(res.valid).toBe(false);
        expect(res.reasonCode).toBe(tc.expectedCode);
        expect(res.isDangerous).toBe(true);
        expect(res.isDoubleExtension).toBe(true);
        expect(res.reason).toBeDefined();
      });
    }
  });

  describe('table-driven safe compound and benign multi-dot filenames', () => {
    const safeTestCases = [
      {
        filename: 'archive.tar.gz',
        expectedCode: 'SAFE_COMPOUND_EXTENSION',
        desc: 'Recognized safe compound archive .tar.gz',
      },
      {
        filename: 'backup.tar.bz2',
        expectedCode: 'SAFE_COMPOUND_EXTENSION',
        desc: 'Recognized safe compound archive .tar.bz2',
      },
      {
        filename: 'data.tar.xz',
        expectedCode: 'SAFE_COMPOUND_EXTENSION',
        desc: 'Recognized safe compound archive .tar.xz',
      },
      {
        filename: 'backup.2026.09.29.pdf',
        expectedCode: 'SINGLE_EXTENSION',
        desc: 'Multi-dot filename with date stamps and single .pdf extension',
      },
      {
        filename: 'my.report.v1.0.docx',
        expectedCode: 'SINGLE_EXTENSION',
        desc: 'Multi-dot filename with version numbers and single .docx extension',
      },
      {
        filename: 'standard-document.pdf',
        expectedCode: 'SINGLE_EXTENSION',
        desc: 'Standard single-extension document',
      },
      {
        filename: 'simple-image.jpg',
        expectedCode: 'SINGLE_EXTENSION',
        desc: 'Standard single-extension image',
      },
      {
        filename: 'README',
        expectedCode: 'NO_EXTENSION',
        desc: 'Filename without extension',
      },
    ];

    for (const tc of safeTestCases) {
      it(`accepts ${tc.desc} ("${tc.filename}") with reasonCode ${tc.expectedCode}`, () => {
        const res = validateDoubleExtension(tc.filename);
        expect(res.valid).toBe(true);
        expect(res.reasonCode).toBe(tc.expectedCode);
        expect(res.isDangerous).toBe(false);
      });
    }
  });

  describe('single executable without disguise', () => {
    it('flags standalone single executable as dangerous', () => {
      const res = validateDoubleExtension('payload.exe');
      expect(res.valid).toBe(false);
      expect(res.isDangerous).toBe(true);
      expect(res.reasonCode).toBe('SINGLE_EXTENSION');
    });
  });
});
