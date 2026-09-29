import { describe, it, expect } from 'vitest';
import { validateTypeConsistency } from '@sug/security-engine';

describe('DoD: val-06 — Detector Consistency Rule (Extension vs Declared MIME vs Magic Detection)', () => {
  describe('table-driven 3-way detector consistency checks', () => {
    it('passes when all three detectors agree on canonical type (PDF)', () => {
      const res = validateTypeConsistency({
        extension: '.pdf',
        declaredMime: 'application/pdf',
        magicExt: 'pdf',
        magicMime: 'application/pdf',
      });

      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('PDF');
      expect(res.discrepancies.length).toBe(0);
    });

    it('passes when all three detectors agree on canonical type (JPEG)', () => {
      const res = validateTypeConsistency({
        extension: '.jpg',
        declaredMime: 'image/jpeg',
        magicExt: 'jpg',
        magicMime: 'image/jpeg',
      });

      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('JPEG');
    });

    it('detects MAGIC_EXTENSION_MISMATCH when magic bytes conflict with extension (e.g. PDF claiming file is JPEG)', () => {
      const res = validateTypeConsistency({
        extension: '.pdf',
        declaredMime: 'application/pdf',
        magicExt: 'jpg',
        magicMime: 'image/jpeg',
      });

      expect(res.consistent).toBe(false);
      expect(res.reasonCode).toBe('MAGIC_EXTENSION_MISMATCH');
      expect(res.extensionCanonicalType).toBe('PDF');
      expect(res.magicCanonicalType).toBe('JPEG');
      expect(res.reason).toContain('does not match detected file signature');
    });

    it('detects MAGIC_EXTENSION_MISMATCH when benign extension disguises executable binary (masquerade attack)', () => {
      const res = validateTypeConsistency({
        extension: '.pdf',
        declaredMime: 'application/pdf',
        magicExt: 'exe',
        magicMime: 'application/x-msdownload',
      });

      expect(res.consistent).toBe(false);
      expect(res.reasonCode).toBe('MAGIC_EXTENSION_MISMATCH');
      expect(res.extensionCanonicalType).toBe('PDF');
      expect(res.magicCanonicalType).toBe('EXECUTABLE');
    });

    it('detects MAGIC_MIME_MISMATCH when magic bytes conflict with declared MIME', () => {
      const res = validateTypeConsistency({
        extension: '.pdf',
        declaredMime: 'image/png',
        magicExt: 'pdf',
        magicMime: 'application/pdf',
      });

      expect(res.consistent).toBe(false);
      expect(res.reasonCode).toBe('MAGIC_MIME_MISMATCH');
      expect(res.mimeCanonicalType).toBe('PNG');
      expect(res.magicCanonicalType).toBe('PDF');
    });

    it('detects MIME_EXTENSION_MISMATCH when declared MIME conflicts with extension and magic is absent', () => {
      const res = validateTypeConsistency({
        extension: '.pdf',
        declaredMime: 'image/jpeg',
      });

      expect(res.consistent).toBe(false);
      expect(res.reasonCode).toBe('MIME_EXTENSION_MISMATCH');
      expect(res.extensionCanonicalType).toBe('PDF');
      expect(res.mimeCanonicalType).toBe('JPEG');
    });

    it('honors container compatibility when OOXML Word (.docx) is detected as ZIP magic', () => {
      const res = validateTypeConsistency({
        extension: '.docx',
        declaredMime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        magicExt: 'zip',
        magicMime: 'application/zip',
      });

      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('ZIP');
    });

    it('honors subtype compatibility when CSV is detected as plain text magic', () => {
      const res = validateTypeConsistency({
        extension: '.csv',
        declaredMime: 'text/csv',
        magicExt: 'txt',
        magicMime: 'text/plain',
      });

      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('TEXT');
    });

    it('returns UNDETERMINED when no detectors can identify the file type', () => {
      const res = validateTypeConsistency({
        extension: '.unknownxyz',
        declaredMime: 'unknown/mystery',
      });

      expect(res.consistent).toBe(false);
      expect(res.reasonCode).toBe('UNDETERMINED');
      expect(res.canonicalType).toBeUndefined();
    });

    it('returns UNDETERMINED when input is completely empty or undefined', () => {
      const res = validateTypeConsistency({});
      expect(res.consistent).toBe(false);
      expect(res.reasonCode).toBe('UNDETERMINED');
      expect(res.canonicalType).toBeUndefined();
    });

    it('resolves consistent when extension is omitted but declared MIME and magic agree', () => {
      const res = validateTypeConsistency({
        declaredMime: 'application/pdf',
        magicMime: 'application/pdf',
      });
      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('PDF');
    });

    it('resolves consistent when declared MIME is omitted but extension and magic agree', () => {
      const res = validateTypeConsistency({
        extension: '.pdf',
        magicExt: 'pdf',
      });
      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('PDF');
    });

    it('resolves consistent when magic bytes are absent but extension and declared MIME agree', () => {
      const res = validateTypeConsistency({
        extension: '.pdf',
        declaredMime: 'application/pdf',
      });
      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('PDF');
    });

    it('resolves consistent when only extension is provided', () => {
      const res = validateTypeConsistency({
        extension: '.pdf',
      });
      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('PDF');
    });

    it('resolves consistent when only declared MIME is provided', () => {
      const res = validateTypeConsistency({
        declaredMime: 'application/pdf',
      });
      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('PDF');
    });

    it('resolves consistent when only magic is provided', () => {
      const res = validateTypeConsistency({
        magicMime: 'application/pdf',
      });
      expect(res.consistent).toBe(true);
      expect(res.reasonCode).toBe('CONSISTENT');
      expect(res.canonicalType).toBe('PDF');
    });
  });
});
