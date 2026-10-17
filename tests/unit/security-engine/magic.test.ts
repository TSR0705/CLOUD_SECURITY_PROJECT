import { describe, it, expect } from 'vitest';
import { detectMagic, MAX_MAGIC_BUFFER_BYTES } from '@sug/security-engine';

describe('DoD: val-04 — Magic-Byte & File-Signature Detection (file-type v22 bounded to 4,100 bytes)', () => {
  // Test buffers with valid magic headers
  const PDF_HEADER = Buffer.from('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\n');
  // Standard 33-byte valid PNG header including 8-byte magic + 25-byte IHDR chunk
  const PNG_HEADER = Buffer.from([
    0x89,
    0x50,
    0x4e,
    0x47,
    0x0d,
    0x0a,
    0x1a,
    0x0a, // PNG Signature
    0x00,
    0x00,
    0x00,
    0x0d, // IHDR chunk length (13)
    0x49,
    0x48,
    0x44,
    0x52, // "IHDR"
    0x00,
    0x00,
    0x00,
    0x01, // Width: 1
    0x00,
    0x00,
    0x00,
    0x01, // Height: 1
    0x08,
    0x06,
    0x00,
    0x00,
    0x00, // Bit depth: 8, Color: RGBA, Compression: 0, Filter: 0, Interlace: 0
    0x1f,
    0x15,
    0xc4,
    0x89, // CRC
  ]);
  const JPEG_HEADER = Buffer.from([
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
  ]);
  const GIF_HEADER = Buffer.from('GIF89a\x01\x00\x01\x00\x80\x00\x00');
  const ZIP_HEADER = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00]);

  describe('recognized binary file signatures', () => {
    it('detects PDF format from bounded prefix', async () => {
      const res = await detectMagic(PDF_HEADER);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('application/pdf');
      expect(res.extension).toBe('.pdf');
      expect(res.source).toBe('file-type');
      expect(res.bytesExamined).toBe(PDF_HEADER.length);
    });

    it('detects PNG image from bounded prefix', async () => {
      const res = await detectMagic(PNG_HEADER);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('image/png');
      expect(res.extension).toBe('.png');
      expect(res.source).toBe('file-type');
    });

    it('detects JPEG image from bounded prefix', async () => {
      const res = await detectMagic(JPEG_HEADER);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('image/jpeg');
      expect(res.extension).toBe('.jpg');
      expect(res.source).toBe('file-type');
    });

    it('detects GIF image from bounded prefix', async () => {
      const res = await detectMagic(GIF_HEADER);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('image/gif');
      expect(res.extension).toBe('.gif');
      expect(res.source).toBe('file-type');
    });

    it('detects ZIP archive from bounded prefix', async () => {
      const res = await detectMagic(ZIP_HEADER);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('application/zip');
      expect(res.extension).toBe('.zip');
      expect(res.source).toBe('file-type');
    });
  });

  describe('bounded prefix enforcement (4,100 bytes limit)', () => {
    it('handles files smaller than 4,100 bytes correctly', async () => {
      // 50 bytes PDF
      const smallBuf = Buffer.concat([PDF_HEADER, Buffer.alloc(30, 0x20)]);
      expect(smallBuf.length).toBeLessThan(MAX_MAGIC_BUFFER_BYTES);

      const res = await detectMagic(smallBuf);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('application/pdf');
      expect(res.bytesExamined).toBe(smallBuf.length);
    });

    it('handles files exactly 4,100 bytes correctly', async () => {
      const exactBuf = Buffer.alloc(MAX_MAGIC_BUFFER_BYTES);
      PDF_HEADER.copy(exactBuf);

      const res = await detectMagic(exactBuf);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('application/pdf');
      expect(res.bytesExamined).toBe(MAX_MAGIC_BUFFER_BYTES);
    });

    it('strictly clamps buffers larger than 4,100 bytes to exactly 4,100 bytes examined', async () => {
      // 100,000 bytes large payload
      const largeBuf = Buffer.alloc(100_000);
      PNG_HEADER.copy(largeBuf);

      const res = await detectMagic(largeBuf);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('image/png');
      expect(res.bytesExamined).toBe(MAX_MAGIC_BUFFER_BYTES);
      expect(res.bytesExamined).toBe(4100);
    });
  });

  describe('text and markup formats via custom signature detection', () => {
    it('detects SVG XML image', async () => {
      const svg = Buffer.from(
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><circle cx="50" cy="50" r="40"/></svg>',
      );
      const res = await detectMagic(svg);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('image/svg+xml');
      expect(res.extension).toBe('.svg');
      expect(['file-type', 'custom-signature']).toContain(res.source);
    });

    it('detects XML document', async () => {
      const xml = Buffer.from(
        '<?xml version="1.0" encoding="UTF-8"?><root><item>test</item></root>',
      );
      const res = await detectMagic(xml);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('application/xml');
      expect(res.extension).toBe('.xml');
      expect(['file-type', 'custom-signature']).toContain(res.source);
    });

    it('detects JSON document', async () => {
      const json = Buffer.from(JSON.stringify({ status: 'ok', items: [1, 2, 3] }));
      const res = await detectMagic(json);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('application/json');
      expect(res.extension).toBe('.json');
      expect(res.source).toBe('custom-signature');
    });

    it('detects CSV tabular text', async () => {
      const csv = Buffer.from('id,name,role\n1,alice,admin\n2,bob,analyst\n3,carol,auditor\n');
      const res = await detectMagic(csv);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('text/csv');
      expect(res.extension).toBe('.csv');
      expect(res.source).toBe('custom-signature');
    });

    it('detects plain text file', async () => {
      const txt = Buffer.from('This is a plain text file without any delimiters or markup.');
      const res = await detectMagic(txt);
      expect(res.detected).toBe(true);
      expect(res.mime).toBe('text/plain');
      expect(res.extension).toBe('.txt');
      expect(res.source).toBe('custom-signature');
    });
  });

  describe('unknown signatures and empty inputs', () => {
    it('returns fallback undetermined for random non-text binary bytes', async () => {
      const unknownBinary = Buffer.from([0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
      const res = await detectMagic(unknownBinary);
      expect(res.detected).toBe(false);
      expect(res.mime).toBeUndefined();
      expect(res.extension).toBeUndefined();
      expect(res.source).toBe('fallback');
    });

    it('returns empty fallback for zero-length buffer', async () => {
      const empty = Buffer.alloc(0);
      const res = await detectMagic(empty);
      expect(res.detected).toBe(false);
      expect(res.bytesExamined).toBe(0);
      expect(res.source).toBe('fallback');
    });
  });
});
