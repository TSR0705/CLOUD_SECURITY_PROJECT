/**
 * @sug/test-fixtures/format-fixtures
 * Deterministic test fixtures for P17 format security checks:
 * - PDF active content (clean, raw keyword, hex-encoded keyword, flate stream)
 * - OOXML macros and external relationships
 * - Image trailing data (PNG, JPEG, GIF)
 * - Embedded executable signatures (PE, ELF, Mach-O)
 * - Polyglots (GIF-ZIP, JPEG-ZIP, PDF-ZIP, advanced polyglot)
 */

import zlib from 'node:zlib';

/**
 * Creates a minimal valid clean PDF.
 */
export function createCleanPdfBuffer(): Buffer {
  const content = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 20 >>
stream
BT
/F1 12 Tf
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000201 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
270
%%EOF
`;
  return Buffer.from(content, 'utf-8');
}

/**
 * Creates a PDF containing active JavaScript in plain text.
 */
export function createActiveContentPdfBuffer(
  type: 'javascript' | 'launch' | 'hex_js' | 'flate_js',
): Buffer {
  if (type === 'launch') {
    const content = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /Type /Action /S /Launch /F (calc.exe) >>
endobj
trailer
<< /Size 5 /Root 1 0 R >>
%%EOF
`;
    return Buffer.from(content, 'utf-8');
  }

  if (type === 'hex_js') {
    // /#4a#61#76#61#53#63#72#69#70#74 = /JavaScript
    const content = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R >>
endobj
4 0 obj
<< /Type /Action /S /#4a#61#76#61#53#63#72#69#70#74 /JS (app.alert("pwned")) >>
endobj
trailer
<< /Size 5 /Root 1 0 R >>
%%EOF
`;
    return Buffer.from(content, 'utf-8');
  }

  if (type === 'flate_js') {
    const rawPayload = '<< /Type /Action /S /JavaScript /JS (app.alert("flate_js")) >>';
    const compressed = zlib.deflateSync(Buffer.from(rawPayload, 'utf-8'));

    const header = Buffer.from(
      `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R >>
endobj
4 0 obj
<< /Filter /FlateDecode /Length ${compressed.length} >>
stream\n`,
      'utf-8',
    );

    const footer = Buffer.from(
      `\nendstream
endobj
trailer
<< /Size 5 /Root 1 0 R >>
%%EOF
`,
      'utf-8',
    );

    return Buffer.concat([header, compressed, footer]);
  }

  // Standard javascript
  const content = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R >>
endobj
4 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert("hello")) >>
endobj
trailer
<< /Size 5 /Root 1 0 R >>
%%EOF
`;
  return Buffer.from(content, 'utf-8');
}

/**
 * Creates a clean PNG buffer.
 */
export function createCleanPngBuffer(): Buffer {
  const pngHeader = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  // IHDR chunk (13 bytes data)
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(1, 0); // width 1
  ihdrData.writeUInt32BE(1, 4); // height 1
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 2; // color type (truecolor)
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace
  const ihdrChunk = createPngChunk('IHDR', ihdrData);

  // IEND chunk (0 bytes data)
  const iendChunk = createPngChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([pngHeader, ihdrChunk, iendChunk]);
}

function createPngChunk(type: string, data: Buffer): Buffer {
  const buf = Buffer.alloc(4 + 4 + data.length + 4);
  buf.writeUInt32BE(data.length, 0);
  buf.write(type, 4, 4, 'ascii');
  data.copy(buf, 8);
  // Calculate CRC-32 (dummy or simple crc)
  buf.writeUInt32BE(0x12345678, 8 + data.length);
  return buf;
}

/**
 * Creates a PNG buffer with trailing suspicious payload.
 */
export function createTrailingPngBuffer(): Buffer {
  const clean = createCleanPngBuffer();
  const trailingPayload = Buffer.from(
    'SURPRISE_PAYLOAD_APPENDED_AFTER_IEND_CHUNK_FOR_STEGANOGRAPHY_AND_C2',
    'utf-8',
  );
  return Buffer.concat([clean, trailingPayload]);
}

/**
 * Creates a clean JPEG buffer.
 */
export function createCleanJpegBuffer(): Buffer {
  // SOI (FF D8), APP0 (FF E0 ...), EOI (FF D9)
  const soi = Buffer.from([0xff, 0xd8]);
  const app0 = Buffer.from([
    0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48,
    0x00, 0x00,
  ]);
  const eoi = Buffer.from([0xff, 0xd9]);
  return Buffer.concat([soi, app0, eoi]);
}

/**
 * Creates a JPEG buffer with trailing suspicious data.
 */
export function createTrailingJpegBuffer(): Buffer {
  const clean = createCleanJpegBuffer();
  const trailingPayload = Buffer.from('HIDDEN_DATA_AFTER_JPEG_EOI_MARKER', 'utf-8');
  return Buffer.concat([clean, trailingPayload]);
}

/**
 * Creates a clean GIF buffer.
 */
export function createCleanGifBuffer(): Buffer {
  // GIF89a header (6) + screen descriptor (7) + trailer ';' (0x3B)
  const header = Buffer.from('GIF89a', 'ascii');
  const screenDesc = Buffer.from([0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00]);
  const trailer = Buffer.from([0x3b]);
  return Buffer.concat([header, screenDesc, trailer]);
}

/**
 * Creates a GIF buffer with trailing data.
 */
export function createTrailingGifBuffer(): Buffer {
  const clean = createCleanGifBuffer();
  const trailing = Buffer.from('SUSPICIOUS_TRAILING_DATA_AFTER_GIF_TRAILER', 'utf-8');
  return Buffer.concat([clean, trailing]);
}

/**
 * Creates a document buffer with an embedded PE executable header at non-zero offset.
 */
export function createEmbeddedPeBuffer(offset: number = 256): Buffer {
  const buf = Buffer.alloc(offset + 512);
  buf.fill(0x20); // fill padding with spaces

  // Write 'MZ' at offset
  buf[offset] = 0x4d;
  buf[offset + 1] = 0x5a;

  // Write e_lfanew at offset + 0x3C pointing to offset + 0x80 (PE header)
  buf.writeUInt32LE(0x80, offset + 0x3c);

  // Write 'PE\0\0' at offset + 0x80
  buf[offset + 0x80] = 0x50;
  buf[offset + 0x81] = 0x45;
  buf[offset + 0x82] = 0x00;
  buf[offset + 0x83] = 0x00;

  return buf;
}

/**
 * Creates a document buffer with an embedded ELF executable header at non-zero offset.
 */
export function createEmbeddedElfBuffer(offset: number = 128): Buffer {
  const buf = Buffer.alloc(offset + 256);
  buf.fill(0x20);

  // '\x7fELF' at offset
  buf[offset] = 0x7f;
  buf[offset + 1] = 0x45; // 'E'
  buf[offset + 2] = 0x4c; // 'L'
  buf[offset + 3] = 0x46; // 'F'
  buf[offset + 4] = 2; // 64-bit
  buf[offset + 5] = 1; // little-endian
  buf[offset + 6] = 1; // version 1

  return buf;
}

/**
 * Creates a minimal valid ZIP archive buffer containing one text file.
 */
export function createMinimalZipBuffer(
  fileName: string = 'test.txt',
  fileContent: string = 'hello',
): Buffer {
  const nameBytes = Buffer.from(fileName, 'utf-8');
  const dataBytes = Buffer.from(fileContent, 'utf-8');

  // Local File Header (30 bytes + name + data)
  const lfh = Buffer.alloc(30 + nameBytes.length + dataBytes.length);
  lfh.writeUInt32LE(0x04034b50, 0); // PK\x03\x04
  lfh.writeUInt16LE(20, 4); // version needed
  lfh.writeUInt16LE(0, 6); // flags
  lfh.writeUInt16LE(0, 8); // compression: stored
  lfh.writeUInt16LE(0, 10); // time
  lfh.writeUInt16LE(0, 12); // date
  lfh.writeUInt32LE(0, 14); // crc32
  lfh.writeUInt32LE(dataBytes.length, 18); // comp size
  lfh.writeUInt32LE(dataBytes.length, 22); // uncomp size
  lfh.writeUInt16LE(nameBytes.length, 26); // name length
  lfh.writeUInt16LE(0, 28); // extra length
  nameBytes.copy(lfh, 30);
  dataBytes.copy(lfh, 30 + nameBytes.length);

  // Central Directory (46 bytes + name)
  const cd = Buffer.alloc(46 + nameBytes.length);
  cd.writeUInt32LE(0x02014b50, 0); // PK\x01\x02
  cd.writeUInt16LE(20, 4); // version made by
  cd.writeUInt16LE(20, 6); // version needed
  cd.writeUInt16LE(0, 8); // flags
  cd.writeUInt16LE(0, 10); // compression: stored
  cd.writeUInt16LE(0, 12); // time
  cd.writeUInt16LE(0, 14); // date
  cd.writeUInt32LE(0, 16); // crc32
  cd.writeUInt32LE(dataBytes.length, 20); // comp size
  cd.writeUInt32LE(dataBytes.length, 24); // uncomp size
  cd.writeUInt16LE(nameBytes.length, 28); // name length
  cd.writeUInt16LE(0, 30); // extra length
  cd.writeUInt16LE(0, 32); // comment length
  cd.writeUInt16LE(0, 34); // disk start
  cd.writeUInt16LE(0, 36); // internal attrs
  cd.writeUInt32LE(0, 38); // external attrs
  cd.writeUInt32LE(0, 42); // relative offset of LFH
  nameBytes.copy(cd, 46);

  // EOCD (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // PK\x05\x06
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // cd disk number
  eocd.writeUInt16LE(1, 8); // entries on disk
  eocd.writeUInt16LE(1, 10); // total entries
  eocd.writeUInt32LE(cd.length, 12); // cd size
  eocd.writeUInt32LE(lfh.length, 16); // cd offset
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([lfh, cd, eocd]);
}

/**
 * Creates poly-01: GIF-ZIP Polyglot.
 */
export function createGifZipPolyglotBuffer(): Buffer {
  const gif = createCleanGifBuffer();
  const zip = createMinimalZipBuffer('payload.txt', 'GIF-ZIP polyglot payload');
  return Buffer.concat([gif, zip]);
}

/**
 * Creates poly-02: JPEG-ZIP Polyglot.
 */
export function createJpegZipPolyglotBuffer(): Buffer {
  const jpeg = createCleanJpegBuffer();
  const zip = createMinimalZipBuffer('payload.txt', 'JPEG-ZIP polyglot payload');
  return Buffer.concat([jpeg, zip]);
}

/**
 * Creates poly-03: PDF-ZIP Polyglot.
 */
export function createPdfZipPolyglotBuffer(): Buffer {
  const pdf = createCleanPdfBuffer();
  const zip = createMinimalZipBuffer('payload.txt', 'PDF-ZIP polyglot payload');
  return Buffer.concat([pdf, zip]);
}

/**
 * Creates poly-04: Advanced polyglot (documented miss).
 * A file with ambiguous format indicators without standard EOCD.
 */
export function createAdvancedPolyglotBuffer(): Buffer {
  // Steganographic / concealed container without standard ZIP EOCD
  const header = Buffer.from('CUSTOM_PARASITIC_CONTAINER_V1\n', 'ascii');
  const payload = Buffer.alloc(1024, 0xaa);
  return Buffer.concat([header, payload]);
}
