/**
 * @sug/test-fixtures/archive-builder
 * Deterministic generator for valid, malformed, and adversarial ZIP fixtures.
 *
 * Implements byte-exact ZIP construction according to PKWARE APPNOTE.TXT:
 * - Stored (method 0) and Deflated (method 8)
 * - Adversarial ZIP bombs (high-ratio, overlapping physical spans)
 * - Security attack vectors (Zip Slip, Symlinks, Encryption, Multiple EOCD, Lying sizes)
 * - Clean OOXML containers (DOCX OPC structure)
 */

import zlib from 'node:zlib';

export interface ZipEntryDefinition {
  name: string;
  content: Buffer | string;
  method?: 0 | 8 | number | undefined;
  isEncrypted?: boolean | undefined;
  isSymlink?: boolean | undefined;
  customCrc32?: number | undefined;
  customCompressedSize?: number | undefined;
  customUncompressedSize?: number | undefined;
  localHeaderOffsetOverride?: number | undefined;
}

export function computeCrc32(data: Buffer): number {
  return zlib.crc32(data);
}

/**
 * Builds a ZIP buffer from a list of entry definitions.
 */
export function buildZip(
  entries: ZipEntryDefinition[],
  options?: {
    trailingGarbage?: Buffer | undefined;
    duplicateEocd?: boolean | undefined;
    corruptEocdComment?: boolean | undefined;
  },
): Buffer {
  const localHeadersAndData: Buffer[] = [];
  const cdHeaders: Buffer[] = [];
  let currentOffset = 0;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!;
    const rawContent = Buffer.isBuffer(entry.content)
      ? entry.content
      : Buffer.from(entry.content, 'utf-8');

    const method = entry.method ?? 8;
    let compressedData: Buffer;

    if (method === 0) {
      compressedData = rawContent;
    } else if (method === 8) {
      compressedData = zlib.deflateRawSync(rawContent);
    } else {
      // unsupported method (e.g. 12 = bzip2), dummy compressed payload
      compressedData = rawContent;
    }

    const uncompressedSize = entry.customUncompressedSize ?? rawContent.length;
    const compressedSize = entry.customCompressedSize ?? compressedData.length;
    const crc = entry.customCrc32 ?? computeCrc32(rawContent);
    const flags = entry.isEncrypted ? 0x0001 : 0x0000;
    const nameBuf = Buffer.from(entry.name, 'utf-8');

    const localOffset = entry.localHeaderOffsetOverride ?? currentOffset;

    // --- Local File Header (30 bytes + nameBuf.length) ---
    const lfh = Buffer.alloc(30 + nameBuf.length);
    lfh.writeUInt32LE(0x04034b50, 0); // PK\x03\x04
    lfh.writeUInt16LE(20, 4); // version needed
    lfh.writeUInt16LE(flags, 6); // general purpose bit flag
    lfh.writeUInt16LE(method, 8); // compression method
    lfh.writeUInt16LE(0x4a21, 10); // time (10:17:02)
    lfh.writeUInt16LE(0x5465, 12); // date (2026-03-05)
    lfh.writeUInt32LE(crc, 14); // crc-32
    lfh.writeUInt32LE(compressedSize, 18); // compressed size
    lfh.writeUInt32LE(uncompressedSize, 22); // uncompressed size
    lfh.writeUInt16LE(nameBuf.length, 26); // file name length
    lfh.writeUInt16LE(0, 28); // extra field length
    nameBuf.copy(lfh, 30);

    localHeadersAndData.push(lfh);
    localHeadersAndData.push(compressedData);

    currentOffset += lfh.length + compressedData.length;

    // --- Central Directory Header (46 bytes + nameBuf.length) ---
    // If symlink, version made by = Unix (3 << 8) and external attributes = (0120777 << 16)
    const versionMadeBy = entry.isSymlink ? 0x031e : 0x0014;
    const externalAttr = entry.isSymlink ? (0o120777 << 16) >>> 0 : 0;

    const cdh = Buffer.alloc(46 + nameBuf.length);
    cdh.writeUInt32LE(0x02014b50, 0); // PK\x01\x02
    cdh.writeUInt16LE(versionMadeBy, 4); // version made by
    cdh.writeUInt16LE(20, 6); // version needed
    cdh.writeUInt16LE(flags, 8); // flags
    cdh.writeUInt16LE(method, 10); // method
    cdh.writeUInt16LE(0x4a21, 12); // time
    cdh.writeUInt16LE(0x5465, 14); // date
    cdh.writeUInt32LE(crc, 16); // crc-32
    cdh.writeUInt32LE(compressedSize, 20); // compressed size
    cdh.writeUInt32LE(uncompressedSize, 24); // uncompressed size
    cdh.writeUInt16LE(nameBuf.length, 28); // file name length
    cdh.writeUInt16LE(0, 30); // extra field length
    cdh.writeUInt16LE(0, 32); // comment length
    cdh.writeUInt16LE(0, 34); // disk number start
    cdh.writeUInt16LE(0, 36); // internal file attributes
    cdh.writeUInt32LE(externalAttr, 38); // external file attributes
    cdh.writeUInt32LE(localOffset, 42); // relative offset of local header
    nameBuf.copy(cdh, 46);

    cdHeaders.push(cdh);
  }

  const localPayload = Buffer.concat(localHeadersAndData);
  const cdOffset = localPayload.length;
  const cdPayload = Buffer.concat(cdHeaders);
  const cdSize = cdPayload.length;

  // --- End of Central Directory (EOCD) (22 bytes) ---
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // PK\x05\x06
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // disk with CD
  eocd.writeUInt16LE(entries.length, 8); // entries on disk
  eocd.writeUInt16LE(entries.length, 10); // total entries
  eocd.writeUInt32LE(cdSize, 12); // size of CD
  eocd.writeUInt32LE(cdOffset, 16); // offset of CD
  eocd.writeUInt16LE(options?.corruptEocdComment ? 999 : 0, 20); // comment length

  const chunks: Buffer[] = [localPayload, cdPayload, eocd];

  if (options?.duplicateEocd) {
    // Append an extra valid EOCD to simulate chameleon parser differential
    const dupEocd = Buffer.alloc(22);
    eocd.copy(dupEocd);
    chunks.push(dupEocd);
  }

  if (options?.trailingGarbage) {
    chunks.push(options.trailingGarbage);
  }

  return Buffer.concat(chunks);
}

/**
 * Generates an adversarial high-ratio ZIP bomb (~1 MB compressed expanding to ~1 GB declared).
 * Uses repeated sequences in DEFLATE to achieve > 100:1 declared and streaming ratio.
 */
export function buildHighRatioZipBombFixture(): Buffer {
  // 1 MB buffer of zeros
  const oneMbZeros = Buffer.alloc(1024 * 1024, 0);
  const compressedZeros = zlib.deflateRawSync(oneMbZeros);

  // We define an entry that claims uncompressed size of 1 GB (1,073,741,824 bytes)
  // or a multi-entry bomb expanding toward 1 GB
  return buildZip([
    {
      name: 'bomb.dat',
      content: oneMbZeros,
      method: 8,
      customUncompressedSize: 1024 * 1024 * 1024, // 1 GB declared
      customCompressedSize: compressedZeros.length,
    },
  ]);
}

/**
 * Generates an adversarial streaming ZIP bomb (ARC-02B).
 * Structurally valid ZIP whose headers declare safe size and ratio (passes Phase 1),
 * but whose deflated stream expands to > 10 MB, causing Phase 2 streaming decompression
 * to detect the ratio/size explosion and abort mid-stream without materializing the full expansion.
 */
export function buildStreamingZipBombFixture(): Buffer {
  const tenMbZeros = Buffer.alloc(10 * 1024 * 1024, 0);
  const compressedZeros = zlib.deflateRawSync(tenMbZeros);
  const crc = zlib.crc32(tenMbZeros);

  return buildZip([
    {
      name: 'stream_bomb.dat',
      content: tenMbZeros,
      method: 8,
      customCompressedSize: compressedZeros.length,
      customUncompressedSize: 500_000,
      customCrc32: crc,
    },
  ]);
}

/**
 * Generates an adversarial Fifield non-recursive ZIP bomb with overlapping physical entry ranges.
 */
export function buildOverlappingZipFixture(): Buffer {
  const content = Buffer.from('Fifield overlapping payload test', 'utf-8');

  return buildZip([
    {
      name: 'entry1.txt',
      content,
      method: 8,
    },
    {
      name: 'entry2.txt',
      content,
      method: 8,
      // Points entry 2 to offset 0 (overlapping entry 1)
      localHeaderOffsetOverride: 0,
    },
  ]);
}

/**
 * Builds a clean OOXML (DOCX) container.
 */
export function buildCleanDocxFixture(): Buffer {
  return buildZip([
    {
      name: '[Content_Types].xml',
      content:
        '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>',
      method: 8,
    },
    {
      name: '_rels/.rels',
      content:
        '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
      method: 8,
    },
    {
      name: 'word/document.xml',
      content:
        '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello Secure Upload Gateway</w:t></w:r></w:p></w:body></w:document>',
      method: 8,
    },
  ]);
}
