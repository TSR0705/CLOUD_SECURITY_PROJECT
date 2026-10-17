/**
 * @sug/tests/unit/security-engine/archive.test.ts
 * Unit tests for Two-Phase Safe ZIP and OOXML Inspection Engine (P16).
 *
 * Verifies canonical security contracts:
 * - arc-01: archive under no-archive policy (ARCHIVE_FORBIDDEN)
 * - arc-02: high-ratio ZIP bomb (< 10s, worker RSS < 256 MB)
 * - arc-03: nested ZIP depth 5 (NESTED_ARCHIVE_DEPTH_EXCEEDED)
 * - arc-04: entry count ceiling (ENTRY_COUNT_EXCEEDED)
 * - arc-05: overlapping physical ranges / Fifield bomb (OVERLAPPING_ENTRIES)
 * - arc-06: lying central directory / size mismatch (SIZE_MISMATCH / CORRUPT_ARCHIVE)
 * - arc-07: Zip Slip / traversal / Windows paths (ZIP_SLIP_DETECTED)
 * - arc-08: encrypted archive (ENCRYPTED_ARCHIVE_FORBIDDEN)
 * - arc-09: symlink archive (SYMLINK_FORBIDDEN)
 * - Multiple EOCD records (MULTIPLE_EOCD_DETECTED)
 * - Duplicate entry names (DUPLICATE_ENTRY_NAMES)
 * - Unsupported compression methods (UNSUPPORTED_COMPRESSION_METHOD)
 * - CRC integrity mismatch (CRC_MISMATCH)
 * - Valid stored and deflated archives (CLEAN)
 * - Valid OOXML container (CLEAN)
 * - Timeout and worker termination (TIMEOUT_EXCEEDED)
 * - Fail-closed error handling
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  inspectArchive,
  inspectArchiveStructure,
  validateEntryPath,
  DEFAULT_ARCHIVE_BUDGET,
  type ArchiveInspectionBudget,
} from '@sug/security-engine';
import {
  buildZip,
  buildHighRatioZipBombFixture,
  buildStreamingZipBombFixture,
  buildOverlappingZipFixture,
  buildCleanDocxFixture,
} from '../../fixtures/archive-builder.js';

describe('P16 — Archive Inspection and Zip-Bomb Security', () => {
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'sug-arc-test-'));
  });

  afterAll(async () => {
    await fs.promises.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  async function writeFixture(fileName: string, buffer: Buffer): Promise<string> {
    const filePath = path.join(tempDir, fileName);
    await fs.promises.writeFile(filePath, buffer);
    return filePath;
  }

  describe('Path Sanitation & Zip Slip Defense', () => {
    it('validates safe standard relative paths', () => {
      expect(validateEntryPath('file.txt').valid).toBe(true);
      expect(validateEntryPath('sub/dir/document.pdf').valid).toBe(true);
      expect(validateEntryPath('a/b/c/data.bin').valid).toBe(true);
    });

    it('rejects path traversal (../ and ..\\)', () => {
      expect(validateEntryPath('../evil.txt').valid).toBe(false);
      expect(validateEntryPath('sub/../../evil.txt').valid).toBe(false);
      expect(validateEntryPath('sub\\..\\evil.txt').valid).toBe(false);
    });

    it('rejects absolute paths', () => {
      expect(validateEntryPath('/etc/passwd').valid).toBe(false);
      expect(validateEntryPath('\\Windows\\System32').valid).toBe(false);
    });

    it('rejects Windows drive letters and UNC paths', () => {
      expect(validateEntryPath('C:/Windows/win.ini').valid).toBe(false);
      expect(validateEntryPath('D:\\test.txt').valid).toBe(false);
      expect(validateEntryPath('\\\\attacker\\share\\payload.exe').valid).toBe(false);
      expect(validateEntryPath('//attacker/share/payload.exe').valid).toBe(false);
    });

    it('rejects Windows reserved device names', () => {
      expect(validateEntryPath('CON').valid).toBe(false);
      expect(validateEntryPath('aux.txt').valid).toBe(false);
      expect(validateEntryPath('sub/NUL').valid).toBe(false);
      expect(validateEntryPath('com1/payload').valid).toBe(false);
    });

    it('rejects null bytes and control characters', () => {
      expect(validateEntryPath('file\0.txt').valid).toBe(false);
      expect(validateEntryPath('file\x1b.txt').valid).toBe(false);
    });
  });

  describe('Phase 1 Structural Inspection', () => {
    it('passes for valid stored (method 0) archive', async () => {
      const zipBuf = buildZip([{ name: 'hello.txt', content: 'Hello World', method: 0 }]);
      const filePath = await writeFixture('valid-stored.zip', zipBuf);

      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(true);
      expect(res.reasonCode).toBe('CLEAN');
      expect(res.entryCount).toBe(1);
    });

    it('passes for valid deflated (method 8) archive', async () => {
      const zipBuf = buildZip([
        { name: 'doc1.txt', content: 'Document 1 content', method: 8 },
        { name: 'doc2.txt', content: 'Document 2 content', method: 8 },
      ]);
      const filePath = await writeFixture('valid-deflated.zip', zipBuf);

      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(true);
      expect(res.reasonCode).toBe('CLEAN');
      expect(res.entryCount).toBe(2);
    });

    it('rejects truncated or malformed EOCD (< 22 bytes)', async () => {
      const filePath = await writeFixture('truncated.zip', Buffer.from('PK\x05\x06too-short'));
      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(false);
      expect(res.reasonCode).toBe('MALFORMED_EOCD');
    });

    it('rejects chameleon multiple EOCD records (MULTIPLE_EOCD_DETECTED)', async () => {
      const baseZip = buildZip([{ name: 'doc.txt', content: 'Test content', method: 0 }], {
        duplicateEocd: true,
      });
      const filePath = await writeFixture('multiple-eocd.zip', baseZip);

      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(false);
      expect(res.reasonCode).toBe('MULTIPLE_EOCD_DETECTED');
    });

    it('rejects duplicate entry names (DUPLICATE_ENTRY_NAMES)', async () => {
      const zipBuf = buildZip([
        { name: 'duplicate.txt', content: 'Version 1', method: 0 },
        { name: 'duplicate.txt', content: 'Version 2', method: 0 },
      ]);
      const filePath = await writeFixture('duplicate-names.zip', zipBuf);

      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(false);
      expect(res.reasonCode).toBe('DUPLICATE_ENTRY_NAMES');
    });

    it('arc-05: rejects overlapping physical entry ranges / Fifield non-recursive zip bomb (OVERLAPPING_ENTRIES)', async () => {
      const bombBuf = buildOverlappingZipFixture();
      const filePath = await writeFixture('fifield-overlap.zip', bombBuf);

      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(false);
      expect(res.reasonCode).toBe('OVERLAPPING_ENTRIES');
    });

    it('arc-07: rejects Zip Slip directory traversal in structural phase (ZIP_SLIP_DETECTED)', async () => {
      const zipBuf = buildZip([{ name: '../../etc/passwd', content: 'root:x:0:0:...', method: 0 }]);
      const filePath = await writeFixture('zip-slip.zip', zipBuf);

      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(false);
      expect(res.reasonCode).toBe('ZIP_SLIP_DETECTED');
    });

    it('arc-08: rejects encrypted archive entry (ENCRYPTED_ARCHIVE_FORBIDDEN)', async () => {
      const zipBuf = buildZip([
        { name: 'secret.txt', content: 'Secret data', method: 8, isEncrypted: true },
      ]);
      const filePath = await writeFixture('encrypted.zip', zipBuf);

      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(false);
      expect(res.reasonCode).toBe('ENCRYPTED_ARCHIVE_FORBIDDEN');
    });

    it('arc-09: rejects symlink archive entry (SYMLINK_FORBIDDEN)', async () => {
      const zipBuf = buildZip([
        { name: 'link_to_passwd', content: '/etc/passwd', method: 0, isSymlink: true },
      ]);
      const filePath = await writeFixture('symlink.zip', zipBuf);

      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(false);
      expect(res.reasonCode).toBe('SYMLINK_FORBIDDEN');
    });

    it('rejects unsupported compression methods (UNSUPPORTED_COMPRESSION_METHOD)', async () => {
      const zipBuf = buildZip([
        { name: 'bzip2_file.bin', content: 'some compressed data', method: 12 },
      ]);
      const filePath = await writeFixture('unsupported-method.zip', zipBuf);

      const res = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(res.valid).toBe(false);
      expect(res.reasonCode).toBe('UNSUPPORTED_COMPRESSION_METHOD');
    });

    it('arc-04: rejects archives exceeding maxEntries budget (ENTRY_COUNT_EXCEEDED)', async () => {
      const entries = Array.from({ length: 25 }, (_, i) => ({
        name: `entry_${i}.txt`,
        content: `Content ${i}`,
        method: 0,
      }));
      const zipBuf = buildZip(entries);
      const filePath = await writeFixture('many-entries.zip', zipBuf);

      // Low entry limit budget for testing
      const tightBudget: ArchiveInspectionBudget = {
        ...DEFAULT_ARCHIVE_BUDGET,
        maxEntries: 20,
      };

      const res = await inspectArchiveStructure(filePath, tightBudget);
      expect(res.valid).toBe(false);
      expect(res.reasonCode).toBe('ENTRY_COUNT_EXCEEDED');
    });
  });

  describe('Phase 2 Streaming Inspection & inspectArchive Public API', () => {
    it('arc-01: rejects archive under no-archive policy (archiveAllowed: false)', async () => {
      const zipBuf = buildZip([{ name: 'allowed.txt', content: 'Simple text', method: 0 }]);
      const filePath = await writeFixture('policy-forbidden.zip', zipBuf);

      const res = await inspectArchive({
        filePath,
        archiveAllowed: false,
      });

      expect(res.status).toBe('REJECTED');
      expect(res.reasonCode).toBe('ARCHIVE_FORBIDDEN');
      expect(res.severity).toBe('HIGH');
      expect(res.confidence).toBe('CONFIRMED');
    });

    it('inspects valid stored archive and returns CLEAN', async () => {
      const zipBuf = buildZip([{ name: 'hello.txt', content: 'Hello World', method: 0 }]);
      const filePath = await writeFixture('clean-stored.zip', zipBuf);

      const res = await inspectArchive({ filePath });
      expect(res.status).toBe('CLEAN');
      expect(res.reasonCode).toBe('CLEAN');
      expect(res.severity).toBe('INFO');
      expect(res.entryCount).toBe(1);
    });

    it('inspects valid deflated archive and returns CLEAN', async () => {
      const zipBuf = buildZip([
        { name: 'doc1.txt', content: 'Deflated document 1', method: 8 },
        { name: 'doc2.txt', content: 'Deflated document 2', method: 8 },
      ]);
      const filePath = await writeFixture('clean-deflated.zip', zipBuf);

      const res = await inspectArchive({ filePath });
      expect(res.status).toBe('CLEAN');
      expect(res.reasonCode).toBe('CLEAN');
      expect(res.entryCount).toBe(2);
    });

    it('inspects valid OOXML container and returns CLEAN without P17 macro checks', async () => {
      const docxBuf = buildCleanDocxFixture();
      const filePath = await writeFixture('sample.docx', docxBuf);

      const res = await inspectArchive({ filePath, isOoxml: true });
      expect(res.status).toBe('CLEAN');
      expect(res.reasonCode).toBe('CLEAN');
      expect(res.entryCount).toBe(3);
    });

    it('arc-03: rejects deeply nested ZIP archives exceeding maxDepth (NESTED_ARCHIVE_DEPTH_EXCEEDED)', async () => {
      // Build 5 levels of nesting: level5.zip inside level4.zip ... inside level1.zip
      let innerZip = buildZip([{ name: 'core.txt', content: 'deep payload', method: 0 }]);
      for (let level = 4; level >= 1; level--) {
        innerZip = buildZip([
          { name: `nested_level_${level + 1}.zip`, content: innerZip, method: 0 },
        ]);
      }

      const filePath = await writeFixture('nested-depth-5.zip', innerZip);

      const res = await inspectArchive({
        filePath,
        budget: {
          maxDepth: 3, // depth 5 must exceed budget of 3
        },
      });

      expect(res.status).toBe('REJECTED');
      expect(res.reasonCode).toBe('NESTED_ARCHIVE_DEPTH_EXCEEDED');
    });

    it('arc-06: rejects lying central directory size / stream mismatch (SIZE_MISMATCH / CORRUPT_ARCHIVE)', async () => {
      const realContent = Buffer.from('Real uncompressed text content that is relatively long');
      const zipBuf = buildZip([
        {
          name: 'lying.txt',
          content: realContent,
          method: 8,
          customUncompressedSize: 5, // central directory claims 5 bytes, actual is 55 bytes
        },
      ]);
      const filePath = await writeFixture('lying-size.zip', zipBuf);

      const res = await inspectArchive({ filePath });
      expect(res.status).toBe('REJECTED');
      expect(['SIZE_MISMATCH', 'CORRUPT_ARCHIVE']).toContain(res.reasonCode);
    });

    it('rejects CRC mismatch in compressed stream (CRC_MISMATCH)', async () => {
      const content = Buffer.from('Integrity test payload');
      const zipBuf = buildZip([
        {
          name: 'corrupt_crc.txt',
          content,
          method: 8,
          customCrc32: 0x12345678, // Corrupt CRC
        },
      ]);
      const filePath = await writeFixture('corrupt-crc.zip', zipBuf);

      const res = await inspectArchive({ filePath });
      expect(res.status).toBe('REJECTED');
      expect(['CRC_MISMATCH', 'CORRUPT_ARCHIVE']).toContain(res.reasonCode);
    });

    it('enforces execution timeout and terminates worker cleanly (TIMEOUT_EXCEEDED)', async () => {
      const zipBuf = buildZip([{ name: 'file.txt', content: 'Small file', method: 0 }]);
      const filePath = await writeFixture('timeout-test.zip', zipBuf);

      const res = await inspectArchive({
        filePath,
        budget: {
          maxExtractionMs: 1, // 1 ms budget triggers timeout
        },
      });

      expect(res.status).toBe('REJECTED');
      expect(res.reasonCode).toBe('TIMEOUT_EXCEEDED');
      expect(res.severity).toBe('HIGH');
    });

    it('arc-02A PERFORMANCE GATE: metadata-level high-ratio ZIP bomb completes in < 10s with peak RSS < 256 MB', async () => {
      const bombBuf = buildHighRatioZipBombFixture();
      const filePath = await writeFixture('high-ratio-bomb.zip', bombBuf);

      const start = Date.now();
      const res = await inspectArchive({
        filePath,
        budget: {
          maxRatio: 100, // 100:1 limit
          maxUncompressedSize: 104_857_600, // 100 MB limit
          maxExtractionMs: 10_000, // 10s budget
          maxMemoryBytes: 268_435_456, // 256 MB budget
        },
      });
      const elapsedMs = Date.now() - start;

      // Acceptance criteria:
      // 1. Must complete under 10,000 ms (10 seconds)
      expect(elapsedMs).toBeLessThan(10_000);

      // 2. Process peak RSS must be below 256 MB
      expect(res.workerRssBytes).toBeLessThan(268_435_456);

      // 3. Must be REJECTED, never CLEAN
      expect(res.status).toBe('REJECTED');
      expect([
        'COMPRESSION_RATIO_EXCEEDED',
        'UNCOMPRESSED_SIZE_EXCEEDED',
        'ARCHIVE_BOMB_DETECTED',
      ]).toContain(res.reasonCode);

      // 4. Must NOT have extracted 1 GB
      expect(res.totalDecompressedBytes).toBeLessThan(104_857_600);
    });

    it('arc-02B PERFORMANCE GATE: streaming decompression bomb triggers Phase 2 budget abort', async () => {
      const bombBuf = buildStreamingZipBombFixture();
      const filePath = await writeFixture('streaming-bomb.zip', bombBuf);

      // Verify that Phase 1 structural inspection considers this fixture valid
      const structural = await inspectArchiveStructure(filePath, DEFAULT_ARCHIVE_BUDGET);
      expect(structural.valid).toBe(true);
      expect(structural.totalDeclaredUncompressed).toBe(500_000); // 500 KB declared

      const start = Date.now();
      const res = await inspectArchive({
        filePath,
        budget: {
          maxRatio: 100, // 100:1 limit
          maxUncompressedSize: 104_857_600, // 100 MB limit
          maxExtractionMs: 10_000, // 10s budget
          maxMemoryBytes: 268_435_456, // 256 MB budget
        },
      });
      const elapsedMs = Date.now() - start;

      // Acceptance criteria:
      // 1. Must complete under 10,000 ms (10 seconds)
      expect(elapsedMs).toBeLessThan(10_000);

      // 2. Process peak RSS must be below 256 MB
      expect(res.workerRssBytes).toBeLessThan(268_435_456);

      // 3. Must be REJECTED, never CLEAN
      expect(res.status).toBe('REJECTED');
      expect([
        'COMPRESSION_RATIO_EXCEEDED',
        'UNCOMPRESSED_SIZE_EXCEEDED',
        'ARCHIVE_BOMB_DETECTED',
      ]).toContain(res.reasonCode);

      // 4. Must NOT have materialized the full 10 MB payload!
      expect(res.totalDecompressedBytes).toBeLessThan(10 * 1024 * 1024);
      // And must have begun decompression (decompressed > 0 bytes before abort)
      expect(res.totalDecompressedBytes).toBeGreaterThan(0);
    });

    it('nested archive sanity: cumulative uncompressed bytes budget propagates into nested archives without materializing directory trees', async () => {
      // Inner zip contains 1.6 MB uncompressed (stored, ratio 1:1)
      const innerZip = buildZip([
        { name: 'inner1.txt', content: Buffer.alloc(800 * 1024, 'A'), method: 0 },
        { name: 'inner2.txt', content: Buffer.alloc(800 * 1024, 'B'), method: 0 },
      ]);
      // Outer zip contains 1.0 MB uncompressed plus inner zip (stored, ratio 1:1)
      const outerZip = buildZip([
        { name: 'outer.txt', content: Buffer.alloc(1024 * 1024, 'C'), method: 0 },
        { name: 'nested.zip', content: innerZip, method: 0 },
      ]);
      const filePath = await writeFixture('nested-cumulative-budget.zip', outerZip);

      // Total uncompressed across nesting is ~2.6 MB. If budget is 2 MB:
      const res = await inspectArchive({
        filePath,
        budget: {
          maxUncompressedSize: 2 * 1024 * 1024, // 2 MB budget
          maxDepth: 3,
        },
      });

      expect(res.status).toBe('REJECTED');
      expect(res.reasonCode).toBe('UNCOMPRESSED_SIZE_EXCEEDED');
      expect(res.totalDecompressedBytes).toBeLessThan(3 * 1024 * 1024);
    });
  });
});
