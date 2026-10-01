/**
 * @sug/security-engine/archive/structural
 * Phase 1 Structural Inspection for ZIP and OOXML containers.
 *
 * Performs deterministic binary audits of ZIP structures WITHOUT decompressing:
 * - Single EOCD record verification
 * - Central Directory boundary and metadata parsing
 * - Local File Header cross-validation
 * - Overlapping physical entry range detection (Fifield non-recursive bomb defense)
 * - Duplicate entry name rejection
 * - Unsafe path / Zip Slip / Windows drive/UNC path rejection
 * - Symlink and encryption rejection
 * - Supported compression methods (0 and 8 only)
 * - Cumulative declared size and ratio limit enforcement
 */

import fs from 'node:fs';
import type {
  ArchiveInspectionBudget,
  ArchiveEntryInfo,
  StructuralInspectionResult,
} from './types.js';

const EOCD_SIGNATURE = 0x06054b50; // PK\x05\x06
const CD_HEADER_SIGNATURE = 0x02014b50; // PK\x01\x02
const LOCAL_HEADER_SIGNATURE = 0x04034b50; // PK\x03\x04

const WINDOWS_RESERVED_NAMES = new Set([
  'CON',
  'PRN',
  'AUX',
  'NUL',
  'COM1',
  'COM2',
  'COM3',
  'COM4',
  'COM5',
  'COM6',
  'COM7',
  'COM8',
  'COM9',
  'LPT1',
  'LPT2',
  'LPT3',
  'LPT4',
  'LPT5',
  'LPT6',
  'LPT7',
  'LPT8',
  'LPT9',
]);

interface PhysicalSpan {
  start: number;
  end: number;
  fileName: string;
}

/**
 * Validates the safety and sanitary properties of a relative ZIP entry path.
 */
export function validateEntryPath(fileName: string): { valid: boolean; reason?: string } {
  if (!fileName || fileName.length === 0) {
    return { valid: false, reason: 'Entry filename is empty' };
  }

  // Null byte or control characters (< ASCII 32)
  for (let i = 0; i < fileName.length; i++) {
    const code = fileName.charCodeAt(i);
    if (code === 0 || code < 32) {
      return {
        valid: false,
        reason: `Entry '${fileName}' contains null byte or control character (0x${code.toString(16)})`,
      };
    }
  }

  // Absolute paths (Unix or Windows)
  if (fileName.startsWith('/') || fileName.startsWith('\\')) {
    return {
      valid: false,
      reason: `Entry '${fileName}' has an illegal leading path separator`,
    };
  }

  // Windows drive letter (e.g. C:/ or C:\)
  if (/^[a-zA-Z]:[/\\]/.test(fileName)) {
    return {
      valid: false,
      reason: `Entry '${fileName}' contains a Windows drive specification`,
    };
  }

  // Windows UNC path (\\server\share or //server/share)
  if (fileName.startsWith('//') || fileName.startsWith('\\\\')) {
    return {
      valid: false,
      reason: `Entry '${fileName}' contains a Windows UNC path specification`,
    };
  }

  // Segment analysis for traversal and reserved device names
  const segments = fileName.split(/[/\\]/);
  for (const seg of segments) {
    if (seg === '..') {
      return {
        valid: false,
        reason: `Entry '${fileName}' contains directory traversal sequence ('..')`,
      };
    }

    const baseName = seg.split('.')[0]!.toUpperCase();
    if (WINDOWS_RESERVED_NAMES.has(baseName)) {
      return {
        valid: false,
        reason: `Entry '${fileName}' targets reserved Windows device name '${baseName}'`,
      };
    }
  }

  return { valid: true };
}

/**
 * Executes Phase 1 Structural Inspection on a ZIP container file.
 * Returns StructuralInspectionResult. Never decompresses archive payload.
 */
export async function performStructuralInspection(
  filePath: string,
  budget: ArchiveInspectionBudget,
): Promise<StructuralInspectionResult> {
  const stat = await fs.promises.stat(filePath);
  const fileSize = stat.size;

  if (fileSize < 22) {
    return {
      valid: false,
      reasonCode: 'MALFORMED_EOCD',
      reason: `File size (${fileSize} bytes) is smaller than minimum ZIP EOCD header (22 bytes)`,
      entryCount: 0,
      totalDeclaredCompressed: 0,
      totalDeclaredUncompressed: 0,
      entries: [],
      eocdOffset: -1,
      cdOffset: -1,
      cdSize: -1,
    };
  }

  if (fileSize > budget.maxCompressedSize) {
    return {
      valid: false,
      reasonCode: 'COMPRESSED_SIZE_EXCEEDED',
      reason: `Archive size (${fileSize} bytes) exceeds maximum compressed size budget of ${budget.maxCompressedSize} bytes`,
      entryCount: 0,
      totalDeclaredCompressed: fileSize,
      totalDeclaredUncompressed: 0,
      entries: [],
      eocdOffset: -1,
      cdOffset: -1,
      cdSize: -1,
    };
  }

  const fd = await fs.promises.open(filePath, 'r');

  try {
    // 1. Locate End of Central Directory (EOCD) Record
    // EOCD is at least 22 bytes, at most 22 + 65535 bytes from end of file
    const searchLength = Math.min(fileSize, 65535 + 22);
    const searchBuf = Buffer.alloc(searchLength);
    const searchStart = fileSize - searchLength;

    await fd.read(searchBuf, 0, searchLength, searchStart);

    let primaryEocdOffset = -1;
    let primaryCdOffset = -1;
    let primaryCdSize = -1;

    // 1. Locate primary EOCD record extending to end of file
    for (let i = searchLength - 22; i >= 0; i--) {
      if (searchBuf.readUInt32LE(i) === EOCD_SIGNATURE) {
        const commentLen = searchBuf.readUInt16LE(i + 20);
        const actualRemaining = searchLength - (i + 22);

        if (commentLen === actualRemaining) {
          primaryEocdOffset = searchStart + i;
          primaryCdSize = searchBuf.readUInt32LE(i + 12);
          primaryCdOffset = searchBuf.readUInt32LE(i + 16);
          break;
        }
      }
    }

    if (primaryEocdOffset === -1) {
      return {
        valid: false,
        reasonCode: 'MALFORMED_EOCD',
        reason: 'End of Central Directory (EOCD) signature not found or comment length corrupt',
        entryCount: 0,
        totalDeclaredCompressed: fileSize,
        totalDeclaredUncompressed: 0,
        entries: [],
        eocdOffset: -1,
        cdOffset: -1,
        cdSize: -1,
      };
    }

    // 2. Chameleon attack detection: verify no other EOCD signatures exist after CD
    for (let i = searchLength - 22; i >= 0; i--) {
      const candidateOffset = searchStart + i;
      if (candidateOffset !== primaryEocdOffset && candidateOffset >= primaryCdOffset) {
        if (searchBuf.readUInt32LE(i) === EOCD_SIGNATURE) {
          return {
            valid: false,
            reasonCode: 'MULTIPLE_EOCD_DETECTED',
            reason: `Detected ambiguous End of Central Directory record at offset ${candidateOffset} (chameleon attack prevention)`,
            entryCount: 0,
            totalDeclaredCompressed: fileSize,
            totalDeclaredUncompressed: 0,
            entries: [],
            eocdOffset: primaryEocdOffset,
            cdOffset: primaryCdOffset,
            cdSize: primaryCdSize,
          };
        }
      }
    }

    const eocdCandidateOffset = primaryEocdOffset;

    // Read full 22-byte EOCD record
    const eocdBuf = Buffer.alloc(22);
    await fd.read(eocdBuf, 0, 22, eocdCandidateOffset);

    const diskNumber = eocdBuf.readUInt16LE(4);
    const diskWithCentralDir = eocdBuf.readUInt16LE(6);
    const entriesOnDisk = eocdBuf.readUInt16LE(8);
    const totalEntries = eocdBuf.readUInt16LE(10);
    const cdSize = eocdBuf.readUInt32LE(12);
    const cdOffset = eocdBuf.readUInt32LE(16);

    // Reject multi-disk or split archives
    if (diskNumber !== 0 || diskWithCentralDir !== 0 || entriesOnDisk !== totalEntries) {
      return {
        valid: false,
        reasonCode: 'CORRUPT_ARCHIVE',
        reason: 'Multi-part or spanned ZIP archives are not supported',
        entryCount: totalEntries,
        totalDeclaredCompressed: fileSize,
        totalDeclaredUncompressed: 0,
        entries: [],
        eocdOffset: eocdCandidateOffset,
        cdOffset,
        cdSize,
      };
    }

    // Validate Central Directory boundaries
    if (cdOffset + cdSize > eocdCandidateOffset || cdOffset + cdSize > fileSize) {
      return {
        valid: false,
        reasonCode: 'CORRUPT_ARCHIVE',
        reason: `Central Directory range [${cdOffset}, ${cdOffset + cdSize}) extends past EOCD offset (${eocdCandidateOffset})`,
        entryCount: totalEntries,
        totalDeclaredCompressed: fileSize,
        totalDeclaredUncompressed: 0,
        entries: [],
        eocdOffset: eocdCandidateOffset,
        cdOffset,
        cdSize,
      };
    }

    // Check entry count ceiling
    if (totalEntries > budget.maxEntries) {
      return {
        valid: false,
        reasonCode: 'ENTRY_COUNT_EXCEEDED',
        reason: `Archive entry count (${totalEntries}) exceeds maximum entry limit (${budget.maxEntries})`,
        entryCount: totalEntries,
        totalDeclaredCompressed: fileSize,
        totalDeclaredUncompressed: 0,
        entries: [],
        eocdOffset: eocdCandidateOffset,
        cdOffset,
        cdSize,
      };
    }

    // 2. Parse Central Directory Entries
    const cdBuf = Buffer.alloc(cdSize);
    await fd.read(cdBuf, 0, cdSize, cdOffset);

    let offset = 0;
    const entries: ArchiveEntryInfo[] = [];
    const seenNames = new Set<string>();
    let totalDeclaredCompressed = 0;
    let totalDeclaredUncompressed = 0;
    const physicalSpans: PhysicalSpan[] = [];

    for (let entryIdx = 0; entryIdx < totalEntries; entryIdx++) {
      if (offset + 46 > cdSize) {
        return {
          valid: false,
          reasonCode: 'CORRUPT_ARCHIVE',
          reason: `Central directory truncated at entry index ${entryIdx}`,
          entryCount: entryIdx,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      const sig = cdBuf.readUInt32LE(offset);
      if (sig !== CD_HEADER_SIGNATURE) {
        return {
          valid: false,
          reasonCode: 'CORRUPT_ARCHIVE',
          reason: `Invalid Central Directory header signature 0x${sig.toString(16)} at offset ${cdOffset + offset}`,
          entryCount: entryIdx,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      const versionMadeBy = cdBuf.readUInt16LE(offset + 4);
      const hostOs = versionMadeBy >> 8;
      const flags = cdBuf.readUInt16LE(offset + 8);
      const compressionMethod = cdBuf.readUInt16LE(offset + 10);
      const crc32 = cdBuf.readUInt32LE(offset + 16);
      const compressedSize = cdBuf.readUInt32LE(offset + 20);
      const uncompressedSize = cdBuf.readUInt32LE(offset + 24);
      const fileNameLen = cdBuf.readUInt16LE(offset + 28);
      const extraLen = cdBuf.readUInt16LE(offset + 30);
      const commentLen = cdBuf.readUInt16LE(offset + 32);
      const externalAttr = cdBuf.readUInt32LE(offset + 38);
      const localHeaderOffset = cdBuf.readUInt32LE(offset + 42);

      if (offset + 46 + fileNameLen > cdSize) {
        return {
          valid: false,
          reasonCode: 'CORRUPT_ARCHIVE',
          reason: 'Entry filename extends past Central Directory boundary',
          entryCount: entryIdx,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      const fileName = cdBuf.toString('utf8', offset + 46, offset + 46 + fileNameLen);

      // Check encryption bit (Bit 0 or Bit 6)
      const isEncrypted = (flags & 0x0001) !== 0 || (flags & 0x0040) !== 0;
      if (isEncrypted) {
        return {
          valid: false,
          reasonCode: 'ENCRYPTED_ARCHIVE_FORBIDDEN',
          reason: `Entry '${fileName}' is encrypted; password-protected archives are strictly prohibited`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      // Check supported compression methods: 0 (Stored) or 8 (Deflate)
      if (compressionMethod !== 0 && compressionMethod !== 8) {
        return {
          valid: false,
          reasonCode: 'UNSUPPORTED_COMPRESSION_METHOD',
          reason: `Entry '${fileName}' uses unsupported compression method ${compressionMethod} (only Stored=0 and Deflate=8 supported)`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      // Check Unix Symlink attribute: S_IFLNK (0120000 octal = 0xA000)
      const isSymlink = hostOs === 3 && ((externalAttr >>> 16) & 0o120000) === 0o120000;
      if (isSymlink) {
        return {
          valid: false,
          reasonCode: 'SYMLINK_FORBIDDEN',
          reason: `Entry '${fileName}' is a symbolic link; symlinks are strictly prohibited in archives`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      // Path validation (Zip Slip / Traversal / Windows UNC / Reserved names)
      const pathValidation = validateEntryPath(fileName);
      if (!pathValidation.valid) {
        return {
          valid: false,
          reasonCode: 'ZIP_SLIP_DETECTED',
          reason: pathValidation.reason || 'Unsafe entry path detected in archive',
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      // Duplicate filename check (case-preserving normalized path)
      const normalizedPath = fileName.replace(/\\/g, '/');
      if (seenNames.has(normalizedPath)) {
        return {
          valid: false,
          reasonCode: 'DUPLICATE_ENTRY_NAMES',
          reason: `Duplicate archive entry name detected: '${fileName}'`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }
      seenNames.add(normalizedPath);

      // Check entry compression ratio ceiling
      if (compressedSize > 0) {
        const ratio = uncompressedSize / compressedSize;
        if (ratio > budget.maxRatio) {
          return {
            valid: false,
            reasonCode: 'ARCHIVE_BOMB_DETECTED',
            reason: `Entry '${fileName}' declared compression ratio ${ratio.toFixed(1)}:1 exceeds safety ceiling of ${budget.maxRatio}:1`,
            entryCount: entryIdx + 1,
            totalDeclaredCompressed,
            totalDeclaredUncompressed,
            entries,
            eocdOffset: eocdCandidateOffset,
            cdOffset,
            cdSize,
          };
        }
      } else if (compressedSize === 0 && uncompressedSize > 0) {
        return {
          valid: false,
          reasonCode: 'ARCHIVE_BOMB_DETECTED',
          reason: `Entry '${fileName}' declares 0 compressed bytes but ${uncompressedSize} uncompressed bytes`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      totalDeclaredCompressed += compressedSize;
      totalDeclaredUncompressed += uncompressedSize;

      if (totalDeclaredUncompressed > budget.maxUncompressedSize) {
        return {
          valid: false,
          reasonCode: 'UNCOMPRESSED_SIZE_EXCEEDED',
          reason: `Cumulative declared uncompressed size (${totalDeclaredUncompressed} bytes) exceeds budget of ${budget.maxUncompressedSize} bytes`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      // Cross-validate with Local File Header (LFH)
      if (localHeaderOffset + 30 > fileSize) {
        return {
          valid: false,
          reasonCode: 'CORRUPT_ARCHIVE',
          reason: `Entry '${fileName}' local header offset (${localHeaderOffset}) exceeds file boundary`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      const lfhBuf = Buffer.alloc(30);
      await fd.read(lfhBuf, 0, 30, localHeaderOffset);

      const lfhSig = lfhBuf.readUInt32LE(0);
      if (lfhSig !== LOCAL_HEADER_SIGNATURE) {
        return {
          valid: false,
          reasonCode: 'CORRUPT_ARCHIVE',
          reason: `Local File Header signature mismatch at offset ${localHeaderOffset} for entry '${fileName}'`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      const lfhMethod = lfhBuf.readUInt16LE(8);
      if (lfhMethod !== compressionMethod) {
        return {
          valid: false,
          reasonCode: 'CORRUPT_ARCHIVE',
          reason: `Compression method mismatch between Central Directory (${compressionMethod}) and Local Header (${lfhMethod}) for '${fileName}'`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      const lfhFlags = lfhBuf.readUInt16LE(6);
      if ((lfhFlags & 0x0001) !== 0) {
        return {
          valid: false,
          reasonCode: 'ENCRYPTED_ARCHIVE_FORBIDDEN',
          reason: `Local File Header specifies encryption bit for '${fileName}'`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      const lfhNameLen = lfhBuf.readUInt16LE(26);
      const lfhExtraLen = lfhBuf.readUInt16LE(28);

      const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
      const dataEnd = dataStart + compressedSize;

      if (dataEnd > fileSize) {
        return {
          valid: false,
          reasonCode: 'CORRUPT_ARCHIVE',
          reason: `Entry '${fileName}' compressed payload spans past end of file (dataEnd: ${dataEnd}, fileSize: ${fileSize})`,
          entryCount: entryIdx + 1,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }

      // Check if entry name indicates a nested archive
      const lowerName = fileName.toLowerCase();
      const isNestedArchive =
        lowerName.endsWith('.zip') ||
        lowerName.endsWith('.docx') ||
        lowerName.endsWith('.xlsx') ||
        lowerName.endsWith('.pptx') ||
        lowerName.endsWith('.jar') ||
        lowerName.endsWith('.tar') ||
        lowerName.endsWith('.gz');

      entries.push({
        fileName,
        compressedSize,
        uncompressedSize,
        compressionMethod,
        crc32,
        relativeOffset: localHeaderOffset,
        isEncrypted,
        isSymlink,
        isNestedArchive,
      });

      physicalSpans.push({
        start: localHeaderOffset,
        end: dataEnd,
        fileName,
      });

      offset += 46 + fileNameLen + extraLen + commentLen;
    }

    // 3. Overlapping Physical Entry Range Verification (Fifield Zip-Bomb Defense)
    physicalSpans.sort((a, b) => a.start - b.start);

    for (let i = 0; i < physicalSpans.length - 1; i++) {
      const current = physicalSpans[i]!;
      const next = physicalSpans[i + 1]!;

      if (next.start < current.end) {
        return {
          valid: false,
          reasonCode: 'OVERLAPPING_ENTRIES',
          reason: `Overlapping physical entry ranges detected between '${current.fileName}' [${current.start}, ${current.end}) and '${next.fileName}' [${next.start}, ${next.end})`,
          entryCount: entries.length,
          totalDeclaredCompressed,
          totalDeclaredUncompressed,
          entries,
          eocdOffset: eocdCandidateOffset,
          cdOffset,
          cdSize,
        };
      }
    }

    return {
      valid: true,
      reasonCode: 'CLEAN',
      reason: 'Phase 1 structural inspection passed all security checks',
      entryCount: entries.length,
      totalDeclaredCompressed,
      totalDeclaredUncompressed,
      entries,
      eocdOffset: eocdCandidateOffset,
      cdOffset,
      cdSize,
    };
  } finally {
    await fd.close();
  }
}

export { performStructuralInspection as inspectArchiveStructure };
