/**
 * @sug/security-engine/archive/streaming
 * Phase 2 Controlled Streaming Decompression for ZIP and OOXML containers.
 *
 * Implements lazy, bounded streaming via yauzl 3.4.0:
 * - Lazy entry consumption (reads entry-by-entry on demand)
 * - Strict per-entry and cumulative uncompressed size limits
 * - Real-time compression ratio enforcement (prevents streaming bombs)
 * - CRC-32 integrity validation (via yauzl internal validation)
 * - Recursive nested archive detection with depth budget enforcement
 * - Fail-closed abort on any budget exceedance or stream corruption
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import yauzl from 'yauzl';
import type {
  ArchiveInspectionBudget,
  ArchiveInspectionResult,
  StructuralInspectionResult,
} from './types.js';
import { inspectArchiveStructure } from './structural.js';

export interface StreamingInspectionInput {
  filePath: string;
  budget: ArchiveInspectionBudget;
  structuralResult: StructuralInspectionResult;
  currentDepth?: number | undefined;
  totalDecompressedPrior?: number | undefined;
  startTime?: number | undefined;
}

const PK_ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

function isArchiveEntry(fileName: string, firstBytes?: Buffer): boolean {
  const lower = fileName.toLowerCase();
  if (
    lower.endsWith('.zip') ||
    lower.endsWith('.docx') ||
    lower.endsWith('.xlsx') ||
    lower.endsWith('.pptx') ||
    lower.endsWith('.jar')
  ) {
    return true;
  }
  if (firstBytes && firstBytes.length >= 4 && firstBytes.subarray(0, 4).equals(PK_ZIP_MAGIC)) {
    return true;
  }
  return false;
}

/**
 * Executes Phase 2 controlled streaming inspection.
 * Decompresses entries in chunks, actively tracking memory and expansion ratios.
 */
export async function streamInspectArchive(
  input: StreamingInspectionInput,
): Promise<ArchiveInspectionResult> {
  const {
    filePath,
    budget,
    structuralResult,
    currentDepth = 1,
    totalDecompressedPrior = 0,
    startTime = Date.now(),
  } = input;

  const fileStats = await fs.promises.stat(filePath);
  const totalCompressedBytes = fileStats.size;

  // Immediate ceiling check on prior decompressed bytes
  if (totalDecompressedPrior > budget.maxUncompressedSize) {
    return {
      status: 'REJECTED',
      reasonCode: 'UNCOMPRESSED_SIZE_EXCEEDED',
      reason: `Cumulative decompressed bytes (${totalDecompressedPrior}) exceeds maximum budget of ${budget.maxUncompressedSize} bytes`,
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      entryCount: structuralResult.entryCount,
      totalCompressedBytes,
      totalDecompressedBytes: 0,
      compressionRatio: 0,
      maxNestingDepth: currentDepth,
      durationMs: Date.now() - startTime,
      workerRssBytes: process.memoryUsage().rss,
      entries: structuralResult.entries,
    };
  }

  return new Promise<ArchiveInspectionResult>((resolve) => {
    let settled = false;
    let totalDecompressedBytes = 0;
    let maxNestingDepth = currentDepth;
    let activeStream: fs.ReadStream | NodeJS.ReadableStream | null = null;
    let zipRef: yauzl.ZipFile | null = null;

    const safeResolve = (result: ArchiveInspectionResult) => {
      if (settled) return;
      settled = true;
      if (
        activeStream &&
        'destroy' in activeStream &&
        typeof (activeStream as { destroy?: unknown }).destroy === 'function'
      ) {
        try {
          (activeStream as { destroy: () => void }).destroy();
        } catch {
          // ignore
        }
      }
      if (zipRef) {
        try {
          zipRef.close();
        } catch {
          // ignore
        }
      }
      resolve(result);
    };

    yauzl.open(
      filePath,
      { lazyEntries: true, autoClose: true, validateEntrySizes: false },
      (openErr, zipfile) => {
        if (openErr || !zipfile) {
          const reasonMsg = openErr?.message || 'Failed to open ZIP file with yauzl';
          const reasonCode = reasonMsg.includes('CRC')
            ? 'CRC_MISMATCH'
            : reasonMsg.includes('size')
              ? 'SIZE_MISMATCH'
              : 'CORRUPT_ARCHIVE';
          return safeResolve({
            status: 'REJECTED',
            reasonCode,
            reason: reasonMsg,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            entryCount: structuralResult.entryCount,
            totalCompressedBytes,
            totalDecompressedBytes: 0,
            compressionRatio: 0,
            maxNestingDepth: currentDepth,
            durationMs: Date.now() - startTime,
            workerRssBytes: process.memoryUsage().rss,
            entries: structuralResult.entries,
          });
        }

        zipRef = zipfile;

        zipfile.on('error', (err) => {
          const reasonMsg = err.message || 'Stream error during archive reading';
          const reasonCode = reasonMsg.includes('CRC')
            ? 'CRC_MISMATCH'
            : reasonMsg.includes('size')
              ? 'SIZE_MISMATCH'
              : 'CORRUPT_ARCHIVE';
          safeResolve({
            status: 'REJECTED',
            reasonCode,
            reason: reasonMsg,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            entryCount: structuralResult.entryCount,
            totalCompressedBytes,
            totalDecompressedBytes,
            compressionRatio:
              totalCompressedBytes > 0
                ? Number((totalDecompressedBytes / totalCompressedBytes).toFixed(2))
                : 0,
            maxNestingDepth,
            durationMs: Date.now() - startTime,
            workerRssBytes: process.memoryUsage().rss,
            entries: structuralResult.entries,
          });
        });

        zipfile.on('end', () => {
          const ratio =
            totalCompressedBytes > 0
              ? Number((totalDecompressedBytes / totalCompressedBytes).toFixed(2))
              : 0;

          safeResolve({
            status: 'CLEAN',
            reasonCode: 'CLEAN',
            reason: 'Archive passed structural and streaming inspection',
            severity: 'INFO',
            confidence: 'CONFIRMED',
            entryCount: structuralResult.entryCount,
            totalCompressedBytes,
            totalDecompressedBytes,
            compressionRatio: ratio,
            maxNestingDepth,
            durationMs: Date.now() - startTime,
            workerRssBytes: process.memoryUsage().rss,
            entries: structuralResult.entries,
          });
        });

        zipfile.on('entry', async (entry: yauzl.Entry) => {
          // 1. Directory entries do not require stream decompression
          if (entry.fileName.endsWith('/')) {
            zipfile.readEntry();
            return;
          }

          // 2. Pre-decompression check on cumulative declared budget
          const remainingUncompressed =
            budget.maxUncompressedSize - (totalDecompressedPrior + totalDecompressedBytes);
          if (entry.uncompressedSize > remainingUncompressed) {
            safeResolve({
              status: 'REJECTED',
              reasonCode: 'UNCOMPRESSED_SIZE_EXCEEDED',
              reason: `Entry '${entry.fileName}' uncompressed size (${entry.uncompressedSize} bytes) exceeds remaining uncompressed budget (${remainingUncompressed} bytes)`,
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              entryCount: structuralResult.entryCount,
              totalCompressedBytes,
              totalDecompressedBytes,
              compressionRatio:
                totalCompressedBytes > 0
                  ? Number((totalDecompressedBytes / totalCompressedBytes).toFixed(2))
                  : 0,
              maxNestingDepth,
              durationMs: Date.now() - startTime,
              workerRssBytes: process.memoryUsage().rss,
              entries: structuralResult.entries,
            });
            return;
          }

          // 3. Pre-decompression check on declared ratio for significant sizes
          const effectiveCompSize = Math.max(1, entry.compressedSize);
          const declaredRatio = entry.uncompressedSize / effectiveCompSize;
          if (declaredRatio > budget.maxRatio && entry.uncompressedSize > 1024 * 1024) {
            safeResolve({
              status: 'REJECTED',
              reasonCode: 'COMPRESSION_RATIO_EXCEEDED',
              reason: `Entry '${entry.fileName}' declared compression ratio ${declaredRatio.toFixed(1)}:1 exceeds limit of ${budget.maxRatio}:1`,
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              entryCount: structuralResult.entryCount,
              totalCompressedBytes,
              totalDecompressedBytes,
              compressionRatio: declaredRatio,
              maxNestingDepth,
              durationMs: Date.now() - startTime,
              workerRssBytes: process.memoryUsage().rss,
              entries: structuralResult.entries,
            });
            return;
          }

          // 4. Nested archive detection by name
          const entryIsArchiveByName = isArchiveEntry(entry.fileName);
          if (entryIsArchiveByName && currentDepth + 1 > budget.maxDepth) {
            safeResolve({
              status: 'REJECTED',
              reasonCode: 'NESTED_ARCHIVE_DEPTH_EXCEEDED',
              reason: `Nested archive depth ${currentDepth + 1} exceeds maximum allowed depth ${budget.maxDepth} at entry '${entry.fileName}'`,
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              entryCount: structuralResult.entryCount,
              totalCompressedBytes,
              totalDecompressedBytes,
              compressionRatio:
                totalCompressedBytes > 0
                  ? Number((totalDecompressedBytes / totalCompressedBytes).toFixed(2))
                  : 0,
              maxNestingDepth: currentDepth + 1,
              durationMs: Date.now() - startTime,
              workerRssBytes: process.memoryUsage().rss,
              entries: structuralResult.entries,
            });
            return;
          }

          // 5. Open stream for controlled decompression
          zipfile.openReadStream(entry, async (streamErr, readStream) => {
            if (streamErr || !readStream) {
              const errMsg =
                streamErr?.message || `Failed to open read stream for '${entry.fileName}'`;
              const reasonCode = errMsg.includes('CRC')
                ? 'CRC_MISMATCH'
                : errMsg.includes('size')
                  ? 'SIZE_MISMATCH'
                  : 'CORRUPT_ARCHIVE';
              safeResolve({
                status: 'REJECTED',
                reasonCode,
                reason: errMsg,
                severity: 'HIGH',
                confidence: 'CONFIRMED',
                entryCount: structuralResult.entryCount,
                totalCompressedBytes,
                totalDecompressedBytes,
                compressionRatio:
                  totalCompressedBytes > 0
                    ? Number((totalDecompressedBytes / totalCompressedBytes).toFixed(2))
                    : 0,
                maxNestingDepth,
                durationMs: Date.now() - startTime,
                workerRssBytes: process.memoryUsage().rss,
                entries: structuralResult.entries,
              });
              return;
            }

            activeStream = readStream;

            let entryDecompressed = 0;
            let runningCrc = 0;
            let tempNestedFile: string | null = null;
            let tempWriteStream: fs.WriteStream | null = null;
            let headerChunk: Buffer | null = null;

            // If nested archive, prepare temporary file for recursive inspection
            if (entryIsArchiveByName) {
              tempNestedFile = path.join(
                os.tmpdir(),
                `sug-nested-${crypto.randomUUID()}-${path.basename(entry.fileName)}`,
              );
              tempWriteStream = fs.createWriteStream(tempNestedFile);
            }

            readStream.on('data', (chunk: Buffer) => {
              if (settled) return;

              entryDecompressed += chunk.length;
              runningCrc = zlib.crc32(chunk, runningCrc);

              if (!headerChunk && chunk.length >= 4) {
                headerChunk = chunk.subarray(0, 4);
                // Magic-byte nested archive detection
                if (!entryIsArchiveByName && headerChunk.equals(PK_ZIP_MAGIC)) {
                  if (currentDepth + 1 > budget.maxDepth) {
                    safeResolve({
                      status: 'REJECTED',
                      reasonCode: 'NESTED_ARCHIVE_DEPTH_EXCEEDED',
                      reason: `Nested archive depth ${currentDepth + 1} exceeds maximum allowed depth ${budget.maxDepth} at entry '${entry.fileName}'`,
                      severity: 'HIGH',
                      confidence: 'CONFIRMED',
                      entryCount: structuralResult.entryCount,
                      totalCompressedBytes,
                      totalDecompressedBytes,
                      compressionRatio:
                        totalCompressedBytes > 0
                          ? Number((totalDecompressedBytes / totalCompressedBytes).toFixed(2))
                          : 0,
                      maxNestingDepth: currentDepth + 1,
                      durationMs: Date.now() - startTime,
                      workerRssBytes: process.memoryUsage().rss,
                      entries: structuralResult.entries,
                    });
                    return;
                  }
                }
              }

              // Check cumulative uncompressed limit
              const cumulativeDecompressed =
                totalDecompressedPrior + totalDecompressedBytes + entryDecompressed;
              if (cumulativeDecompressed > budget.maxUncompressedSize) {
                safeResolve({
                  status: 'REJECTED',
                  reasonCode: 'UNCOMPRESSED_SIZE_EXCEEDED',
                  reason: `Total uncompressed bytes (${cumulativeDecompressed}) exceeded limit of ${budget.maxUncompressedSize} bytes during decompression of '${entry.fileName}'`,
                  severity: 'HIGH',
                  confidence: 'CONFIRMED',
                  entryCount: structuralResult.entryCount,
                  totalCompressedBytes,
                  totalDecompressedBytes: totalDecompressedBytes + entryDecompressed,
                  compressionRatio:
                    totalCompressedBytes > 0
                      ? Number(
                          (
                            (totalDecompressedBytes + entryDecompressed) /
                            totalCompressedBytes
                          ).toFixed(2),
                        )
                      : 0,
                  maxNestingDepth,
                  durationMs: Date.now() - startTime,
                  workerRssBytes: process.memoryUsage().rss,
                  entries: structuralResult.entries,
                });
                return;
              }

              // Check instantaneous compression ratio for streaming zip bombs
              const instantaneousRatio = entryDecompressed / effectiveCompSize;
              if (instantaneousRatio > budget.maxRatio && entryDecompressed > 1024 * 1024) {
                safeResolve({
                  status: 'REJECTED',
                  reasonCode: 'COMPRESSION_RATIO_EXCEEDED',
                  reason: `Decompression ratio ${instantaneousRatio.toFixed(1)}:1 exceeded maximum limit of ${budget.maxRatio}:1 for entry '${entry.fileName}'`,
                  severity: 'HIGH',
                  confidence: 'CONFIRMED',
                  entryCount: structuralResult.entryCount,
                  totalCompressedBytes,
                  totalDecompressedBytes: totalDecompressedBytes + entryDecompressed,
                  compressionRatio: instantaneousRatio,
                  maxNestingDepth,
                  durationMs: Date.now() - startTime,
                  workerRssBytes: process.memoryUsage().rss,
                  entries: structuralResult.entries,
                });
                return;
              }

              if (tempWriteStream) {
                tempWriteStream.write(chunk);
              }
            });

            readStream.on('error', (err) => {
              if (tempWriteStream) {
                tempWriteStream.destroy();
              }
              if (tempNestedFile) {
                fs.promises.unlink(tempNestedFile).catch(() => {});
              }
              const errMsg = err.message || `Error reading entry '${entry.fileName}'`;
              const reasonCode = errMsg.includes('CRC')
                ? 'CRC_MISMATCH'
                : errMsg.includes('size')
                  ? 'SIZE_MISMATCH'
                  : 'CORRUPT_ARCHIVE';
              safeResolve({
                status: 'REJECTED',
                reasonCode,
                reason: errMsg,
                severity: 'HIGH',
                confidence: 'CONFIRMED',
                entryCount: structuralResult.entryCount,
                totalCompressedBytes,
                totalDecompressedBytes,
                compressionRatio:
                  totalCompressedBytes > 0
                    ? Number((totalDecompressedBytes / totalCompressedBytes).toFixed(2))
                    : 0,
                maxNestingDepth,
                durationMs: Date.now() - startTime,
                workerRssBytes: process.memoryUsage().rss,
                entries: structuralResult.entries,
              });
            });

            readStream.on('end', async () => {
              activeStream = null;
              if (settled) {
                if (tempWriteStream) tempWriteStream.destroy();
                if (tempNestedFile) fs.promises.unlink(tempNestedFile).catch(() => {});
                return;
              }

              // Finish writing nested file if applicable
              if (tempWriteStream && tempNestedFile) {
                await new Promise<void>((cb) => tempWriteStream!.end(cb));

                try {
                  // Phase 1 structural inspection of nested archive
                  const nestedStructural = await inspectArchiveStructure(tempNestedFile, budget);
                  if (!nestedStructural.valid) {
                    safeResolve({
                      status: 'REJECTED',
                      reasonCode: nestedStructural.reasonCode,
                      reason: `Nested archive '${entry.fileName}' failed structural inspection: ${nestedStructural.reason}`,
                      severity: 'HIGH',
                      confidence: 'CONFIRMED',
                      entryCount: structuralResult.entryCount,
                      totalCompressedBytes,
                      totalDecompressedBytes: totalDecompressedBytes + entryDecompressed,
                      compressionRatio:
                        totalCompressedBytes > 0
                          ? Number(
                              (
                                (totalDecompressedBytes + entryDecompressed) /
                                totalCompressedBytes
                              ).toFixed(2),
                            )
                          : 0,
                      maxNestingDepth: currentDepth + 1,
                      durationMs: Date.now() - startTime,
                      workerRssBytes: process.memoryUsage().rss,
                      entries: structuralResult.entries,
                    });
                    return;
                  }

                  // Phase 2 streaming inspection of nested archive
                  const nestedStreaming = await streamInspectArchive({
                    filePath: tempNestedFile,
                    budget,
                    structuralResult: nestedStructural,
                    currentDepth: currentDepth + 1,
                    totalDecompressedPrior:
                      totalDecompressedPrior + totalDecompressedBytes + entryDecompressed,
                    startTime,
                  });

                  if (nestedStreaming.status !== 'CLEAN') {
                    safeResolve(nestedStreaming);
                    return;
                  }

                  maxNestingDepth = Math.max(maxNestingDepth, nestedStreaming.maxNestingDepth);
                  totalDecompressedBytes += nestedStreaming.totalDecompressedBytes;
                } finally {
                  await fs.promises.unlink(tempNestedFile).catch(() => {});
                }
              }

              // 6. Validate CRC-32 checksum integrity
              if (entry.crc32 !== 0 && runningCrc >>> 0 !== entry.crc32 >>> 0) {
                safeResolve({
                  status: 'REJECTED',
                  reasonCode: 'CRC_MISMATCH',
                  reason: `CRC-32 checksum mismatch for entry '${entry.fileName}': expected 0x${entry.crc32.toString(16)}, computed 0x${(runningCrc >>> 0).toString(16)}`,
                  severity: 'HIGH',
                  confidence: 'CONFIRMED',
                  entryCount: structuralResult.entryCount,
                  totalCompressedBytes,
                  totalDecompressedBytes: totalDecompressedBytes + entryDecompressed,
                  compressionRatio:
                    totalCompressedBytes > 0
                      ? Number(
                          (
                            (totalDecompressedBytes + entryDecompressed) /
                            totalCompressedBytes
                          ).toFixed(2),
                        )
                      : 0,
                  maxNestingDepth,
                  durationMs: Date.now() - startTime,
                  workerRssBytes: process.memoryUsage().rss,
                  entries: structuralResult.entries,
                });
                return;
              }

              // 7. Validate actual decompressed byte count matches declared uncompressed size
              if (entry.uncompressedSize > 0 && entryDecompressed !== entry.uncompressedSize) {
                safeResolve({
                  status: 'REJECTED',
                  reasonCode: 'SIZE_MISMATCH',
                  reason: `Entry '${entry.fileName}' actual decompressed bytes (${entryDecompressed}) does not match declared uncompressed size (${entry.uncompressedSize})`,
                  severity: 'HIGH',
                  confidence: 'CONFIRMED',
                  entryCount: structuralResult.entryCount,
                  totalCompressedBytes,
                  totalDecompressedBytes: totalDecompressedBytes + entryDecompressed,
                  compressionRatio:
                    totalCompressedBytes > 0
                      ? Number(
                          (
                            (totalDecompressedBytes + entryDecompressed) /
                            totalCompressedBytes
                          ).toFixed(2),
                        )
                      : 0,
                  maxNestingDepth,
                  durationMs: Date.now() - startTime,
                  workerRssBytes: process.memoryUsage().rss,
                  entries: structuralResult.entries,
                });
                return;
              }

              totalDecompressedBytes += entryDecompressed;
              // Read next entry
              zipfile.readEntry();
            });
          });
        });

        // Trigger first entry read
        zipfile.readEntry();
      },
    );
  });
}
