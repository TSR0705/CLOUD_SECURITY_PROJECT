/**
 * @sug/security-engine/archive/worker
 * Dedicated Worker Thread for CPU, memory, and timeout isolation during archive inspection.
 */

import { parentPort, workerData } from 'node:worker_threads';
import fs from 'node:fs';
import type {
  ArchiveInspectionInput,
  ArchiveInspectionResult,
  ArchiveInspectionBudget,
  SeverityLevel,
} from './types.js';
import { DEFAULT_ARCHIVE_BUDGET } from './types.js';
import { inspectArchiveStructure } from './structural.js';
import { streamInspectArchive } from './streaming.js';

function getSeverityForReason(reasonCode: string): SeverityLevel {
  switch (reasonCode) {
    case 'ARCHIVE_BOMB_DETECTED':
    case 'OVERLAPPING_ENTRIES':
    case 'ZIP_SLIP_DETECTED':
    case 'UNSAFE_PATH':
      return 'CRITICAL';
    case 'CLEAN':
      return 'INFO';
    default:
      return 'HIGH';
  }
}

export async function runInspectionInWorker(
  input: ArchiveInspectionInput,
): Promise<ArchiveInspectionResult> {
  const startTime = Date.now();
  const budget: ArchiveInspectionBudget = {
    ...DEFAULT_ARCHIVE_BUDGET,
    ...(input.budget || {}),
  };

  // 1. Policy check: archiveAllowed
  if (input.archiveAllowed === false) {
    let fileSize = 0;
    try {
      fileSize = fs.statSync(input.filePath).size;
    } catch {
      // ignore
    }
    return {
      status: 'REJECTED',
      reasonCode: 'ARCHIVE_FORBIDDEN',
      reason: 'Archive processing is forbidden by security policy (archiveAllowed: false)',
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      entryCount: 0,
      totalCompressedBytes: fileSize,
      totalDecompressedBytes: 0,
      compressionRatio: 0,
      maxNestingDepth: 1,
      durationMs: Date.now() - startTime,
      workerRssBytes: process.memoryUsage().rss,
      entries: [],
    };
  }

  // 2. Phase 1: Deterministic Structural Inspection
  const structural = await inspectArchiveStructure(input.filePath, budget);
  if (!structural.valid) {
    return {
      status: 'REJECTED',
      reasonCode: structural.reasonCode,
      reason: structural.reason,
      severity: getSeverityForReason(structural.reasonCode),
      confidence: 'CONFIRMED',
      entryCount: structural.entryCount,
      totalCompressedBytes: structural.totalDeclaredCompressed,
      totalDecompressedBytes: 0,
      compressionRatio: 0,
      maxNestingDepth: 1,
      durationMs: Date.now() - startTime,
      workerRssBytes: process.memoryUsage().rss,
      entries: structural.entries,
      details: {
        eocdOffset: structural.eocdOffset,
        cdOffset: structural.cdOffset,
        cdSize: structural.cdSize,
      },
    };
  }

  // 3. Phase 2: Controlled Streaming Inspection
  const streamingResult = await streamInspectArchive({
    filePath: input.filePath,
    budget,
    structuralResult: structural,
    currentDepth: input.currentDepth ?? 1,
    totalDecompressedPrior: input.totalDecompressedPrior ?? 0,
    startTime,
  });

  // 4. Memory budget verification
  const peakRss = process.memoryUsage().rss;
  if (peakRss > budget.maxMemoryBytes) {
    return {
      status: 'REJECTED',
      reasonCode: 'MEMORY_BUDGET_EXCEEDED',
      reason: `Worker RSS memory (${peakRss} bytes) exceeded safety budget of ${budget.maxMemoryBytes} bytes`,
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      entryCount: streamingResult.entryCount,
      totalCompressedBytes: streamingResult.totalCompressedBytes,
      totalDecompressedBytes: streamingResult.totalDecompressedBytes,
      compressionRatio: streamingResult.compressionRatio,
      maxNestingDepth: streamingResult.maxNestingDepth,
      durationMs: Date.now() - startTime,
      workerRssBytes: peakRss,
      entries: streamingResult.entries,
    };
  }

  return {
    ...streamingResult,
    workerRssBytes: peakRss,
  };
}

// If invoked as a Worker thread:
if (parentPort) {
  const inputData = workerData as ArchiveInspectionInput;
  runInspectionInWorker(inputData)
    .then((result) => {
      parentPort!.postMessage(result);
    })
    .catch((err) => {
      parentPort!.postMessage({
        status: 'ERROR',
        reasonCode: 'INSPECTION_ERROR',
        reason: (err as Error).message || 'Unexpected worker thread error',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        entryCount: 0,
        totalCompressedBytes: 0,
        totalDecompressedBytes: 0,
        compressionRatio: 0,
        maxNestingDepth: 1,
        durationMs: 0,
        workerRssBytes: process.memoryUsage().rss,
        entries: [],
      } satisfies ArchiveInspectionResult);
    });
}
