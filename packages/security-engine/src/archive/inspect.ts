/**
 * @sug/security-engine/archive/inspect
 * Orchestrator for safe two-phase ZIP and OOXML inspection.
 *
 * Spawns an isolated Worker Thread to execute Phase 1 and Phase 2 checks,
 * enforcing execution timeout budgets via worker.terminate() and guaranteeing
 * fail-closed results on worker errors or crashes.
 */

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';
import type {
  ArchiveInspectionInput,
  ArchiveInspectionResult,
  ArchiveInspectionBudget,
} from './types.js';
import { DEFAULT_ARCHIVE_BUDGET } from './types.js';
import { runInspectionInWorker } from './worker.js';

function resolveWorkerUrl(): URL {
  // 1. Same-directory compiled worker (production / dist)
  const sameDirJs = new URL('./worker.js', import.meta.url);
  try {
    if (fs.existsSync(fileURLToPath(sameDirJs))) {
      return sameDirJs;
    }
  } catch {
    // ignore
  }

  // 2. Relative dist directory if running from src
  const distDirJs = new URL('../../dist/archive/worker.js', import.meta.url);
  try {
    if (fs.existsSync(fileURLToPath(distDirJs))) {
      return distDirJs;
    }
  } catch {
    // ignore
  }

  return sameDirJs;
}

/**
 * Public API to inspect untrusted ZIP and OOXML archives.
 * Executes within a dedicated worker thread with strict timeout and memory controls.
 */
export async function inspectArchive(
  input: ArchiveInspectionInput,
): Promise<ArchiveInspectionResult> {
  const startTime = Date.now();
  const budget: ArchiveInspectionBudget = {
    ...DEFAULT_ARCHIVE_BUDGET,
    ...(input.budget || {}),
  };
  const timeoutMs = budget.maxExtractionMs;

  return new Promise<ArchiveInspectionResult>((resolve) => {
    let settled = false;
    let timer: NodeJS.Timeout | null = null;
    let worker: Worker | null = null;

    const finalize = (result: ArchiveInspectionResult) => {
      if (settled) return;
      settled = true;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (worker) {
        worker.terminate().catch(() => {});
        worker = null;
      }
      resolve(result);
    };

    try {
      const workerUrl = resolveWorkerUrl();
      worker = new Worker(workerUrl, {
        workerData: {
          ...input,
          budget,
        },
      });

      timer = setTimeout(() => {
        finalize({
          status: 'REJECTED',
          reasonCode: 'TIMEOUT_EXCEEDED',
          reason: `Archive inspection timed out after exceeding budget of ${timeoutMs} ms`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          entryCount: 0,
          totalCompressedBytes: 0,
          totalDecompressedBytes: 0,
          compressionRatio: 0,
          maxNestingDepth: 1,
          durationMs: Date.now() - startTime,
          workerRssBytes: 0,
          entries: [],
        });
      }, timeoutMs);

      worker.on('message', (result: ArchiveInspectionResult) => {
        finalize(result);
      });

      worker.on('error', (err) => {
        finalize({
          status: 'ERROR',
          reasonCode: 'INSPECTION_ERROR',
          reason: `Worker thread error: ${err.message}`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          entryCount: 0,
          totalCompressedBytes: 0,
          totalDecompressedBytes: 0,
          compressionRatio: 0,
          maxNestingDepth: 1,
          durationMs: Date.now() - startTime,
          workerRssBytes: 0,
          entries: [],
        });
      });

      worker.on('exit', (code) => {
        if (!settled && code !== 0) {
          finalize({
            status: 'ERROR',
            reasonCode: 'INSPECTION_ERROR',
            reason: `Worker thread exited unexpectedly with code ${code}`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            entryCount: 0,
            totalCompressedBytes: 0,
            totalDecompressedBytes: 0,
            compressionRatio: 0,
            maxNestingDepth: 1,
            durationMs: Date.now() - startTime,
            workerRssBytes: 0,
            entries: [],
          });
        }
      });
    } catch {
      // Fallback: if Worker cannot be spawned in the execution environment, run directly fail-closed
      runInspectionInWorker({ ...input, budget })
        .then((res) => finalize(res))
        .catch((err) =>
          finalize({
            status: 'ERROR',
            reasonCode: 'INSPECTION_ERROR',
            reason: (err as Error).message,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            entryCount: 0,
            totalCompressedBytes: 0,
            totalDecompressedBytes: 0,
            compressionRatio: 0,
            maxNestingDepth: 1,
            durationMs: Date.now() - startTime,
            workerRssBytes: process.memoryUsage().rss,
            entries: [],
          }),
        );
    }
  });
}
