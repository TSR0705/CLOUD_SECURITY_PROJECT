/**
 * @sug/security-engine/format/pdf
 * PDF Active Content Inspection Engine.
 *
 * Implements scan-04:
 * - Attempts normalization via qpdf (--qdf --object-streams=disable) if available.
 * - In-process fallback: safe FlateDecode stream decompressor with strict memory budgets.
 * - Decodes PDF name hex encodings (e.g., /#4a#61#76#61#53#63#72#69#70#74 -> /JavaScript).
 * - Scans for active-content keywords:
 *     /JavaScript, /JS, /Launch, /EmbeddedFiles, /SubmitForm, /XFA, /OpenAction
 * - Returns deterministic ScanFindingRecord-compatible result.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import zlib from 'node:zlib';
import type { PdfCheckResult, PdfKeywordMatch } from './types.js';

const execFileAsync = promisify(execFile);

const ACTIVE_KEYWORDS = [
  '/JavaScript',
  '/JS',
  '/Launch',
  '/EmbeddedFiles',
  '/SubmitForm',
  '/XFA',
  '/OpenAction',
  '/RichMedia',
] as const;

// Primary blocking keywords that trigger ACTIVE_CONTENT_DETECTED
const CRITICAL_KEYWORDS = new Set([
  '/JavaScript',
  '/JS',
  '/Launch',
  '/EmbeddedFiles',
  '/SubmitForm',
  '/XFA',
]);

const MAX_STREAM_EXPANSION_BYTES = 10 * 1024 * 1024; // 10 MB per stream
const MAX_TOTAL_DECOMPRESSED_BYTES = 50 * 1024 * 1024; // 50 MB cumulative

/**
 * Normalizes hex-encoded PDF names (e.g. /#4a#61#76#61 -> /Java)
 */
function decodePdfHexNames(input: string): string {
  return input.replace(/#([0-9a-fA-F]{2})/g, (_, hex) => {
    try {
      return String.fromCharCode(parseInt(hex, 16));
    } catch {
      return hex;
    }
  });
}

/**
 * Extracts and safely inflates FlateDecode streams from raw PDF buffer.
 */
function extractAndDecompressStreams(buffer: Buffer): string[] {
  const decompressedStreams: string[] = [];
  let totalDecompressed = 0;

  const content = buffer.toString('binary');
  const streamRegex = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
  let match: RegExpExecArray | null;

  while ((match = streamRegex.exec(content)) !== null) {
    if (totalDecompressed >= MAX_TOTAL_DECOMPRESSED_BYTES) {
      break;
    }

    const streamRaw = Buffer.from(match[1]!, 'binary');
    if (streamRaw.length === 0) continue;

    // Attempt zlib inflate (standard FlateDecode)
    let inflated: Buffer | null = null;
    try {
      inflated = zlib.inflateSync(streamRaw, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
    } catch {
      try {
        // Fallback to raw inflate (without zlib header)
        inflated = zlib.inflateRawSync(streamRaw);
      } catch {
        // Stream may be uncompressed or using unsupported filter (e.g. DCTDecode, JBIG2)
        inflated = null;
      }
    }

    if (inflated) {
      const allowed = Math.min(inflated.length, MAX_STREAM_EXPANSION_BYTES);
      totalDecompressed += allowed;
      decompressedStreams.push(inflated.subarray(0, allowed).toString('utf-8'));
    }
  }

  return decompressedStreams;
}

export interface QpdfNormalizeResult {
  success: boolean;
  warnings?: boolean;
  malformed?: boolean;
  timedOut?: boolean;
  error?: string;
  exitCode?: number | null;
}

/**
 * Checks whether qpdf CLI is available on the system.
 */
async function isQpdfAvailable(options?: {
  qpdfPath?: string | undefined;
  qpdfArgs?: string[] | undefined;
}): Promise<boolean> {
  const binary = options?.qpdfPath ?? 'qpdf';
  const extraArgs = options?.qpdfArgs ?? [];
  try {
    await execFileAsync(binary, [...extraArgs, '--version'], { timeout: 2000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Normalizes a PDF file using qpdf if available.
 */
export async function normalizeWithQpdf(
  inputPath: string,
  outputPath: string,
  options: {
    qpdfPath?: string | undefined;
    qpdfArgs?: string[] | undefined;
    timeoutMs?: number | undefined;
  } = {},
): Promise<QpdfNormalizeResult> {
  const binary = options.qpdfPath ?? 'qpdf';
  const extraArgs = options.qpdfArgs ?? [];
  const timeout = options.timeoutMs ?? 10000;
  try {
    await execFileAsync(
      binary,
      [...extraArgs, '--qdf', '--object-streams=disable', inputPath, outputPath],
      {
        timeout,
      },
    );
    return { success: true };
  } catch (err: unknown) {
    const error = err as {
      code?: string | number;
      killed?: boolean;
      signal?: string;
      status?: number;
      stderr?: Buffer | string;
      message?: string;
    };
    const isTimeout =
      error.killed === true || error.signal === 'SIGTERM' || error.code === 'ETIMEDOUT';
    if (isTimeout) {
      return { success: false, timedOut: true, error: 'qpdf process timed out' };
    }
    const exitCode =
      typeof error.status === 'number'
        ? error.status
        : typeof error.code === 'number'
          ? error.code
          : null;
    if (exitCode === 3) {
      // Exit code 3 = warnings, but output file was produced
      if (fs.existsSync(outputPath)) {
        return { success: true, warnings: true };
      }
    }
    const stderrStr = error.stderr ? error.stderr.toString() : (error.message ?? '');
    const isMalformed = exitCode === 2 || /damaged|corrupt|invalid|unable to find/i.test(stderrStr);
    return {
      success: false,
      malformed: isMalformed,
      exitCode,
      error: stderrStr || error.message || 'qpdf execution failed',
    };
  }
}

/**
 * Scans a text buffer or string for PDF active content keywords.
 */
function scanTextForKeywords(text: string): {
  detected: string[];
  matches: PdfKeywordMatch[];
} {
  const decoded = decodePdfHexNames(text);
  const detected: string[] = [];
  const matches: PdfKeywordMatch[] = [];

  for (const kw of ACTIVE_KEYWORDS) {
    // Word boundary or delimiter match for PDF names
    // PDF names start with '/' and end at delimiter or whitespace
    const escapedKw = kw.replace('/', '\\/');
    const regex = new RegExp(`(?:^|[^a-zA-Z0-9])${escapedKw}(?=[\\s<>\\[\\]{}\\/()%]|\$)`, 'g');
    const occurrences = (decoded.match(regex) || []).length;

    if (occurrences > 0) {
      detected.push(kw);
      matches.push({
        keyword: kw,
        count: occurrences,
      });
    }
  }

  return { detected, matches };
}

export interface InspectPdfOptions {
  filePath?: string;
  buffer?: Buffer;
  qpdfPath?: string;
  qpdfArgs?: string[];
  timeoutMs?: number;
}

/**
 * Inspects a PDF file or buffer for active content.
 */
export async function inspectPdf(options: InspectPdfOptions): Promise<PdfCheckResult> {
  const startTime = Date.now();
  let buffer: Buffer;
  let filePath = options.filePath;

  let tempDirToClean: string | null = null;

  try {
    if (options.buffer) {
      buffer = options.buffer;
      if (!filePath) {
        tempDirToClean = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'sug-pdf-'));
        filePath = path.join(tempDirToClean, 'input.pdf');
        await fs.promises.writeFile(filePath, buffer);
      }
    } else if (filePath) {
      buffer = await fs.promises.readFile(filePath);
    } else {
      throw new Error('Either filePath or buffer must be provided');
    }

    // Quick sanity check: must start with PDF header or contain it in the first 1024 bytes
    const headerSlice = buffer.subarray(0, 1024).toString('binary');
    if (!headerSlice.includes('%PDF-')) {
      const durationMs = Date.now() - startTime;
      return {
        checkId: 'scanner.pdf',
        engine: 'qpdf-fallback',
        outcome: 'ERROR',
        reasonCode: 'PDF_MALFORMED',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        detectedKeywords: [],
        evidence: {
          error: 'Missing %PDF- header',
        },
        durationMs,
      };
    }

    const tailSlice = buffer.subarray(Math.max(0, buffer.length - 2048)).toString('binary');
    const hasEof = tailSlice.includes('%%EOF') || buffer.toString('binary').includes('%%EOF');

    let normalizedWithQpdf = false;
    let fullTextToScan = buffer.toString('binary');

    // Attempt normalization with qpdf if executable is available
    if (
      filePath &&
      (await isQpdfAvailable({ qpdfPath: options.qpdfPath, qpdfArgs: options.qpdfArgs }))
    ) {
      const qpdfTempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'sug-qpdf-'));
      const qpdfOutput = path.join(qpdfTempDir, 'normalized.pdf');
      try {
        const qpdfRes = await normalizeWithQpdf(filePath, qpdfOutput, {
          qpdfPath: options.qpdfPath,
          qpdfArgs: options.qpdfArgs,
          timeoutMs: options.timeoutMs,
        });

        if (qpdfRes.success && fs.existsSync(qpdfOutput)) {
          const normalizedBuf = await fs.promises.readFile(qpdfOutput);
          fullTextToScan += '\n' + normalizedBuf.toString('binary');
          normalizedWithQpdf = true;
        } else {
          // qpdf failed: fail closed! Errors NEVER become clean results!
          const durationMs = Date.now() - startTime;
          if (qpdfRes.timedOut) {
            return {
              checkId: 'scanner.pdf',
              engine: 'qpdf',
              outcome: 'ERROR',
              reasonCode: 'PDF_NORMALIZATION_FAILED',
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              detectedKeywords: [],
              evidence: {
                error: 'qpdf normalization timed out',
                timedOut: true,
              },
              durationMs,
            };
          }
          if (qpdfRes.malformed) {
            return {
              checkId: 'scanner.pdf',
              engine: 'qpdf',
              outcome: 'ERROR',
              reasonCode: 'PDF_MALFORMED',
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              detectedKeywords: [],
              evidence: {
                error: qpdfRes.error || 'qpdf rejected malformed PDF',
                exitCode: qpdfRes.exitCode,
              },
              durationMs,
            };
          }
          return {
            checkId: 'scanner.pdf',
            engine: 'qpdf',
            outcome: 'ERROR',
            reasonCode: 'PDF_NORMALIZATION_FAILED',
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            detectedKeywords: [],
            evidence: {
              error: qpdfRes.error || 'qpdf normalization failed',
              exitCode: qpdfRes.exitCode,
            },
            durationMs,
          };
        }
      } finally {
        await fs.promises.rm(qpdfTempDir, { recursive: true, force: true }).catch(() => {});
      }
    } else {
      // In-process fallback: enforce EOF validation
      if (!hasEof) {
        const durationMs = Date.now() - startTime;
        return {
          checkId: 'scanner.pdf',
          engine: 'pdf-scanner',
          outcome: 'ERROR',
          reasonCode: 'PDF_MALFORMED',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          detectedKeywords: [],
          evidence: {
            error: 'Missing %%EOF termination marker in PDF',
          },
          durationMs,
        };
      }
    }

    // Extract and decompress any embedded Flate streams (fallback & defense-in-depth)
    const decompressedStreams = extractAndDecompressStreams(buffer);
    for (const streamText of decompressedStreams) {
      fullTextToScan += '\n' + streamText;
    }

    // Scan the combined representation
    const { detected, matches } = scanTextForKeywords(fullTextToScan);
    const durationMs = Date.now() - startTime;

    const hasCriticalActiveContent = detected.some((kw) => CRITICAL_KEYWORDS.has(kw));

    if (hasCriticalActiveContent) {
      return {
        checkId: 'scanner.pdf',
        engine: normalizedWithQpdf ? 'qpdf' : 'pdf-scanner',
        engineVersion: normalizedWithQpdf ? 'normalized-qdf' : '1.0.0',
        outcome: 'FAIL',
        reasonCode: 'ACTIVE_CONTENT_DETECTED',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        detectedKeywords: detected,
        evidence: {
          status: 'ACTIVE_CONTENT_DETECTED',
          normalizedWithQpdf,
          detectedKeywords: detected,
          matches,
          decompressedStreamCount: decompressedStreams.length,
        },
        durationMs,
      };
    }

    return {
      checkId: 'scanner.pdf',
      engine: normalizedWithQpdf ? 'qpdf' : 'pdf-scanner',
      engineVersion: normalizedWithQpdf ? 'normalized-qdf' : '1.0.0',
      outcome: 'PASS',
      reasonCode: 'CLEAN',
      severity: 'INFO',
      confidence: 'CONFIRMED',
      detectedKeywords: [],
      evidence: {
        status: 'CLEAN',
        normalizedWithQpdf,
        decompressedStreamCount: decompressedStreams.length,
      },
      durationMs,
    };
  } catch (err) {
    const durationMs = Date.now() - startTime;
    return {
      checkId: 'scanner.pdf',
      engine: 'pdf-scanner',
      outcome: 'ERROR',
      reasonCode: 'PDF_NORMALIZATION_FAILED',
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      detectedKeywords: [],
      evidence: {
        error: (err as Error).message,
      },
      durationMs,
    };
  } finally {
    if (tempDirToClean) {
      await fs.promises.rm(tempDirToClean, { recursive: true, force: true }).catch(() => {});
    }
  }
}
