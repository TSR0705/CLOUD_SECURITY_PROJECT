/**
 * @sug/security-engine/format/polyglot
 * Basic Polyglot Security Inspection Engine.
 *
 * Implements detection for contradictory dual-format containers:
 * - poly-01: GIF-ZIP polyglot (GIF header + valid ZIP EOCD/structures)
 * - poly-02: JPEG-ZIP polyglot (JPEG SOI + valid ZIP EOCD/structures)
 * - poly-03: PDF-ZIP polyglot (PDF header + valid ZIP EOCD/structures)
 * - poly-04: Documented known limitation / miss (advanced polyglots without standard EOCD)
 *
 * Polyglot files deceive file type filters by presenting different valid formats
 * depending on which parser (image parser vs archive unpacker) reads them.
 */

import fs from 'node:fs';
import type { PolyglotResult } from './types.js';

const GIF87A_MAGIC = Buffer.from('GIF87a', 'ascii');
const GIF89A_MAGIC = Buffer.from('GIF89a', 'ascii');
const JPEG_SOI = Buffer.from([0xff, 0xd8]);
const PDF_MAGIC = Buffer.from('%PDF-', 'ascii');

const ZIP_EOCD_MAGIC = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const ZIP_LOCAL_HEADER_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

export interface InspectPolyglotOptions {
  filePath?: string;
  buffer?: Buffer;
}

/**
 * Searches for ZIP End of Central Directory (EOCD) signature in buffer.
 */
function hasZipEocd(buffer: Buffer): boolean {
  if (buffer.length < 22) return false;
  // Search within last 65,557 bytes (maximum ZIP comment size + EOCD record)
  const searchLimit = Math.max(0, buffer.length - 65557);
  for (let i = buffer.length - 22; i >= searchLimit; i--) {
    if (buffer.subarray(i, i + 4).equals(ZIP_EOCD_MAGIC)) {
      return true;
    }
  }
  return false;
}

/**
 * Searches for ZIP Local File Header magic anywhere in buffer.
 */
function hasZipLocalHeader(buffer: Buffer): boolean {
  return buffer.includes(ZIP_LOCAL_HEADER_MAGIC);
}

/**
 * Inspects a file or buffer for basic polyglots.
 */
export async function inspectPolyglot(options: InspectPolyglotOptions): Promise<PolyglotResult> {
  const startTime = Date.now();
  let buffer: Buffer;

  if (options.buffer) {
    buffer = options.buffer;
  } else if (options.filePath) {
    buffer = await fs.promises.readFile(options.filePath);
  } else {
    throw new Error('Either filePath or buffer must be provided');
  }

  let primaryFormat: string | undefined;
  let secondaryFormat: string | undefined;

  const isGif =
    buffer.length >= 6 &&
    (buffer.subarray(0, 6).equals(GIF87A_MAGIC) || buffer.subarray(0, 6).equals(GIF89A_MAGIC));
  const isJpeg = buffer.length >= 2 && buffer.subarray(0, 2).equals(JPEG_SOI);
  const isPdf = buffer.length >= 5 && buffer.subarray(0, 5).equals(PDF_MAGIC);

  const containsZip = hasZipEocd(buffer) || hasZipLocalHeader(buffer);

  if (isGif && containsZip) {
    primaryFormat = 'GIF';
    secondaryFormat = 'ZIP';
  } else if (isJpeg && containsZip) {
    primaryFormat = 'JPEG';
    secondaryFormat = 'ZIP';
  } else if (isPdf && containsZip) {
    primaryFormat = 'PDF';
    secondaryFormat = 'ZIP';
  }

  const durationMs = Date.now() - startTime;

  if (primaryFormat && secondaryFormat) {
    return {
      checkId: 'scanner.polyglot',
      engine: 'sug.polyglot',
      engineVersion: '1.0.0',
      outcome: 'FAIL',
      reasonCode: 'POLYGLOT_DETECTED',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      primaryFormat,
      secondaryFormat,
      evidence: {
        status: 'POLYGLOT_DETECTED',
        primaryFormat,
        secondaryFormat,
        description: `Contradictory valid ${primaryFormat} and ${secondaryFormat} headers detected in single container`,
      },
      durationMs,
    };
  }

  return {
    checkId: 'scanner.polyglot',
    engine: 'sug.polyglot',
    engineVersion: '1.0.0',
    outcome: 'PASS',
    reasonCode: 'CLEAN',
    severity: 'INFO',
    confidence: 'CONFIRMED',
    evidence: {
      status: 'CLEAN',
    },
    durationMs,
  };
}
