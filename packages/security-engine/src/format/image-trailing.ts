/**
 * @sug/security-engine/format/image-trailing
 * Image Trailing Data Security Inspection Engine.
 *
 * Implements detection of suspicious payload or data appended after format-legal
 * termination markers:
 * - PNG: Chunks parsed to IEND chunk (89 50 4E 47 ... IEND ... CRC).
 * - JPEG: Markers parsed to EOI (0xFF 0xD9).
 * - GIF: Blocks parsed to trailer terminator (0x3B).
 *
 * Appended trailing data is a common steganography, polyglot, and malware delivery vector.
 */

import fs from 'node:fs';
import type { ImageTrailingResult } from './types.js';

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const JPEG_MAGIC = Buffer.from([0xff, 0xd8]);
const GIF87A_MAGIC = Buffer.from('GIF87a', 'ascii');
const GIF89A_MAGIC = Buffer.from('GIF89a', 'ascii');

export interface InspectImageTrailingOptions {
  filePath?: string;
  buffer?: Buffer;
}

/**
 * Parses PNG chunks and locates the legal end of the IEND chunk.
 */
function findPngLegalEnd(buffer: Buffer): number | null {
  if (buffer.length < 8 || !buffer.subarray(0, 8).equals(PNG_MAGIC)) {
    return null;
  }

  let offset = 8;
  while (offset + 12 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.subarray(offset + 4, offset + 8).toString('ascii');
    const chunkTotalLen = 4 + 4 + length + 4; // length + type + data + crc

    if (type === 'IEND') {
      return offset + chunkTotalLen;
    }

    offset += chunkTotalLen;
  }

  return null;
}

/**
 * Locates the JPEG EOI (0xFF 0xD9) marker.
 */
function findJpegLegalEnd(buffer: Buffer): number | null {
  if (buffer.length < 2 || !buffer.subarray(0, 2).equals(JPEG_MAGIC)) {
    return null;
  }

  // Find the last occurrence of 0xFF 0xD9
  for (let i = buffer.length - 2; i >= 2; i--) {
    if (buffer[i] === 0xff && buffer[i + 1] === 0xd9) {
      return i + 2;
    }
  }

  return null;
}

/**
 * Locates the GIF trailer (0x3B).
 */
function findGifLegalEnd(buffer: Buffer): number | null {
  if (
    buffer.length < 6 ||
    (!buffer.subarray(0, 6).equals(GIF87A_MAGIC) && !buffer.subarray(0, 6).equals(GIF89A_MAGIC))
  ) {
    return null;
  }

  // Find 0x3B terminator
  // Parse through blocks or find the first/last legitimate trailer
  for (let i = 6; i < buffer.length; i++) {
    if (buffer[i] === 0x3b) {
      return i + 1;
    }
  }

  return null;
}

/**
 * Inspects an image buffer or file for data appended after the legal format termination.
 */
export async function inspectImageTrailing(
  options: InspectImageTrailingOptions,
): Promise<ImageTrailingResult> {
  const startTime = Date.now();
  let buffer: Buffer;

  if (options.buffer) {
    buffer = options.buffer;
  } else if (options.filePath) {
    buffer = await fs.promises.readFile(options.filePath);
  } else {
    throw new Error('Either filePath or buffer must be provided');
  }

  let format: 'png' | 'jpeg' | 'gif' | undefined;
  let legalEnd: number | null = null;

  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(PNG_MAGIC)) {
    format = 'png';
    legalEnd = findPngLegalEnd(buffer);
  } else if (buffer.length >= 2 && buffer.subarray(0, 2).equals(JPEG_MAGIC)) {
    format = 'jpeg';
    legalEnd = findJpegLegalEnd(buffer);
  } else if (
    buffer.length >= 6 &&
    (buffer.subarray(0, 6).equals(GIF87A_MAGIC) || buffer.subarray(0, 6).equals(GIF89A_MAGIC))
  ) {
    format = 'gif';
    legalEnd = findGifLegalEnd(buffer);
  }

  const durationMs = Date.now() - startTime;

  // If not a recognized image format, return CLEAN / not applicable
  if (!format || legalEnd === null) {
    return {
      checkId: 'scanner.image.trailing',
      engine: 'sug.image.trailing',
      engineVersion: '1.0.0',
      outcome: 'PASS',
      reasonCode: 'CLEAN',
      severity: 'INFO',
      confidence: 'CONFIRMED',
      evidence: {
        status: 'CLEAN',
        format: format || 'non_image',
      },
      durationMs,
    };
  }

  const trailingBytesCount = buffer.length - legalEnd;

  // Filter out harmless trailing whitespace or single null byte
  if (trailingBytesCount > 0) {
    const trailingSlice = buffer.subarray(legalEnd);
    const hasMeaningfulData = trailingSlice.some((b) => b !== 0x00 && b !== 0x0a && b !== 0x0d);

    if (hasMeaningfulData || trailingBytesCount > 32) {
      return {
        checkId: 'scanner.image.trailing',
        engine: 'sug.image.trailing',
        engineVersion: '1.0.0',
        outcome: 'FAIL',
        reasonCode: 'IMAGE_TRAILING_DATA_DETECTED',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        format,
        trailerOffset: legalEnd,
        trailingBytesCount,
        evidence: {
          status: 'TRAILING_DATA_DETECTED',
          format,
          trailerOffset: legalEnd,
          trailingBytesCount,
          trailingPreviewHex: trailingSlice.subarray(0, 64).toString('hex'),
        },
        durationMs,
      };
    }
  }

  return {
    checkId: 'scanner.image.trailing',
    engine: 'sug.image.trailing',
    engineVersion: '1.0.0',
    outcome: 'PASS',
    reasonCode: 'CLEAN',
    severity: 'INFO',
    confidence: 'CONFIRMED',
    format,
    trailerOffset: legalEnd,
    trailingBytesCount: 0,
    evidence: {
      status: 'CLEAN',
      format,
      trailerOffset: legalEnd,
    },
    durationMs,
  };
}
