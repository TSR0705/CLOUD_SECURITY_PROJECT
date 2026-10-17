import { fileTypeFromBuffer } from 'file-type';
import { TextDecoder } from 'node:util';
import type { MagicDetectionResult } from './types.js';

/**
 * Maximum number of header bytes examined for magic-byte detection.
 * Strictly bounded to the first 4,100 bytes in compliance with the streaming architecture.
 */
export const MAX_MAGIC_BUFFER_BYTES = 4100;

/**
 * Checks if a byte buffer contains only valid printable ASCII / UTF-8 text
 * without binary control characters or null bytes.
 */
function isPrintableText(buf: Uint8Array): boolean {
  if (buf.length === 0) return false;
  let nonPrintableCount = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]!;
    // Allow tab (9), newline (10), carriage return (13)
    if (b === 9 || b === 10 || b === 13) continue;
    // Disallow null bytes and non-printable control characters
    if (b < 32 || b === 127) {
      return false;
    }
    // High bytes (UTF-8 multi-byte sequence)
    if (b > 127) {
      nonPrintableCount++;
    }
  }
  // If more than 30% are high bytes without matching known UTF-8 patterns, treat as binary
  return nonPrintableCount / buf.length < 0.3;
}

/**
 * Deterministically detects file type from a bounded buffer prefix.
 *
 * Invariants:
 * 1. Strictly bounded to at most MAX_MAGIC_BUFFER_BYTES (4,100 bytes).
 *    Never buffers or inspects beyond 4,100 bytes.
 * 2. Uses file-type v22 for standard binary formats (PDF, JPEG, PNG, ZIP, etc.).
 * 3. Supplements with bounded inspection for text formats (SVG, XML, JSON, CSV, TXT).
 * 4. Pure function with zero disk, network, or server dependencies.
 */
export async function detectMagic(buffer: Uint8Array | Buffer): Promise<MagicDetectionResult> {
  // Enforce 4,100 byte prefix boundary
  const prefix = buffer.subarray(0, MAX_MAGIC_BUFFER_BYTES);
  const bytesExamined = prefix.length;

  if (bytesExamined === 0) {
    return {
      detected: false,
      mime: undefined,
      extension: undefined,
      source: 'fallback',
      bytesExamined: 0,
    };
  }

  // 1. Primary detector: file-type v22 from bounded buffer prefix
  try {
    const ftResult = await fileTypeFromBuffer(prefix);
    if (ftResult) {
      return {
        detected: true,
        mime: ftResult.mime,
        extension: `.${ftResult.ext.toLowerCase()}`,
        source: 'file-type',
        bytesExamined,
      };
    }
  } catch {
    // If file-type fails or throws on truncated/malformed bytes, fall through to custom signatures
  }

  // 2. Custom bounded signature detection for text/markup formats not identified by file-type
  const textPrefix = new TextDecoder('utf-8', { fatal: false }).decode(prefix);
  const trimmed = textPrefix.trim();

  // SVG detection: <?xml ... ?> ... <svg or <svg xmlns=...
  if (/^(?:<\?xml[\s\S]*?\?>\s*)?<svg[\s>]/i.test(trimmed)) {
    return {
      detected: true,
      mime: 'image/svg+xml',
      extension: '.svg',
      source: 'custom-signature',
      bytesExamined,
    };
  }

  // XML detection: <?xml version=...
  if (/^<\?xml\s+version=/i.test(trimmed)) {
    return {
      detected: true,
      mime: 'application/xml',
      extension: '.xml',
      source: 'custom-signature',
      bytesExamined,
    };
  }

  // JSON detection: starts with { or [ and ends with } or ] (or looks like JSON object/array)
  if (
    (/^\{[\s\S]*\}$/.test(trimmed) || /^\[[\s\S]*\]$/.test(trimmed)) &&
    (trimmed.includes('":') || trimmed.length <= 10)
  ) {
    try {
      JSON.parse(trimmed);
      return {
        detected: true,
        mime: 'application/json',
        extension: '.json',
        source: 'custom-signature',
        bytesExamined,
      };
    } catch {
      // Partial JSON within prefix
      if (/^\{[\s\S]*"[\s\S]*":/.test(trimmed) || /^\[[\s\S]*[\d"truefalse{]/.test(trimmed)) {
        return {
          detected: true,
          mime: 'application/json',
          extension: '.json',
          source: 'custom-signature',
          bytesExamined,
        };
      }
    }
  }

  // CSV detection: check for comma-separated lines of text
  if (isPrintableText(prefix)) {
    const lines = trimmed.split(/\r?\n/).filter((l: string) => l.length > 0);
    if (lines.length >= 2) {
      const firstLineCommas = (lines[0]!.match(/,/g) || []).length;
      const secondLineCommas = (lines[1]!.match(/,/g) || []).length;
      if (firstLineCommas > 0 && firstLineCommas === secondLineCommas) {
        return {
          detected: true,
          mime: 'text/csv',
          extension: '.csv',
          source: 'custom-signature',
          bytesExamined,
        };
      }
    }

    // Plain text
    return {
      detected: true,
      mime: 'text/plain',
      extension: '.txt',
      source: 'custom-signature',
      bytesExamined,
    };
  }

  return {
    detected: false,
    mime: undefined,
    extension: undefined,
    source: 'fallback',
    bytesExamined,
  };
}
