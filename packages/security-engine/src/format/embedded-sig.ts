/**
 * @sug/security-engine/format/embedded-sig
 * Embedded Executable Signature Inspection Engine.
 *
 * Scans for executable binary headers at non-zero offsets (> 0):
 * - Windows PE/MZ: MZ header with valid e_lfanew pointing to 'PE\0\0'.
 * - Linux ELF: '\x7fELF' with valid EI_CLASS, EI_DATA, EI_VERSION.
 * - macOS Mach-O: 32/64-bit and Universal Fat headers.
 *
 * Detecting executable payloads concealed within documents or media files.
 */

import fs from 'node:fs';
import type { EmbeddedSignatureMatch, EmbeddedSignatureResult } from './types.js';

const PE_MAGIC = Buffer.from([0x50, 0x45, 0x00, 0x00]); // 'PE\0\0'

const MACHO_MAGICS = [
  Buffer.from([0xfe, 0xed, 0xfa, 0xce]), // 32-bit BE
  Buffer.from([0xce, 0xfa, 0xed, 0xfe]), // 32-bit LE
  Buffer.from([0xfe, 0xed, 0xfa, 0xcf]), // 64-bit BE
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), // 64-bit LE
  Buffer.from([0xca, 0xfe, 0xba, 0xbe]), // Mach-O Fat Universal
];

export interface InspectEmbeddedSigOptions {
  filePath?: string;
  buffer?: Buffer;
}

/**
 * Validates whether an MZ header at offset has a valid PE header.
 */
function isValidEmbeddedPe(buffer: Buffer, offset: number): boolean {
  if (offset + 0x40 > buffer.length) return false;
  // Read e_lfanew at offset + 0x3C
  const peOffset = buffer.readUInt32LE(offset + 0x3c);
  if (peOffset < 0x40 || peOffset > 1024 * 1024) return false;
  if (offset + peOffset + 4 > buffer.length) return false;

  return buffer.subarray(offset + peOffset, offset + peOffset + 4).equals(PE_MAGIC);
}

/**
 * Validates whether an ELF header at offset has standard e_ident values.
 */
function isValidEmbeddedElf(buffer: Buffer, offset: number): boolean {
  if (offset + 16 > buffer.length) return false;
  const eiClass = buffer[offset + 4]; // 1 = 32-bit, 2 = 64-bit
  const eiData = buffer[offset + 5]; // 1 = LE, 2 = BE
  const eiVersion = buffer[offset + 6]; // 1 = current

  return (eiClass === 1 || eiClass === 2) && (eiData === 1 || eiData === 2) && eiVersion === 1;
}

/**
 * Validates whether a Mach-O header at offset is plausible.
 */
function isValidEmbeddedMacho(buffer: Buffer, offset: number): boolean {
  if (offset + 16 > buffer.length) return false;
  const slice = buffer.subarray(offset, offset + 4);
  return MACHO_MAGICS.some((magic) => slice.equals(magic));
}

/**
 * Inspects a file or buffer for embedded executable signatures at offset > 0.
 */
export async function inspectEmbeddedSignatures(
  options: InspectEmbeddedSigOptions,
): Promise<EmbeddedSignatureResult> {
  const startTime = Date.now();
  let buffer: Buffer;

  if (options.buffer) {
    buffer = options.buffer;
  } else if (options.filePath) {
    buffer = await fs.promises.readFile(options.filePath);
  } else {
    throw new Error('Either filePath or buffer must be provided');
  }

  const matches: EmbeddedSignatureMatch[] = [];

  // Scan starting at offset 1 to avoid flagging legitimate executables at offset 0
  // Step through buffer looking for magic candidates
  const len = buffer.length;

  for (let offset = 1; offset < len - 4; offset++) {
    // Check PE / MZ
    if (buffer[offset] === 0x4d && buffer[offset + 1] === 0x5a) {
      if (isValidEmbeddedPe(buffer, offset)) {
        matches.push({
          signatureType: 'PE',
          offset,
          description: `Embedded Windows PE/MZ executable header at byte offset ${offset}`,
        });
        // Skip ahead to avoid duplicate hits within same binary
        offset += 64;
        continue;
      }
    }

    // Check Linux ELF
    if (
      buffer[offset] === 0x7f &&
      buffer[offset + 1] === 0x45 &&
      buffer[offset + 2] === 0x4c &&
      buffer[offset + 3] === 0x46
    ) {
      if (isValidEmbeddedElf(buffer, offset)) {
        matches.push({
          signatureType: 'ELF',
          offset,
          description: `Embedded Linux ELF executable header at byte offset ${offset}`,
        });
        offset += 64;
        continue;
      }
    }

    // Check Mach-O
    const slice4 = buffer.subarray(offset, offset + 4);
    if (MACHO_MAGICS.some((m) => slice4.equals(m))) {
      if (isValidEmbeddedMacho(buffer, offset)) {
        matches.push({
          signatureType: 'MACHO',
          offset,
          description: `Embedded macOS Mach-O executable header at byte offset ${offset}`,
        });
        offset += 64;
        continue;
      }
    }
  }

  const durationMs = Date.now() - startTime;

  if (matches.length > 0) {
    return {
      checkId: 'scanner.signature.embedded',
      engine: 'sug.signature.embedded',
      engineVersion: '1.0.0',
      outcome: 'FAIL',
      reasonCode: 'EMBEDDED_EXECUTABLE_DETECTED',
      severity: 'CRITICAL',
      confidence: 'CONFIRMED',
      matches,
      evidence: {
        status: 'EMBEDDED_EXECUTABLE_DETECTED',
        matchCount: matches.length,
        matches,
      },
      durationMs,
    };
  }

  return {
    checkId: 'scanner.signature.embedded',
    engine: 'sug.signature.embedded',
    engineVersion: '1.0.0',
    outcome: 'PASS',
    reasonCode: 'CLEAN',
    severity: 'INFO',
    confidence: 'CONFIRMED',
    matches: [],
    evidence: {
      status: 'CLEAN',
      matchCount: 0,
    },
    durationMs,
  };
}
