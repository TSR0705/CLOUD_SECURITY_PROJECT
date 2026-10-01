/**
 * @sug/security-engine/format/ooxml
 * OOXML Security Inspection Engine.
 *
 * Implements scan-05 (macro check) and scan-06 (external relationship check).
 *
 * Requirements:
 * - Uses yauzl lazy entry iteration (no disk extraction).
 * - Macro check detects VBA project streams (vbaProject.bin) and macro-enabled Content_Types.
 * - Relationship check inspects all .rels parts for TargetMode="External".
 * - STATIC ANALYSIS ONLY: Zero network or DNS requests are made.
 */

import yauzl from 'yauzl';
import type {
  ExternalRelationshipTarget,
  OoxmlMacroResult,
  OoxmlRelationshipResult,
} from './types.js';

const MACRO_ENTRY_PATTERNS = [
  /vbaProject\.bin$/i,
  /vbaData\.xml$/i,
  /word\/vbaProject\.bin$/i,
  /xl\/vbaProject\.bin$/i,
  /ppt\/vbaProject\.bin$/i,
];

const MACRO_CONTENT_TYPES = [
  'application/vnd.ms-office.vbaProject',
  'application/vnd.ms-word.document.macroEnabled.main+xml',
  'application/vnd.ms-excel.sheet.macroEnabled.main+xml',
  'application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml',
  'application/vnd.ms-word.template.macroEnabledTemplate.main+xml',
  'application/vnd.ms-excel.template.macroEnabled.main+xml',
  'application/vnd.ms-powerpoint.template.macroEnabled.main+xml',
  'application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml',
  'application/vnd.ms-powerpoint.slide.macroEnabled.main+xml',
];

const MAX_ENTRY_READ_BYTES = 2 * 1024 * 1024; // 2 MB max per XML part

/**
 * Safely reads a small entry stream into a string buffer with a hard byte limit.
 */
function readZipEntryToString(
  zipfile: yauzl.ZipFile,
  entry: yauzl.Entry,
  maxBytes: number = MAX_ENTRY_READ_BYTES,
): Promise<string> {
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (err, readStream) => {
      if (err) return reject(err);
      if (!readStream) return resolve('');

      const chunks: Buffer[] = [];
      let totalBytes = 0;

      readStream.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > maxBytes) {
          readStream.destroy();
          resolve(Buffer.concat(chunks).toString('utf-8'));
          return;
        }
        chunks.push(chunk);
      });

      readStream.on('end', () => {
        resolve(Buffer.concat(chunks).toString('utf-8'));
      });

      readStream.on('error', (streamErr) => {
        reject(streamErr);
      });
    });
  });
}

export interface InspectOoxmlOptions {
  filePath: string;
}

/**
 * Inspects an OOXML container for macros and external relationships.
 */
export async function inspectOoxml(
  options: InspectOoxmlOptions,
): Promise<{ macro: OoxmlMacroResult; relationships: OoxmlRelationshipResult }> {
  const startTime = Date.now();

  const detectedMacroEntries: string[] = [];
  const detectedMacroContentTypes: string[] = [];
  const externalTargets: ExternalRelationshipTarget[] = [];

  await new Promise<void>((resolve) => {
    yauzl.open(options.filePath, { lazyEntries: true, autoClose: true }, (err, zipfile) => {
      if (err) {
        // Not a valid ZIP file
        return resolve();
      }
      if (!zipfile) return resolve();

      const processNextEntry = () => {
        zipfile.readEntry();
      };

      zipfile.on('entry', async (entry: yauzl.Entry) => {
        const fileName = entry.fileName;

        // 1. Check macro entry name patterns
        for (const pattern of MACRO_ENTRY_PATTERNS) {
          if (pattern.test(fileName)) {
            detectedMacroEntries.push(fileName);
            break;
          }
        }

        // 2. Check [Content_Types].xml for macro content types
        if (fileName.toLowerCase() === '[content_types].xml') {
          try {
            const content = await readZipEntryToString(zipfile, entry);
            for (const ct of MACRO_CONTENT_TYPES) {
              if (content.includes(ct)) {
                detectedMacroContentTypes.push(ct);
              }
            }
          } catch {
            // Ignore entry read error, continue
          }
          processNextEntry();
          return;
        }

        // 3. Check relationship files (.rels) for external relationships
        if (fileName.toLowerCase().endsWith('.rels')) {
          try {
            const content = await readZipEntryToString(zipfile, entry);
            // Parse <Relationship ... TargetMode="External" ... />
            // Handles both TargetMode="External" and TargetMode='External'
            // and attributes in arbitrary order
            const relTagRegex = /<Relationship\b([^>]*)\/?>/gi;
            let relMatch: RegExpExecArray | null;

            while ((relMatch = relTagRegex.exec(content)) !== null) {
              const attrs = relMatch[1]!;
              if (/TargetMode\s*=\s*["']External["']/i.test(attrs)) {
                const targetMatch = /Target\s*=\s*["']([^"']+)["']/i.exec(attrs);
                const idMatch = /Id\s*=\s*["']([^"']+)["']/i.exec(attrs);
                const typeMatch = /Type\s*=\s*["']([^"']+)["']/i.exec(attrs);

                if (targetMatch && targetMatch[1]) {
                  externalTargets.push({
                    target: targetMatch[1],
                    id: idMatch?.[1],
                    type: typeMatch?.[1],
                    sourcePart: fileName,
                  });
                }
              }
            }
          } catch {
            // Ignore entry read error, continue
          }
          processNextEntry();
          return;
        }

        processNextEntry();
      });

      zipfile.on('end', () => {
        resolve();
      });

      zipfile.on('error', () => {
        // Non-fatal, resolve with whatever was collected
        resolve();
      });

      zipfile.readEntry();
    });
  });

  const durationMs = Date.now() - startTime;

  // Build Macro Result (scan-05)
  const hasMacros = detectedMacroEntries.length > 0 || detectedMacroContentTypes.length > 0;
  const macroResult: OoxmlMacroResult = hasMacros
    ? {
        checkId: 'scanner.ooxml.macro',
        engine: 'sug.ooxml.macro',
        engineVersion: '1.0.0',
        outcome: 'FAIL',
        reasonCode: 'OOXML_MACRO_DETECTED',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        macroEntries: detectedMacroEntries,
        contentTypes: detectedMacroContentTypes,
        evidence: {
          status: 'MACRO_DETECTED',
          macroEntries: detectedMacroEntries,
          macroContentTypes: detectedMacroContentTypes,
        },
        durationMs,
      }
    : {
        checkId: 'scanner.ooxml.macro',
        engine: 'sug.ooxml.macro',
        engineVersion: '1.0.0',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        macroEntries: [],
        contentTypes: [],
        evidence: {
          status: 'CLEAN',
        },
        durationMs,
      };

  // Build External Relationship Result (scan-06)
  const hasExternalRelationships = externalTargets.length > 0;
  const relationshipResult: OoxmlRelationshipResult = hasExternalRelationships
    ? {
        checkId: 'scanner.ooxml.relationship',
        engine: 'sug.ooxml.relationship',
        engineVersion: '1.0.0',
        outcome: 'FAIL',
        reasonCode: 'OOXML_EXTERNAL_RELATIONSHIP',
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        externalTargets,
        evidence: {
          status: 'EXTERNAL_RELATIONSHIPS_DETECTED',
          targetCount: externalTargets.length,
          externalTargets,
        },
        durationMs,
      }
    : {
        checkId: 'scanner.ooxml.relationship',
        engine: 'sug.ooxml.relationship',
        engineVersion: '1.0.0',
        outcome: 'PASS',
        reasonCode: 'CLEAN',
        severity: 'INFO',
        confidence: 'CONFIRMED',
        externalTargets: [],
        evidence: {
          status: 'CLEAN',
          targetCount: 0,
        },
        durationMs,
      };

  return {
    macro: macroResult,
    relationships: relationshipResult,
  };
}
