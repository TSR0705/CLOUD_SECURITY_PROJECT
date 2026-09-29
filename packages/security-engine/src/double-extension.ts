import { extractExtension } from './extension.js';
import type { DoubleExtensionValidationResult } from './types.js';

export const DANGEROUS_EXECUTABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  '.exe',
  '.bat',
  '.cmd',
  '.sh',
  '.vbs',
  '.js',
  '.py',
  '.php',
  '.phtml',
  '.scr',
  '.pif',
  '.dll',
  '.com',
  '.ps1',
  '.msi',
  '.jar',
  '.app',
  '.hta',
  '.cpl',
  '.vbe',
  '.jse',
  '.wsf',
  '.wsh',
  '.so',
  '.bin',
  '.elf',
]);

const RECOGNIZED_SAFE_COMPOUNDS: ReadonlySet<string> = new Set([
  '.tar.gz',
  '.tar.bz2',
  '.tar.xz',
  '.tar.zst',
]);

const BENIGN_MEDIA_DOC_EXTENSIONS: ReadonlySet<string> = new Set([
  '.pdf',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.ppt',
  '.pptx',
  '.txt',
  '.csv',
  '.jpg',
  '.jpeg',
  '.png',
  '.gif',
  '.webp',
  '.bmp',
  '.tiff',
  '.tif',
  '.svg',
  '.mp3',
  '.mp4',
  '.zip',
]);

/**
 * Validates filenames against double-extension attacks and executable disguised extensions.
 *
 * Distinguishes:
 * 1. Safe compound extensions (e.g. 'archive.tar.gz') -> SAFE_COMPOUND_EXTENSION (valid)
 * 2. Benign multi-dot filenames (e.g. 'backup.2026.09.29.pdf') -> SINGLE_EXTENSION (valid)
 * 3. Double-extension masquerades (e.g. 'invoice.pdf.exe', 'photo.jpg.exe') -> DOUBLE_EXTENSION_DETECTED (invalid)
 * 4. Hidden executable extensions (e.g. 'invoice.exe.pdf') -> HIDDEN_EXECUTABLE_EXTENSION (invalid)
 */
export function validateDoubleExtension(
  rawFilename?: string | null,
): DoubleExtensionValidationResult {
  const extraction = extractExtension(rawFilename);

  if (!extraction.hasExtension || extraction.allExtensions.length === 0) {
    return {
      valid: true,
      reasonCode: 'NO_EXTENSION',
      isDoubleExtension: false,
      isDangerous: false,
      reason: 'Filename does not contain an extension',
    };
  }

  // Check for safe compound extensions (e.g. .tar.gz)
  if (
    extraction.compoundExtension &&
    RECOGNIZED_SAFE_COMPOUNDS.has(extraction.compoundExtension.toLowerCase())
  ) {
    return {
      valid: true,
      reasonCode: 'SAFE_COMPOUND_EXTENSION',
      isDoubleExtension: false,
      isDangerous: false,
      detectedSuffix: extraction.compoundExtension,
      reason: `Filename contains recognized safe compound extension '${extraction.compoundExtension}'`,
    };
  }

  // Single extension (e.g. 'invoice.pdf')
  if (extraction.allExtensions.length <= 1) {
    const isDangerous = DANGEROUS_EXECUTABLE_EXTENSIONS.has(extraction.extension.toLowerCase());
    return {
      valid: !isDangerous,
      reasonCode: 'SINGLE_EXTENSION',
      isDoubleExtension: false,
      isDangerous,
      detectedSuffix: extraction.extension,
      reason: isDangerous
        ? `Filename has high-risk executable extension '${extraction.extension}'`
        : 'Filename contains a single standard extension',
    };
  }

  // Multiple extensions present (e.g. ['pdf', 'exe'] or ['exe', 'pdf'] or ['2026', 'pdf'])
  const exts = extraction.allExtensions.map((e) => e.toLowerCase());
  const finalExt = exts[exts.length - 1]!;
  const priorExts = exts.slice(0, exts.length - 1);

  // Case A: Trailing extension is a dangerous executable/script, and prior extension is a benign media/doc type
  // e.g., 'invoice.pdf.exe', 'photo.jpg.exe', 'report.docx.js', 'document.pdf.php'
  if (DANGEROUS_EXECUTABLE_EXTENSIONS.has(finalExt)) {
    const matchingPrior = priorExts.find((e) => BENIGN_MEDIA_DOC_EXTENSIONS.has(e));
    return {
      valid: false,
      reasonCode: 'DOUBLE_EXTENSION_DETECTED',
      isDoubleExtension: true,
      isDangerous: true,
      detectedSuffix: finalExt,
      innerExtension: matchingPrior ?? priorExts[priorExts.length - 1],
      reason: `Dangerous double extension detected: disguised as '${matchingPrior ?? priorExts[priorExts.length - 1]}' with executable suffix '${finalExt}'`,
    };
  }

  // Case B: Inner extension is a dangerous executable hidden before a benign trailing extension
  // e.g., 'invoice.exe.pdf', 'malware.sh.png'
  const dangerousInner = priorExts.find((e) => DANGEROUS_EXECUTABLE_EXTENSIONS.has(e));
  if (dangerousInner) {
    return {
      valid: false,
      reasonCode: 'HIDDEN_EXECUTABLE_EXTENSION',
      isDoubleExtension: true,
      isDangerous: true,
      detectedSuffix: finalExt,
      innerExtension: dangerousInner,
      reason: `Dangerous hidden executable extension '${dangerousInner}' disguised before '${finalExt}'`,
    };
  }

  // Case C: Multiple dots without any dangerous or media masquerade (e.g. 'data.v1.0.tar')
  return {
    valid: true,
    reasonCode: 'SINGLE_EXTENSION',
    isDoubleExtension: false,
    isDangerous: false,
    detectedSuffix: finalExt,
    reason: 'Multi-dot filename contains no disguised executable extensions',
  };
}
