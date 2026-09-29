import { PolicyDocumentSchema, type PolicyDocument } from './schema.js';

/**
 * Immutable factory for the canonical 'images-only' policy preset.
 * Permits web images (JPEG, PNG, WebP, GIF) up to 10 MB, blocks executables and archives.
 */
export function createImagesOnlyPreset(): Readonly<PolicyDocument> {
  const doc = PolicyDocumentSchema.parse({
    schema: 'sug.policy/v1',
    name: 'images-only',
    description: 'Strict image upload policy for JPEG, PNG, WebP, and GIF files up to 10 MB',
    maxFileSize: 10 * 1024 * 1024, // 10 MB
    allowedExtensions: ['.jpg', '.jpeg', '.png', '.webp', '.gif'],
    allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp', 'image/gif'],
    blockedExtensions: [
      '.exe',
      '.sh',
      '.bat',
      '.cmd',
      '.js',
      '.vbs',
      '.ps1',
      '.zip',
      '.tar',
      '.gz',
    ],
    blockedMimeTypes: ['application/x-executable', 'application/x-msdownload', 'application/zip'],
    scanRequired: true,
    requiredChecks: [
      'filename.safe',
      'extension.allowed',
      'magic.detect',
      'type.consistency',
      'size.limit',
      'clamav.instream',
      'yara.rules',
      'polyglot.basic',
      'image.format',
    ],
    archiveAllowed: false,
    archive: {
      maxCompressedSize: 10 * 1024 * 1024,
      maxUncompressedSize: 10 * 1024 * 1024,
      maxEntries: 1,
      maxDepth: 1,
      maxRatio: 1,
      maxExtractionMs: 1000,
      maxMemoryBytes: 32 * 1024 * 1024,
    },
    pdf: {
      allowActiveContent: false,
      allowEncrypted: false,
      allowEmbeddedFiles: false,
    },
    office: {
      allowMacros: false,
    },
    image: {
      maxPixels: 25_000_000,
      reencode: false,
    },
    cdrRequired: false,
    onSuspicious: 'QUARANTINE',
    manualReviewThreshold: 50,
    scanTimeoutMs: 30000,
    retention: {
      quarantineDays: 7,
    },
    replicate: true,
  });
  return Object.freeze(doc);
}

/**
 * Immutable factory for the canonical 'documents' policy preset.
 * Permits standard documents (PDF, TXT, CSV, DOCX, XLSX) up to 25 MB.
 */
export function createDocumentsPreset(): Readonly<PolicyDocument> {
  const doc = PolicyDocumentSchema.parse({
    schema: 'sug.policy/v1',
    name: 'documents',
    description: 'Standard business documents (PDF, TXT, CSV, DOCX, XLSX) up to 25 MB',
    maxFileSize: 25 * 1024 * 1024, // 25 MB
    allowedExtensions: ['.pdf', '.txt', '.csv', '.docx', '.xlsx'],
    allowedMimeTypes: [
      'application/pdf',
      'text/plain',
      'text/csv',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ],
    blockedExtensions: [
      '.exe',
      '.sh',
      '.bat',
      '.cmd',
      '.js',
      '.vbs',
      '.ps1',
      '.zip',
      '.tar',
      '.gz',
    ],
    blockedMimeTypes: ['application/x-executable', 'application/x-msdownload', 'application/zip'],
    scanRequired: true,
    requiredChecks: [
      'filename.safe',
      'extension.allowed',
      'magic.detect',
      'type.consistency',
      'size.limit',
      'clamav.instream',
      'yara.rules',
      'polyglot.basic',
      'pdf.active_content',
      'pdf.encrypted',
      'pdf.embedded',
      'office.macros',
    ],
    archiveAllowed: false,
    archive: {
      maxCompressedSize: 25 * 1024 * 1024,
      maxUncompressedSize: 25 * 1024 * 1024,
      maxEntries: 1,
      maxDepth: 1,
      maxRatio: 1,
      maxExtractionMs: 1000,
      maxMemoryBytes: 32 * 1024 * 1024,
    },
    pdf: {
      allowActiveContent: false,
      allowEncrypted: false,
      allowEmbeddedFiles: false,
    },
    office: {
      allowMacros: false,
    },
    image: {
      maxPixels: 25_000_000,
      reencode: false,
    },
    cdrRequired: false,
    onSuspicious: 'QUARANTINE',
    manualReviewThreshold: 50,
    scanTimeoutMs: 30000,
    retention: {
      quarantineDays: 7,
    },
    replicate: true,
  });
  return Object.freeze(doc);
}

/**
 * Immutable factory for the canonical 'archives-strict' policy preset.
 * Permits ZIP, TAR, GZ up to 50 MB with strictly bounded recursion depth (2) and entry count (100).
 */
export function createArchivesStrictPreset(): Readonly<PolicyDocument> {
  const doc = PolicyDocumentSchema.parse({
    schema: 'sug.policy/v1',
    name: 'archives-strict',
    description: 'Strict compressed archives policy with bounded depth and file counts up to 50 MB',
    maxFileSize: 50 * 1024 * 1024, // 50 MB
    allowedExtensions: ['.zip', '.tar', '.gz'],
    allowedMimeTypes: ['application/zip', 'application/x-tar', 'application/gzip'],
    blockedExtensions: ['.exe', '.sh', '.bat', '.cmd', '.js', '.vbs', '.ps1'],
    blockedMimeTypes: ['application/x-executable', 'application/x-msdownload'],
    scanRequired: true,
    requiredChecks: [
      'filename.safe',
      'extension.allowed',
      'magic.detect',
      'type.consistency',
      'size.limit',
      'clamav.instream',
      'yara.rules',
      'polyglot.basic',
      'archive.bomb',
      'archive.traversal',
      'archive.integrity',
    ],
    archiveAllowed: true,
    archive: {
      maxCompressedSize: 50 * 1024 * 1024,
      maxUncompressedSize: 100 * 1024 * 1024,
      maxEntries: 100,
      maxDepth: 2,
      maxRatio: 20,
      maxExtractionMs: 10000,
      maxMemoryBytes: 256 * 1024 * 1024,
    },
    pdf: {
      allowActiveContent: false,
      allowEncrypted: false,
      allowEmbeddedFiles: false,
    },
    office: {
      allowMacros: false,
    },
    image: {
      maxPixels: 25_000_000,
      reencode: false,
    },
    cdrRequired: false,
    onSuspicious: 'QUARANTINE',
    manualReviewThreshold: 50,
    scanTimeoutMs: 30000,
    retention: {
      quarantineDays: 7,
    },
    replicate: true,
  });
  return Object.freeze(doc);
}

export const PRESET_IMAGES_ONLY = createImagesOnlyPreset();
export const PRESET_DOCUMENTS = createDocumentsPreset();
export const PRESET_ARCHIVES_STRICT = createArchivesStrictPreset();

export const CANONICAL_PRESETS = Object.freeze({
  'images-only': PRESET_IMAGES_ONLY,
  documents: PRESET_DOCUMENTS,
  'archives-strict': PRESET_ARCHIVES_STRICT,
});

export type CanonicalPresetName = keyof typeof CANONICAL_PRESETS;

/**
 * Resolves a canonical preset by name, or throws an error if unknown.
 */
export function getPresetByName(name: string): Readonly<PolicyDocument> {
  if (name in CANONICAL_PRESETS) {
    return CANONICAL_PRESETS[name as CanonicalPresetName];
  }
  throw new Error(
    `Unknown policy preset: '${name}'. Available presets: ${Object.keys(CANONICAL_PRESETS).join(', ')}`,
  );
}
