import type { CanonicalFileType } from './types.js';

export interface CanonicalTypeDefinition {
  id: CanonicalFileType;
  description: string;
  primaryExtension: string;
  extensions: readonly string[];
  primaryMime: string;
  mimeTypes: readonly string[];
  magicExtensions: readonly string[];
  magicMimes: readonly string[];
  containerType?: CanonicalFileType | undefined;
  compatibleTypes?: readonly CanonicalFileType[] | undefined;
}

export const CANONICAL_TYPE_DEFINITIONS: Record<CanonicalFileType, CanonicalTypeDefinition> = {
  PDF: {
    id: 'PDF',
    description: 'Portable Document Format',
    primaryExtension: '.pdf',
    extensions: ['.pdf'],
    primaryMime: 'application/pdf',
    mimeTypes: ['application/pdf'],
    magicExtensions: ['pdf'],
    magicMimes: ['application/pdf'],
  },
  JPEG: {
    id: 'JPEG',
    description: 'JPEG Image',
    primaryExtension: '.jpg',
    extensions: ['.jpg', '.jpeg'],
    primaryMime: 'image/jpeg',
    mimeTypes: ['image/jpeg', 'image/pjpeg'],
    magicExtensions: ['jpg', 'jpeg'],
    magicMimes: ['image/jpeg'],
  },
  PNG: {
    id: 'PNG',
    description: 'Portable Network Graphics',
    primaryExtension: '.png',
    extensions: ['.png'],
    primaryMime: 'image/png',
    mimeTypes: ['image/png'],
    magicExtensions: ['png'],
    magicMimes: ['image/png'],
  },
  GIF: {
    id: 'GIF',
    description: 'Graphics Interchange Format',
    primaryExtension: '.gif',
    extensions: ['.gif'],
    primaryMime: 'image/gif',
    mimeTypes: ['image/gif'],
    magicExtensions: ['gif'],
    magicMimes: ['image/gif'],
  },
  WEBP: {
    id: 'WEBP',
    description: 'WebP Image',
    primaryExtension: '.webp',
    extensions: ['.webp'],
    primaryMime: 'image/webp',
    mimeTypes: ['image/webp'],
    magicExtensions: ['webp'],
    magicMimes: ['image/webp'],
  },
  TIFF: {
    id: 'TIFF',
    description: 'Tagged Image File Format',
    primaryExtension: '.tiff',
    extensions: ['.tif', '.tiff'],
    primaryMime: 'image/tiff',
    mimeTypes: ['image/tiff'],
    magicExtensions: ['tif', 'tiff'],
    magicMimes: ['image/tiff'],
  },
  DOCX: {
    id: 'DOCX',
    description: 'Microsoft Word (OpenXML)',
    primaryExtension: '.docx',
    extensions: ['.docx'],
    primaryMime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    mimeTypes: [
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/docx',
    ],
    magicExtensions: ['docx', 'zip'],
    magicMimes: [
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/zip',
    ],
    containerType: 'ZIP',
    compatibleTypes: ['ZIP'],
  },
  XLSX: {
    id: 'XLSX',
    description: 'Microsoft Excel (OpenXML)',
    primaryExtension: '.xlsx',
    extensions: ['.xlsx'],
    primaryMime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    mimeTypes: [
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/xlsx',
    ],
    magicExtensions: ['xlsx', 'zip'],
    magicMimes: [
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/zip',
    ],
    containerType: 'ZIP',
    compatibleTypes: ['ZIP'],
  },
  PPTX: {
    id: 'PPTX',
    description: 'Microsoft PowerPoint (OpenXML)',
    primaryExtension: '.pptx',
    extensions: ['.pptx'],
    primaryMime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    mimeTypes: [
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'application/pptx',
    ],
    magicExtensions: ['pptx', 'zip'],
    magicMimes: [
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'application/zip',
    ],
    containerType: 'ZIP',
    compatibleTypes: ['ZIP'],
  },
  ZIP: {
    id: 'ZIP',
    description: 'ZIP Archive',
    primaryExtension: '.zip',
    extensions: ['.zip'],
    primaryMime: 'application/zip',
    mimeTypes: ['application/zip', 'application/x-zip-compressed'],
    magicExtensions: ['zip'],
    magicMimes: ['application/zip', 'application/x-zip-compressed'],
    compatibleTypes: ['DOCX', 'XLSX', 'PPTX'],
  },
  TAR: {
    id: 'TAR',
    description: 'Tape Archive',
    primaryExtension: '.tar',
    extensions: ['.tar'],
    primaryMime: 'application/x-tar',
    mimeTypes: ['application/x-tar', 'application/tar'],
    magicExtensions: ['tar'],
    magicMimes: ['application/x-tar', 'application/tar'],
  },
  GZIP: {
    id: 'GZIP',
    description: 'Gzip Compressed Archive',
    primaryExtension: '.gz',
    extensions: ['.gz', '.tgz', '.tar.gz'],
    primaryMime: 'application/gzip',
    mimeTypes: ['application/gzip', 'application/x-gzip'],
    magicExtensions: ['gz', 'gzip'],
    magicMimes: ['application/gzip', 'application/x-gzip'],
  },
  TEXT: {
    id: 'TEXT',
    description: 'Plain Text',
    primaryExtension: '.txt',
    extensions: ['.txt', '.text', '.log'],
    primaryMime: 'text/plain',
    mimeTypes: ['text/plain'],
    magicExtensions: ['txt', 'text'],
    magicMimes: ['text/plain'],
    compatibleTypes: ['CSV', 'JSON', 'XML'],
  },
  CSV: {
    id: 'CSV',
    description: 'Comma-Separated Values',
    primaryExtension: '.csv',
    extensions: ['.csv'],
    primaryMime: 'text/csv',
    mimeTypes: ['text/csv', 'text/plain', 'application/csv'],
    magicExtensions: ['csv', 'txt'],
    magicMimes: ['text/csv', 'text/plain'],
    compatibleTypes: ['TEXT'],
  },
  JSON: {
    id: 'JSON',
    description: 'JavaScript Object Notation',
    primaryExtension: '.json',
    extensions: ['.json'],
    primaryMime: 'application/json',
    mimeTypes: ['application/json', 'text/json'],
    magicExtensions: ['json', 'txt'],
    magicMimes: ['application/json', 'text/json', 'text/plain'],
    compatibleTypes: ['TEXT'],
  },
  XML: {
    id: 'XML',
    description: 'Extensible Markup Language',
    primaryExtension: '.xml',
    extensions: ['.xml'],
    primaryMime: 'application/xml',
    mimeTypes: ['application/xml', 'text/xml'],
    magicExtensions: ['xml'],
    magicMimes: ['application/xml', 'text/xml', 'text/plain'],
    compatibleTypes: ['TEXT', 'SVG'],
  },
  SVG: {
    id: 'SVG',
    description: 'Scalable Vector Graphics',
    primaryExtension: '.svg',
    extensions: ['.svg'],
    primaryMime: 'image/svg+xml',
    mimeTypes: ['image/svg+xml'],
    magicExtensions: ['svg', 'xml'],
    magicMimes: ['image/svg+xml', 'application/xml'],
    compatibleTypes: ['XML', 'TEXT'],
  },
  EXECUTABLE: {
    id: 'EXECUTABLE',
    description: 'Executable or Script Binary',
    primaryExtension: '.exe',
    extensions: [
      '.exe',
      '.dll',
      '.bat',
      '.cmd',
      '.sh',
      '.bin',
      '.elf',
      '.msi',
      '.com',
      '.scr',
      '.ps1',
      '.vbs',
      '.js',
    ],
    primaryMime: 'application/x-executable',
    mimeTypes: [
      'application/x-executable',
      'application/x-msdownload',
      'application/x-dosexec',
      'application/x-sharedlib',
      'application/x-shellscript',
      'application/octet-stream',
    ],
    magicExtensions: ['exe', 'dll', 'elf', 'class', 'msi'],
    magicMimes: [
      'application/x-msdownload',
      'application/x-executable',
      'application/x-dosexec',
      'application/x-elf',
    ],
  },
  OCTET_STREAM: {
    id: 'OCTET_STREAM',
    description: 'Generic Binary Stream / Unknown',
    primaryExtension: '.bin',
    extensions: ['.bin', '.dat', '.octet'],
    primaryMime: 'application/octet-stream',
    mimeTypes: ['application/octet-stream', 'application/x-unknown'],
    magicExtensions: ['bin'],
    magicMimes: ['application/octet-stream'],
  },
};

// Fast index lookup tables built once deterministically
const EXTENSION_TO_TYPE = new Map<string, CanonicalFileType>();
const MIME_TO_TYPE = new Map<string, CanonicalFileType>();
const MAGIC_EXT_TO_TYPE = new Map<string, CanonicalFileType>();
const MAGIC_MIME_TO_TYPE = new Map<string, CanonicalFileType>();

// 1. First pass: Register primary mappings for all canonical definitions
for (const def of Object.values(CANONICAL_TYPE_DEFINITIONS)) {
  EXTENSION_TO_TYPE.set(def.primaryExtension.toLowerCase(), def.id);
  MIME_TO_TYPE.set(def.primaryMime.toLowerCase(), def.id);
  if (def.magicExtensions.length > 0) {
    MAGIC_EXT_TO_TYPE.set(def.magicExtensions[0]!.toLowerCase(), def.id);
  }
  if (def.magicMimes.length > 0) {
    MAGIC_MIME_TO_TYPE.set(def.magicMimes[0]!.toLowerCase(), def.id);
  }
}

// 2. Second pass: Register alternative extensions, MIMEs, and magic signatures without overwriting primary entries
for (const def of Object.values(CANONICAL_TYPE_DEFINITIONS)) {
  for (const ext of def.extensions) {
    const k = ext.toLowerCase();
    if (!EXTENSION_TO_TYPE.has(k)) {
      EXTENSION_TO_TYPE.set(k, def.id);
    }
  }
  for (const mime of def.mimeTypes) {
    const k = mime.toLowerCase();
    if (!MIME_TO_TYPE.has(k)) {
      MIME_TO_TYPE.set(k, def.id);
    }
  }
  for (const mExt of def.magicExtensions) {
    const k = mExt.toLowerCase();
    if (!MAGIC_EXT_TO_TYPE.has(k)) {
      MAGIC_EXT_TO_TYPE.set(k, def.id);
    }
  }
  for (const mMime of def.magicMimes) {
    const k = mMime.toLowerCase();
    if (!MAGIC_MIME_TO_TYPE.has(k)) {
      MAGIC_MIME_TO_TYPE.set(k, def.id);
    }
  }
}

/**
 * Returns the canonical definition for a given CanonicalFileType.
 */
export function getCanonicalTypeDefinition(type: CanonicalFileType): CanonicalTypeDefinition {
  return CANONICAL_TYPE_DEFINITIONS[type];
}

/**
 * Resolves canonical file type from an extension (e.g. '.pdf' -> 'PDF').
 * Normalizes input by ensuring leading dot and lowercase.
 */
export function getCanonicalTypeFromExtension(
  rawExtension?: string,
): CanonicalFileType | undefined {
  if (!rawExtension) return undefined;
  let ext = rawExtension.trim().toLowerCase();
  if (!ext.startsWith('.')) {
    ext = `.${ext}`;
  }
  return EXTENSION_TO_TYPE.get(ext);
}

/**
 * Resolves canonical file type from a MIME type (e.g. 'application/pdf' -> 'PDF').
 * Normalizes input by stripping parameters and whitespace.
 */
export function getCanonicalTypeFromMime(rawMime?: string): CanonicalFileType | undefined {
  if (!rawMime) return undefined;
  const cleanMime = rawMime.split(';')[0]?.trim().toLowerCase() ?? '';
  return MIME_TO_TYPE.get(cleanMime);
}

/**
 * Resolves canonical file type from magic detection results (magic extension and/or magic MIME).
 */
export function getCanonicalTypeFromMagic(
  magicExt?: string,
  magicMime?: string,
): CanonicalFileType | undefined {
  if (magicExt) {
    const cleanExt = magicExt.replace(/^\./, '').trim().toLowerCase();
    const typeByExt = MAGIC_EXT_TO_TYPE.get(cleanExt);
    if (typeByExt) return typeByExt;
  }
  if (magicMime) {
    const cleanMime = magicMime.split(';')[0]?.trim().toLowerCase() ?? '';
    const typeByMime = MAGIC_MIME_TO_TYPE.get(cleanMime);
    if (typeByMime) return typeByMime;
  }
  return undefined;
}

/**
 * Checks whether an extension is permitted for a canonical type.
 */
export function isExtensionAllowedForCanonical(
  canonical: CanonicalFileType,
  rawExtension: string,
): boolean {
  let ext = rawExtension.trim().toLowerCase();
  if (!ext.startsWith('.')) {
    ext = `.${ext}`;
  }
  const def = CANONICAL_TYPE_DEFINITIONS[canonical];
  return def.extensions.includes(ext);
}

/**
 * Checks whether a MIME type is permitted for a canonical type.
 */
export function isMimeAllowedForCanonical(canonical: CanonicalFileType, rawMime: string): boolean {
  const cleanMime = rawMime.split(';')[0]?.trim().toLowerCase() ?? '';
  const def = CANONICAL_TYPE_DEFINITIONS[canonical];
  return def.mimeTypes.includes(cleanMime);
}

/**
 * Checks whether two canonical file types are mutually compatible.
 * Handles container types (e.g., DOCX within ZIP container) and subtype compatibility (e.g., CSV within TEXT).
 */
export function areTypesCompatible(typeA?: CanonicalFileType, typeB?: CanonicalFileType): boolean {
  if (!typeA || !typeB) return false;
  if (typeA === typeB) return true;

  const defA = CANONICAL_TYPE_DEFINITIONS[typeA];
  if (defA.compatibleTypes?.includes(typeB) || defA.containerType === typeB) {
    return true;
  }

  const defB = CANONICAL_TYPE_DEFINITIONS[typeB];
  if (defB.compatibleTypes?.includes(typeA) || defB.containerType === typeA) {
    return true;
  }

  return false;
}

/**
 * Returns all registered canonical file types.
 */
export function getAllCanonicalTypes(): readonly CanonicalFileType[] {
  return Object.keys(CANONICAL_TYPE_DEFINITIONS) as CanonicalFileType[];
}
