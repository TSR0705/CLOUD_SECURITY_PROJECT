import { z } from 'zod';

export const POLICY_SCHEMA = 'sug.policy/v1' as const;
export const POLICY_SCHEMA_VERSION = POLICY_SCHEMA; // Backwards-compatible alias
export const MAX_POLICY_FILE_SIZE_BYTES = 52_428_800; // 50 MB Gateway ceiling

export const EXTENSION_REGEX = /^\.[a-zA-Z0-9]{1,16}$/;
export const MIME_TYPE_REGEX = /^[a-zA-Z0-9\-+.]+\/[a-zA-Z0-9\-+.]+$/;

/**
 * Valid check identifiers supported by the multi-engine inspection pipeline.
 */
export const SUPPORTED_REQUIRED_CHECKS = [
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
  'pdf.active_content',
  'pdf.encrypted',
  'pdf.embedded',
  'office.macros',
  'image.format',
] as const;

export type RequiredCheckIdentifier = (typeof SUPPORTED_REQUIRED_CHECKS)[number];

export const CANONICAL_BASELINE_CHECKS: readonly RequiredCheckIdentifier[] = [
  'filename.safe',
  'extension.allowed',
  'magic.detect',
  'type.consistency',
  'size.limit',
  'clamav.instream',
  'yara.rules',
  'polyglot.basic',
] as const;

/**
 * Archive inspection constraints schema.
 */
export const ArchivePolicySchema = z
  .object({
    maxCompressedSize: z
      .number()
      .int('maxCompressedSize must be an integer')
      .positive('maxCompressedSize must be positive')
      .max(
        MAX_POLICY_FILE_SIZE_BYTES,
        `maxCompressedSize cannot exceed ${MAX_POLICY_FILE_SIZE_BYTES}`,
      ),
    maxUncompressedSize: z
      .number()
      .int('maxUncompressedSize must be an integer')
      .positive('maxUncompressedSize must be positive')
      .max(500 * 1024 * 1024, 'maxUncompressedSize cannot exceed 500 MB'),
    maxEntries: z
      .number()
      .int('maxEntries must be an integer')
      .positive('maxEntries must be positive')
      .max(10_000, 'maxEntries cannot exceed 10000'),
    maxDepth: z
      .number()
      .int('maxDepth must be an integer')
      .min(1, 'maxDepth must be at least 1')
      .max(10, 'maxDepth cannot exceed 10'),
    maxRatio: z
      .number()
      .positive('maxRatio must be positive')
      .min(1, 'maxRatio must be at least 1')
      .max(1000, 'maxRatio cannot exceed 1000'),
    maxExtractionMs: z
      .number()
      .int('maxExtractionMs must be an integer')
      .positive('maxExtractionMs must be positive')
      .max(60_000, 'maxExtractionMs cannot exceed 60000'),
    maxMemoryBytes: z
      .number()
      .int('maxMemoryBytes must be an integer')
      .positive('maxMemoryBytes must be positive')
      .max(1024 * 1024 * 1024, 'maxMemoryBytes cannot exceed 1 GB'),
  })
  .strict();

export type ArchivePolicy = z.infer<typeof ArchivePolicySchema>;

export const DEFAULT_ARCHIVE_POLICY: ArchivePolicy = {
  maxCompressedSize: 50 * 1024 * 1024,
  maxUncompressedSize: 100 * 1024 * 1024,
  maxEntries: 1000,
  maxDepth: 3,
  maxRatio: 100,
  maxExtractionMs: 10000,
  maxMemoryBytes: 256 * 1024 * 1024,
};

/**
 * PDF active content and encryption policy schema.
 */
export const PdfPolicySchema = z
  .object({
    allowActiveContent: z.boolean().default(false),
    allowEncrypted: z.boolean().default(false),
    allowEmbeddedFiles: z.boolean().default(false),
  })
  .strict();

export type PdfPolicy = z.infer<typeof PdfPolicySchema>;

export const DEFAULT_PDF_POLICY: PdfPolicy = {
  allowActiveContent: false,
  allowEncrypted: false,
  allowEmbeddedFiles: false,
};

/**
 * OOXML / Office macro policy schema.
 */
export const OfficePolicySchema = z
  .object({
    allowMacros: z.boolean().default(false),
  })
  .strict();

export type OfficePolicy = z.infer<typeof OfficePolicySchema>;

export const DEFAULT_OFFICE_POLICY: OfficePolicy = {
  allowMacros: false,
};

/**
 * Image inspection and re-encoding policy schema.
 */
export const ImagePolicySchema = z
  .object({
    maxPixels: z
      .number()
      .int('maxPixels must be an integer')
      .positive('maxPixels must be positive')
      .max(100_000_000, 'maxPixels cannot exceed 100000000')
      .default(25_000_000),
    reencode: z.boolean().default(false),
  })
  .strict();

export type ImagePolicy = z.infer<typeof ImagePolicySchema>;

export const DEFAULT_IMAGE_POLICY: ImagePolicy = {
  maxPixels: 25_000_000,
  reencode: false,
};

/**
 * Retention policy schema.
 */
export const RetentionPolicySchema = z
  .object({
    quarantineDays: z
      .number()
      .int('quarantineDays must be an integer')
      .min(1, 'quarantineDays must be at least 1')
      .max(365, 'quarantineDays cannot exceed 365')
      .default(7),
  })
  .strict();

export type RetentionPolicy = z.infer<typeof RetentionPolicySchema>;

export const DEFAULT_RETENTION_POLICY: RetentionPolicy = {
  quarantineDays: 7,
};

export const SUSPICIOUS_ACTION_VALUES = ['QUARANTINE', 'BLOCK'] as const;
export type SuspiciousAction = (typeof SUSPICIOUS_ACTION_VALUES)[number];

const ARCHIVE_EXTENSIONS = new Set(['.zip', '.tar', '.gz', '.tgz', '.7z', '.rar']);
const ARCHIVE_MIME_TYPES = new Set([
  'application/zip',
  'application/x-zip-compressed',
  'application/x-tar',
  'application/gzip',
  'application/x-gzip',
  'application/x-7z-compressed',
  'application/vnd.rar',
]);

/**
 * Strict Zod schema for versioned security policy documents (sug.policy/v1).
 * Rejects unknown properties, impossible size limits, invalid extensions,
 * invalid MIME type identifiers, contradictory rule configurations, and unbound nested policies.
 */
export const PolicyDocumentSchema = z
  .object({
    schema: z.literal(POLICY_SCHEMA, {
      error: `Invalid policy schema version; expected '${POLICY_SCHEMA}'`,
    }),
    name: z
      .string()
      .trim()
      .min(1, 'Policy name must not be empty')
      .max(64, 'Policy name must not exceed 64 characters'),
    description: z
      .string()
      .trim()
      .max(256, 'Policy description must not exceed 256 characters')
      .optional(),
    maxFileSize: z
      .number()
      .int('maxFileSize must be an integer')
      .positive('maxFileSize must be greater than 0')
      .max(
        MAX_POLICY_FILE_SIZE_BYTES,
        `maxFileSize cannot exceed global limit of ${MAX_POLICY_FILE_SIZE_BYTES} bytes (50 MB)`,
      ),
    allowedExtensions: z
      .array(
        z
          .string()
          .trim()
          .toLowerCase()
          .regex(
            EXTENSION_REGEX,
            'File extension must begin with a dot and contain 1-16 alphanumeric characters (e.g. .pdf)',
          ),
      )
      .min(1, 'allowedExtensions must contain at least one extension'),
    allowedMimeTypes: z
      .array(
        z
          .string()
          .trim()
          .toLowerCase()
          .regex(MIME_TYPE_REGEX, 'MIME type must match standard type/subtype format'),
      )
      .min(1, 'allowedMimeTypes must contain at least one MIME type'),
    blockedExtensions: z
      .array(
        z
          .string()
          .trim()
          .toLowerCase()
          .regex(EXTENSION_REGEX, 'Blocked extension must begin with a dot'),
      )
      .default([]),
    blockedMimeTypes: z
      .array(
        z
          .string()
          .trim()
          .toLowerCase()
          .regex(MIME_TYPE_REGEX, 'Blocked MIME type must match standard type/subtype format'),
      )
      .default([]),
    scanRequired: z.boolean().default(true),
    requiredChecks: z
      .array(
        z.enum(SUPPORTED_REQUIRED_CHECKS, {
          error: 'Invalid check identifier in requiredChecks',
        }),
      )
      .min(1, 'requiredChecks must contain at least one check')
      .default([...CANONICAL_BASELINE_CHECKS]),
    archiveAllowed: z.boolean().default(false),
    archive: ArchivePolicySchema.default(DEFAULT_ARCHIVE_POLICY),
    pdf: PdfPolicySchema.default(DEFAULT_PDF_POLICY),
    office: OfficePolicySchema.default(DEFAULT_OFFICE_POLICY),
    image: ImagePolicySchema.default(DEFAULT_IMAGE_POLICY),
    cdrRequired: z.boolean().default(false),
    onSuspicious: z
      .enum(SUSPICIOUS_ACTION_VALUES, {
        error: `onSuspicious must be one of: ${SUSPICIOUS_ACTION_VALUES.join(', ')}`,
      })
      .default('QUARANTINE'),
    manualReviewThreshold: z
      .number()
      .int('manualReviewThreshold must be an integer')
      .min(0, 'manualReviewThreshold cannot be negative')
      .max(100, 'manualReviewThreshold cannot exceed 100')
      .default(50),
    scanTimeoutMs: z
      .number()
      .int('scanTimeoutMs must be an integer')
      .positive('scanTimeoutMs must be positive')
      .max(60_000, 'scanTimeoutMs cannot exceed 60000 ms')
      .default(30_000),
    retention: RetentionPolicySchema.default(DEFAULT_RETENTION_POLICY),
    replicate: z.boolean().default(true),
  })
  .strict()
  .superRefine((data, ctx) => {
    // 1. Contradiction check: allowedExtensions vs blockedExtensions
    const allowedExts = new Set(data.allowedExtensions.map((e) => e.toLowerCase()));
    for (const blocked of data.blockedExtensions) {
      if (allowedExts.has(blocked.toLowerCase())) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `Extension '${blocked}' cannot be simultaneously allowed and blocked`,
          path: ['blockedExtensions'],
        });
      }
    }

    // 2. Contradiction check: allowedMimeTypes vs blockedMimeTypes
    const allowedMimes = new Set(data.allowedMimeTypes.map((m) => m.toLowerCase()));
    for (const blocked of data.blockedMimeTypes) {
      if (allowedMimes.has(blocked.toLowerCase())) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `MIME type '${blocked}' cannot be simultaneously allowed and blocked`,
          path: ['blockedMimeTypes'],
        });
      }
    }

    // 3. Duplicate checks in requiredChecks
    const uniqueChecks = new Set(data.requiredChecks);
    if (uniqueChecks.size !== data.requiredChecks.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'requiredChecks cannot contain duplicate check identifiers',
        path: ['requiredChecks'],
      });
    }

    // 4. Archive coherence with archiveAllowed and file size
    if (data.archive.maxUncompressedSize < data.archive.maxCompressedSize) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'archive.maxUncompressedSize cannot be smaller than archive.maxCompressedSize',
        path: ['archive', 'maxUncompressedSize'],
      });
    }

    if (!data.archiveAllowed) {
      for (const ext of data.allowedExtensions) {
        if (ARCHIVE_EXTENSIONS.has(ext.toLowerCase())) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Archive extension '${ext}' is not permitted when archiveAllowed is false`,
            path: ['allowedExtensions'],
          });
        }
      }
      for (const mime of data.allowedMimeTypes) {
        if (ARCHIVE_MIME_TYPES.has(mime.toLowerCase())) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Archive MIME type '${mime}' is not permitted when archiveAllowed is false`,
            path: ['allowedMimeTypes'],
          });
        }
      }
    } else {
      if (data.archive.maxCompressedSize > data.maxFileSize) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'archive.maxCompressedSize cannot exceed maxFileSize',
          path: ['archive', 'maxCompressedSize'],
        });
      }
    }
  });

export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;
export type CreatePolicyInput = z.input<typeof PolicyDocumentSchema>;

/**
 * Validates untrusted input as a strict PolicyDocument, throwing on violation.
 */
export function parsePolicyDocument(input: unknown): PolicyDocument {
  return PolicyDocumentSchema.parse(input);
}

/**
 * Safely parses untrusted input as a PolicyDocument without throwing.
 */
export function safeParsePolicyDocument(input: unknown) {
  return PolicyDocumentSchema.safeParse(input);
}
