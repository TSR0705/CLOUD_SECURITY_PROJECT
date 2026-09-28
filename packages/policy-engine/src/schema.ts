import { z } from 'zod';

export const POLICY_SCHEMA_VERSION = 'sug.policy/v1' as const;
export const MAX_POLICY_FILE_SIZE_BYTES = 52_428_800; // 50 MB Gateway ceiling

const EXTENSION_REGEX = /^\.[a-zA-Z0-9]{1,16}$/;
const MIME_TYPE_REGEX = /^[a-zA-Z0-9\-+.]+\/[a-zA-Z0-9\-+.]+$/;

/**
 * Strict Zod schema for versioned security policy documents (sug.policy/v1).
 * Rejects unknown properties, impossible size limits, invalid extensions,
 * invalid MIME type identifiers, and contradictory rule configurations.
 */
export const PolicyDocumentSchema = z
  .object({
    schemaVersion: z.literal(POLICY_SCHEMA_VERSION, {
      error: `Invalid policy schema version; expected '${POLICY_SCHEMA_VERSION}'`,
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
    requireMimeMatch: z.boolean().default(true),
    allowArchives: z.boolean().default(false),
    maxArchiveDepth: z
      .number()
      .int()
      .min(0, 'maxArchiveDepth cannot be negative')
      .max(5, 'maxArchiveDepth cannot exceed 5')
      .default(0),
    maxArchiveFiles: z
      .number()
      .int()
      .min(0, 'maxArchiveFiles cannot be negative')
      .max(1000, 'maxArchiveFiles cannot exceed 1000')
      .default(0),
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

    // 3. Archive settings consistency
    if (!data.allowArchives) {
      if (data.maxArchiveDepth > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'maxArchiveDepth must be 0 when allowArchives is false',
          path: ['maxArchiveDepth'],
        });
      }
      if (data.maxArchiveFiles > 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'maxArchiveFiles must be 0 when allowArchives is false',
          path: ['maxArchiveFiles'],
        });
      }
    } else {
      if (data.maxArchiveFiles === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'maxArchiveFiles must be greater than 0 when allowArchives is true',
          path: ['maxArchiveFiles'],
        });
      }
      if (data.maxArchiveDepth === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'maxArchiveDepth must be at least 1 when allowArchives is true',
          path: ['maxArchiveDepth'],
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
