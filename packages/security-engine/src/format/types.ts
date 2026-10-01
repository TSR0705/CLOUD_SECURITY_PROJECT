/**
 * @sug/security-engine/format/types
 * Type contracts for P17 security format checkers.
 */

import type {
  CanonicalReasonCode,
  CheckId,
  ConfidenceLevel,
  FindingOutcome,
  SeverityLevel,
} from '@sug/shared';

export interface BaseFormatCheckResult {
  checkId: CheckId;
  engine: string;
  engineVersion?: string | undefined;
  signatureVersion?: string | undefined;
  outcome: FindingOutcome;
  reasonCode: CanonicalReasonCode;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  evidence: Record<string, unknown>;
  durationMs: number;
}

export interface PdfKeywordMatch {
  keyword: string;
  count: number;
  locations?: string[] | undefined;
}

export interface PdfCheckResult extends BaseFormatCheckResult {
  checkId: 'scanner.pdf';
  detectedKeywords: string[];
}

export interface OoxmlMacroResult extends BaseFormatCheckResult {
  checkId: 'scanner.ooxml.macro';
  macroEntries: string[];
  contentTypes: string[];
}

export interface ExternalRelationshipTarget {
  id?: string | undefined;
  type?: string | undefined;
  target: string;
  sourcePart: string;
}

export interface OoxmlRelationshipResult extends BaseFormatCheckResult {
  checkId: 'scanner.ooxml.relationship';
  externalTargets: ExternalRelationshipTarget[];
}

export interface ImageTrailingResult extends BaseFormatCheckResult {
  checkId: 'scanner.image.trailing';
  format?: 'png' | 'jpeg' | 'gif' | undefined;
  trailerOffset?: number | undefined;
  trailingBytesCount?: number | undefined;
}

export interface EmbeddedSignatureMatch {
  signatureType: 'PE' | 'ELF' | 'MACHO';
  offset: number;
  description: string;
}

export interface EmbeddedSignatureResult extends BaseFormatCheckResult {
  checkId: 'scanner.signature.embedded';
  matches: EmbeddedSignatureMatch[];
}

export interface PolyglotResult extends BaseFormatCheckResult {
  checkId: 'scanner.polyglot';
  primaryFormat?: string | undefined;
  secondaryFormat?: string | undefined;
  isDocumentedMiss?: boolean | undefined;
}
