/**
 * @sug/security-engine/format
 * Format-specific security checks for P17:
 * - PDF active content (scan-04)
 * - OOXML macros (scan-05)
 * - OOXML external relationships (scan-06)
 * - Image trailing data
 * - Embedded executable signatures
 * - Basic polyglots (poly-01, poly-02, poly-03)
 */

export * from './types.js';
export * from './pdf.js';
export * from './ooxml.js';
export * from './image-trailing.js';
export * from './embedded-sig.js';
export * from './polyglot.js';
