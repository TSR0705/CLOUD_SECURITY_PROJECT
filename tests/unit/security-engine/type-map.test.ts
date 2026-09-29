import { describe, it, expect } from 'vitest';
import {
  getAllCanonicalTypes,
  getCanonicalTypeDefinition,
  getCanonicalTypeFromExtension,
  getCanonicalTypeFromMagic,
  getCanonicalTypeFromMime,
  isExtensionAllowedForCanonical,
  isMimeAllowedForCanonical,
  areTypesCompatible,
} from '@sug/security-engine';

describe('Canonical Type Map & 100% Branch Coverage', () => {
  const allTypes = getAllCanonicalTypes();

  it('contains definitions for all standard canonical types', () => {
    expect(allTypes.length).toBeGreaterThanOrEqual(18);
    expect(allTypes).toContain('PDF');
    expect(allTypes).toContain('JPEG');
    expect(allTypes).toContain('PNG');
    expect(allTypes).toContain('DOCX');
    expect(allTypes).toContain('ZIP');
    expect(allTypes).toContain('EXECUTABLE');
  });

  describe('comprehensive resolution for every registered canonical type', () => {
    for (const type of allTypes) {
      const def = getCanonicalTypeDefinition(type);

      it(`resolves ${type} by definition, primary extension, and MIME`, () => {
        expect(def.id).toBe(type);
        expect(def.primaryExtension).toBeDefined();
        expect(def.primaryMime).toBeDefined();

        // Resolve by extension (with and without leading dot)
        expect(getCanonicalTypeFromExtension(def.primaryExtension)).toBe(type);
        const withoutDot = def.primaryExtension.replace(/^\./, '');
        expect(getCanonicalTypeFromExtension(withoutDot)).toBe(type);

        // Resolve by MIME
        expect(getCanonicalTypeFromMime(def.primaryMime)).toBe(type);

        // Validate allowed extension and MIME
        expect(isExtensionAllowedForCanonical(type, def.primaryExtension)).toBe(true);
        expect(isMimeAllowedForCanonical(type, def.primaryMime)).toBe(true);

        // Resolve by magic
        if (def.magicExtensions.length > 0) {
          expect(getCanonicalTypeFromMagic(def.magicExtensions[0])).toBe(type);
        }
        if (def.magicMimes.length > 0) {
          expect(getCanonicalTypeFromMagic(undefined, def.magicMimes[0])).toBe(type);
        }
      });
    }
  });

  describe('negative lookups and edge cases', () => {
    it('returns undefined for unknown or empty extensions', () => {
      expect(getCanonicalTypeFromExtension('.unknownext')).toBeUndefined();
      expect(getCanonicalTypeFromExtension('')).toBeUndefined();
      expect(getCanonicalTypeFromExtension(undefined)).toBeUndefined();
    });

    it('returns undefined for unknown or empty MIME types', () => {
      expect(getCanonicalTypeFromMime('unknown/unknown-type')).toBeUndefined();
      expect(getCanonicalTypeFromMime('')).toBeUndefined();
      expect(getCanonicalTypeFromMime(undefined)).toBeUndefined();
    });

    it('returns undefined for unknown or empty magic inputs', () => {
      expect(getCanonicalTypeFromMagic('unknownmagic', 'unknown/mime')).toBeUndefined();
      expect(getCanonicalTypeFromMagic(undefined, undefined)).toBeUndefined();
      expect(getCanonicalTypeFromMagic('', '')).toBeUndefined();
    });

    it('returns false for mismatched extensions and MIMEs', () => {
      expect(isExtensionAllowedForCanonical('PDF', '.jpg')).toBe(false);
      expect(isMimeAllowedForCanonical('PDF', 'image/jpeg')).toBe(false);
      expect(isExtensionAllowedForCanonical('JPEG', '.pdf')).toBe(false);
      expect(isMimeAllowedForCanonical('JPEG', 'application/pdf')).toBe(false);
    });
  });

  describe('container and subtype compatibility rule (areTypesCompatible)', () => {
    it('returns true for identical types', () => {
      expect(areTypesCompatible('PDF', 'PDF')).toBe(true);
      expect(areTypesCompatible('PNG', 'PNG')).toBe(true);
    });

    it('returns true for OOXML documents in ZIP container (symmetric)', () => {
      expect(areTypesCompatible('DOCX', 'ZIP')).toBe(true);
      expect(areTypesCompatible('ZIP', 'DOCX')).toBe(true);
      expect(areTypesCompatible('XLSX', 'ZIP')).toBe(true);
      expect(areTypesCompatible('ZIP', 'XLSX')).toBe(true);
      expect(areTypesCompatible('PPTX', 'ZIP')).toBe(true);
      expect(areTypesCompatible('ZIP', 'PPTX')).toBe(true);
    });

    it('returns true for text subtypes (CSV, JSON, XML within TEXT)', () => {
      expect(areTypesCompatible('CSV', 'TEXT')).toBe(true);
      expect(areTypesCompatible('TEXT', 'CSV')).toBe(true);
      expect(areTypesCompatible('JSON', 'TEXT')).toBe(true);
      expect(areTypesCompatible('TEXT', 'JSON')).toBe(true);
      expect(areTypesCompatible('XML', 'TEXT')).toBe(true);
      expect(areTypesCompatible('TEXT', 'XML')).toBe(true);
      expect(areTypesCompatible('SVG', 'XML')).toBe(true);
    });

    it('returns false for incompatible types', () => {
      expect(areTypesCompatible('PDF', 'JPEG')).toBe(false);
      expect(areTypesCompatible('EXECUTABLE', 'PNG')).toBe(false);
      expect(areTypesCompatible('ZIP', 'PDF')).toBe(false);
      expect(areTypesCompatible('DOCX', 'JPEG')).toBe(false);
    });

    it('returns false when either type is undefined', () => {
      expect(areTypesCompatible(undefined, 'PDF')).toBe(false);
      expect(areTypesCompatible('PDF', undefined)).toBe(false);
      expect(areTypesCompatible(undefined, undefined)).toBe(false);
    });
  });
});
