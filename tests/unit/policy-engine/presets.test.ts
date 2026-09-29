import { describe, it, expect } from 'vitest';
import {
  createImagesOnlyPreset,
  createDocumentsPreset,
  createArchivesStrictPreset,
  getPresetByName,
  CANONICAL_PRESETS,
  parsePolicyDocument,
} from '@sug/policy-engine';

describe('Policy Presets', () => {
  it('images-only preset satisfies sug.policy/v1 and is immutable', () => {
    const preset = createImagesOnlyPreset();
    expect(parsePolicyDocument(preset)).toEqual(preset);
    expect(preset.schema).toBe('sug.policy/v1');
    expect(preset.name).toBe('images-only');
    expect(preset.maxFileSize).toBe(10 * 1024 * 1024);
    expect(preset.allowedExtensions).toContain('.jpg');
    expect(preset.allowedExtensions).toContain('.png');
    expect(preset.archiveAllowed).toBe(false);
    expect(preset.image.maxPixels).toBe(25_000_000);
    expect(preset.requiredChecks).toContain('image.format');
    expect(Object.isFrozen(preset)).toBe(true);
  });

  it('documents preset satisfies sug.policy/v1 and is immutable', () => {
    const preset = createDocumentsPreset();
    expect(parsePolicyDocument(preset)).toEqual(preset);
    expect(preset.schema).toBe('sug.policy/v1');
    expect(preset.name).toBe('documents');
    expect(preset.maxFileSize).toBe(25 * 1024 * 1024);
    expect(preset.allowedExtensions).toContain('.pdf');
    expect(preset.allowedExtensions).toContain('.docx');
    expect(preset.archiveAllowed).toBe(false);
    expect(preset.pdf.allowActiveContent).toBe(false);
    expect(preset.office.allowMacros).toBe(false);
    expect(preset.requiredChecks).toContain('pdf.active_content');
    expect(Object.isFrozen(preset)).toBe(true);
  });

  it('archives-strict preset satisfies sug.policy/v1 and is immutable', () => {
    const preset = createArchivesStrictPreset();
    expect(parsePolicyDocument(preset)).toEqual(preset);
    expect(preset.schema).toBe('sug.policy/v1');
    expect(preset.name).toBe('archives-strict');
    expect(preset.maxFileSize).toBe(50 * 1024 * 1024);
    expect(preset.allowedExtensions).toContain('.zip');
    expect(preset.archiveAllowed).toBe(true);
    expect(preset.archive.maxDepth).toBe(2);
    expect(preset.archive.maxEntries).toBe(100);
    expect(preset.archive.maxRatio).toBe(20);
    expect(preset.requiredChecks).toContain('archive.bomb');
    expect(Object.isFrozen(preset)).toBe(true);
  });

  it('resolves preset by name correctly', () => {
    expect(getPresetByName('images-only')).toBe(CANONICAL_PRESETS['images-only']);
    expect(getPresetByName('documents')).toBe(CANONICAL_PRESETS['documents']);
    expect(getPresetByName('archives-strict')).toBe(CANONICAL_PRESETS['archives-strict']);
  });

  it('throws on unknown preset name', () => {
    expect(() => getPresetByName('malicious-preset')).toThrow(/Unknown policy preset/);
  });
});
