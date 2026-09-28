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
    expect(preset.name).toBe('images-only');
    expect(preset.maxFileSize).toBe(10 * 1024 * 1024);
    expect(preset.allowedExtensions).toContain('.jpg');
    expect(preset.allowedExtensions).toContain('.png');
    expect(preset.allowArchives).toBe(false);
    expect(Object.isFrozen(preset)).toBe(true);
  });

  it('documents preset satisfies sug.policy/v1 and is immutable', () => {
    const preset = createDocumentsPreset();
    expect(parsePolicyDocument(preset)).toEqual(preset);
    expect(preset.name).toBe('documents');
    expect(preset.maxFileSize).toBe(25 * 1024 * 1024);
    expect(preset.allowedExtensions).toContain('.pdf');
    expect(preset.allowedExtensions).toContain('.docx');
    expect(preset.allowArchives).toBe(false);
    expect(Object.isFrozen(preset)).toBe(true);
  });

  it('archives-strict preset satisfies sug.policy/v1 and is immutable', () => {
    const preset = createArchivesStrictPreset();
    expect(parsePolicyDocument(preset)).toEqual(preset);
    expect(preset.name).toBe('archives-strict');
    expect(preset.maxFileSize).toBe(50 * 1024 * 1024);
    expect(preset.allowedExtensions).toContain('.zip');
    expect(preset.allowArchives).toBe(true);
    expect(preset.maxArchiveDepth).toBe(2);
    expect(preset.maxArchiveFiles).toBe(100);
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
