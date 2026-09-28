import { describe, it, expect } from 'vitest';
import {
  precheck,
  createImagesOnlyPreset,
  createDocumentsPreset,
  createArchivesStrictPreset,
} from '@sug/policy-engine';

describe('Policy Precheck Pure Function', () => {
  const imagesPolicy = createImagesOnlyPreset();
  const docsPolicy = createDocumentsPreset();
  const archivesPolicy = createArchivesStrictPreset();

  it('allows valid files complying with policy', () => {
    const res = precheck(imagesPolicy, {
      filename: 'photo.jpg',
      declaredSize: 1024 * 500, // 500 KB
      declaredMime: 'image/jpeg',
    });
    expect(res.allowed).toBe(true);
    expect(res.details?.extension).toBe('.jpg');
    expect(res.details?.normalizedFilename).toBe('photo.jpg');
  });

  it('rejects files exceeding policy maxFileSize', () => {
    const res = precheck(imagesPolicy, {
      filename: 'huge.png',
      declaredSize: 11 * 1024 * 1024, // 11 MB > 10 MB limit
      declaredMime: 'image/png',
    });
    expect(res.allowed).toBe(false);
    expect(res.code).toBe('SIZE_EXCEEDS_POLICY');
  });

  it('rejects files with zero or negative declared size', () => {
    const resZero = precheck(imagesPolicy, {
      filename: 'empty.png',
      declaredSize: 0,
      declaredMime: 'image/png',
    });
    expect(resZero.allowed).toBe(false);
    expect(resZero.code).toBe('INVALID_SIZE');

    const resNeg = precheck(imagesPolicy, {
      filename: 'neg.png',
      declaredSize: -1,
      declaredMime: 'image/png',
    });
    expect(resNeg.allowed).toBe(false);
    expect(resNeg.code).toBe('INVALID_SIZE');
  });

  it('rejects unpermitted file extensions', () => {
    const res = precheck(imagesPolicy, {
      filename: 'document.pdf',
      declaredSize: 1024 * 100,
      declaredMime: 'application/pdf',
    });
    expect(res.allowed).toBe(false);
    expect(res.code).toBe('EXTENSION_NOT_ALLOWED');
  });

  it('rejects explicitly blocked file extensions', () => {
    const res = precheck(docsPolicy, {
      filename: 'malware.exe',
      declaredSize: 1024 * 100,
      declaredMime: 'application/x-executable',
    });
    expect(res.allowed).toBe(false);
    expect(res.code).toBe('EXTENSION_BLOCKED');
  });

  it('rejects unpermitted MIME types', () => {
    const res = precheck(docsPolicy, {
      filename: 'document.pdf',
      declaredSize: 1024 * 100,
      declaredMime: 'audio/wav',
    });
    expect(res.allowed).toBe(false);
    expect(res.code).toBe('MIME_NOT_ALLOWED');
  });

  it('rejects MIME and extension mismatch when requireMimeMatch is true', () => {
    // Policy allowing both PDF and JPEG
    const mixedPolicy = {
      ...docsPolicy,
      allowedExtensions: ['.pdf', '.jpg'],
      allowedMimeTypes: ['application/pdf', 'image/jpeg'],
    };
    const res = precheck(mixedPolicy, {
      filename: 'spoofed.jpg',
      declaredSize: 1024 * 100,
      declaredMime: 'application/pdf', // Extension is .jpg but MIME is PDF
    });
    expect(res.allowed).toBe(false);
    expect(res.code).toBe('MIME_EXTENSION_MISMATCH');
  });

  it('rejects archives when policy forbids archives', () => {
    const res = precheck(docsPolicy, {
      filename: 'archive.zip',
      declaredSize: 1024 * 100,
      declaredMime: 'application/zip',
    });
    expect(res.allowed).toBe(false);
    expect(res.code).toBe('EXTENSION_BLOCKED');
  });

  it('allows archives when policy permits archives', () => {
    const res = precheck(archivesPolicy, {
      filename: 'backup.zip',
      declaredSize: 1024 * 100,
      declaredMime: 'application/zip',
    });
    expect(res.allowed).toBe(true);
  });

  it('rejects filenames with RTL override spoofing (U+202E)', () => {
    const res = precheck(imagesPolicy, {
      filename: 'innocent\u202Egpj.exe',
      declaredSize: 1024 * 100,
      declaredMime: 'image/jpeg',
    });
    expect(res.allowed).toBe(false);
    expect(res.code).toBe('SUSPICIOUS_FILENAME');
  });

  it('rejects filenames with disguised executable extensions', () => {
    const res = precheck(imagesPolicy, {
      filename: 'avatar.exe.jpg',
      declaredSize: 1024 * 100,
      declaredMime: 'image/jpeg',
    });
    expect(res.allowed).toBe(false);
    expect(res.code).toBe('SUSPICIOUS_FILENAME');
  });
});
