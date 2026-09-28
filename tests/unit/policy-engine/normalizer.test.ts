import { describe, it, expect } from 'vitest';
import { normalizeFilename } from '@sug/policy-engine';

describe('Filename Normalizer Security Tests', () => {
  it('preserves clean, standard filenames', () => {
    const res = normalizeFilename('monthly-report_2026.pdf');
    expect(res.normalized).toBe('monthly-report_2026.pdf');
    expect(res.extension).toBe('.pdf');
    expect(res.hasDangerousCharacters).toBe(false);
    expect(res.hasTraversalAttempt).toBe(false);
    expect(res.hasHiddenExtension).toBe(false);
    expect(res.hasRtlOverride).toBe(false);
  });

  it('eliminates Unix directory traversal sequences and flags attempt', () => {
    const res = normalizeFilename('../../../etc/passwd');
    expect(res.normalized).toBe('passwd');
    expect(res.hasTraversalAttempt).toBe(true);
  });

  it('eliminates Windows directory traversal sequences and backslashes', () => {
    const res = normalizeFilename('..\\..\\Windows\\System32\\cmd.exe');
    expect(res.normalized).toBe('cmd.exe');
    expect(res.extension).toBe('.exe');
    expect(res.hasTraversalAttempt).toBe(true);
    expect(res.hasHiddenExtension).toBe(true);
  });

  it('collapses repeated path separators', () => {
    const res = normalizeFilename('///var///log////app.log');
    expect(res.normalized).toBe('app.log');
    expect(res.extension).toBe('.log');
    expect(res.hasTraversalAttempt).toBe(true);
  });

  it('collapses multiple consecutive dots', () => {
    const res = normalizeFilename('report....2026...pdf');
    expect(res.normalized).toBe('report.2026.pdf');
  });

  it('strips null bytes and ASCII control characters', () => {
    const res = normalizeFilename('malicious\x00file\x01\x1f.pdf');
    expect(res.normalized).toBe('maliciousfile.pdf');
    expect(res.hasDangerousCharacters).toBe(true);
  });

  it('detects and strips Unicode Right-to-Left Override (U+202E) spoofing characters', () => {
    // Attack: invoice\u202Efdp.exe -> visually appears as invoiceexe.pdf in bidirectional UI
    const res = normalizeFilename('invoice\u202Efdp.exe');
    expect(res.hasRtlOverride).toBe(true);
    expect(res.hasDangerousCharacters).toBe(true);
    expect(res.normalized).not.toContain('\u202E');
    expect(res.extension).toBe('.exe');
  });

  it('detects hidden executable extensions in double-extension attacks', () => {
    const exeJpg = normalizeFilename('photo.exe.jpg');
    expect(exeJpg.extension).toBe('.jpg');
    expect(exeJpg.hasHiddenExtension).toBe(true);

    const phpPng = normalizeFilename('avatar.php.png');
    expect(phpPng.extension).toBe('.png');
    expect(phpPng.hasHiddenExtension).toBe(true);

    const shTxt = normalizeFilename('notes.sh.txt');
    expect(shTxt.extension).toBe('.txt');
    expect(shTxt.hasHiddenExtension).toBe(true);

    // Benign multi-dot file should NOT flag as hidden extension
    const benign = normalizeFilename('annual.report.v2.final.pdf');
    expect(benign.extension).toBe('.pdf');
    expect(benign.hasHiddenExtension).toBe(false);
  });

  it('clamps extremely long filenames to <= 255 characters while preserving extension', () => {
    const longName = 'a'.repeat(300) + '.pdf';
    const res = normalizeFilename(longName);
    expect(res.normalized.length).toBeLessThanOrEqual(255);
    expect(res.normalized.endsWith('.pdf')).toBe(true);
    expect(res.extension).toBe('.pdf');
  });

  it('handles empty or whitespace-only filenames safely', () => {
    const res = normalizeFilename('   ');
    expect(res.normalized).toBe('unnamed_file');
    expect(res.hasDangerousCharacters).toBe(true);
  });
});
