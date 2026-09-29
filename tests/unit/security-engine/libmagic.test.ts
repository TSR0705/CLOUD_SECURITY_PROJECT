import { describe, it, expect } from 'vitest';
import { detectMimeWithLibmagic, detectMimeFromBufferWithLibmagic } from '@sug/security-engine';

describe('DoD: val-07 — libmagic CLI Integration (file --mime-type -b)', () => {
  it('parses successful MIME detection from file --mime-type -b', async () => {
    const mockRunner = async (command: string, args: string[]) => {
      expect(command).toBe('file');
      expect(args[0]).toBe('--mime-type');
      expect(args[1]).toBe('-b');
      return {
        stdout: 'application/pdf\n',
        stderr: '',
        exitCode: 0,
      };
    };

    const res = await detectMimeWithLibmagic('/tmp/test.pdf', {
      customRunner: mockRunner,
    });

    expect(res.available).toBe(true);
    expect(res.detectedMime).toBe('application/pdf');
    expect(res.rawOutput).toBe('application/pdf');
    expect(res.error).toBeUndefined();
  });

  it('normalizes MIME output containing trailing parameters', async () => {
    const mockRunner = async () => ({
      stdout: 'text/plain; charset=us-ascii\n',
      stderr: '',
      exitCode: 0,
    });

    const res = await detectMimeWithLibmagic('/tmp/test.txt', {
      customRunner: mockRunner,
    });

    expect(res.available).toBe(true);
    expect(res.detectedMime).toBe('text/plain');
  });

  it('handles non-zero exit code from file command gracefully', async () => {
    const mockRunner = async () => ({
      stdout: '',
      stderr: 'cannot open /tmp/notfound (No such file or directory)',
      exitCode: 1,
    });

    const res = await detectMimeWithLibmagic('/tmp/notfound', {
      customRunner: mockRunner,
    });

    expect(res.available).toBe(false);
    expect(res.detectedMime).toBeUndefined();
    expect(res.error).toContain('file command exited with code 1');
  });

  it('handles command failure or exception gracefully', async () => {
    const mockRunner = async () => {
      throw new Error('Command failed: spawn file ENOENT');
    };

    const res = await detectMimeWithLibmagic('/tmp/test.pdf', {
      customRunner: mockRunner,
    });

    expect(res.available).toBe(false);
    expect(res.detectedMime).toBeUndefined();
    expect(res.error).toContain('libmagic execution failed');
  });

  it('detects MIME from in-memory buffer via temporary file with cleanup', async () => {
    let capturedPath = '';
    const mockRunner = async (command: string, args: string[]) => {
      capturedPath = args[2]!;
      return {
        stdout: 'image/png\n',
        stderr: '',
        exitCode: 0,
      };
    };

    const dummyBuffer = Buffer.from('dummy image bytes');
    const res = await detectMimeFromBufferWithLibmagic(dummyBuffer, {
      customRunner: mockRunner,
    });

    expect(res.available).toBe(true);
    expect(res.detectedMime).toBe('image/png');
    expect(capturedPath).toContain('sug_magic_');
  });

  it('handles unparseable output gracefully', async () => {
    const mockRunner = async () => ({
      stdout: 'unrecognized_data_without_slash\n',
      stderr: '',
      exitCode: 0,
    });

    const res = await detectMimeWithLibmagic('/tmp/test.bin', {
      customRunner: mockRunner,
    });

    expect(res.available).toBe(true);
    expect(res.detectedMime).toBeUndefined();
    expect(res.error).toContain('Could not parse valid MIME');
  });
});
