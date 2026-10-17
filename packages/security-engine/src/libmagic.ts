import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import type { LibmagicOptions, LibmagicResult } from './types.js';
import { parseAndNormalizeMime } from './mime.js';

const execFileAsync = promisify(execFile);

/**
 * Default CLI runner using Node.js child_process.execFile.
 */
async function defaultRunner(
  command: string,
  args: string[],
  timeoutMs = 5000,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
    });
    return {
      stdout: stdout.toString(),
      stderr: stderr.toString(),
      exitCode: 0,
    };
  } catch (err: unknown) {
    const nodeErr = err as { code?: string | number; stdout?: string; stderr?: string };
    return {
      stdout: nodeErr.stdout ? nodeErr.stdout.toString() : '',
      stderr: nodeErr.stderr
        ? nodeErr.stderr.toString()
        : err instanceof Error
          ? err.message
          : String(err),
      exitCode: typeof nodeErr.code === 'number' ? nodeErr.code : 1,
    };
  }
}

/**
 * Detects MIME type for a file path using the standard POSIX libmagic utility:
 * `file --mime-type -b <filePath>`
 *
 * Used at the scanner execution boundary (e.g. inside Docker scanner container).
 */
export async function detectMimeWithLibmagic(
  filePath: string,
  options?: LibmagicOptions,
): Promise<LibmagicResult> {
  const runner =
    options?.customRunner ?? ((cmd, args) => defaultRunner(cmd, args, options?.timeoutMs));

  try {
    const result = await runner('file', ['--mime-type', '-b', filePath]);
    if (result.exitCode !== 0) {
      return {
        available: false,
        detectedMime: undefined,
        rawOutput: result.stderr,
        error: `file command exited with code ${result.exitCode}: ${result.stderr}`,
      };
    }

    const rawOutput = result.stdout.trim();
    const parsed = parseAndNormalizeMime(rawOutput);

    if (parsed.isValid && parsed.baseMime) {
      return {
        available: true,
        detectedMime: parsed.baseMime,
        rawOutput,
      };
    }

    return {
      available: true,
      detectedMime: undefined,
      rawOutput,
      error: `Could not parse valid MIME from output: ${rawOutput}`,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      available: false,
      detectedMime: undefined,
      error: `libmagic execution failed: ${msg}`,
    };
  }
}

/**
 * Detects MIME type from an in-memory buffer using libmagic CLI (`file --mime-type -b`).
 * Temporarily writes bounded bytes (up to 4,100 bytes) to an OS tmpfile, runs `file`, and deletes the tmpfile.
 */
export async function detectMimeFromBufferWithLibmagic(
  buffer: Uint8Array | Buffer,
  options?: LibmagicOptions,
): Promise<LibmagicResult> {
  const tmpId = crypto.randomUUID();
  const tmpPath = path.join(os.tmpdir(), `sug_magic_${tmpId}.tmp`);

  try {
    // Write only bounded prefix (up to 4,100 bytes)
    const boundedPrefix = buffer.subarray(0, 4100);
    await fs.writeFile(tmpPath, boundedPrefix);

    const result = await detectMimeWithLibmagic(tmpPath, options);
    return result;
  } finally {
    try {
      await fs.unlink(tmpPath);
    } catch {
      // Ignore cleanup error
    }
  }
}
