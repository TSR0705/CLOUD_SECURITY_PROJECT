import net from 'node:net';
import type { Readable } from 'node:stream';

export type ClamAvScanStatus = 'CLEAN' | 'FOUND' | 'ERROR';

export interface ClamAvScanResult {
  status: ClamAvScanStatus;
  signature?: string | null;
  rawResponse?: string;
  durationMs: number;
  error?: string | null;
}

export interface ClamAvConfig {
  host: string;
  port: number;
  connectTimeoutMs: number;
  scanTimeoutMs: number;
  chunkSize: number;
}

export interface ScanStreamOptions {
  scanTimeoutMs?: number;
}

export interface ClamAvParsedResponse {
  status: ClamAvScanStatus;
  signature: string | null;
  error: string | null;
  raw: string;
}

export interface ClamAvSignatureInfo {
  available: boolean;
  ageSeconds: number | null;
  version: string | null;
  dbVersion: number | null;
  dbDate: Date | null;
  error?: string;
}

export const DEFAULT_CLAMAV_CONFIG: ClamAvConfig = {
  host: '127.0.0.1',
  port: 3310,
  connectTimeoutMs: 5000,
  scanTimeoutMs: 60_000,
  chunkSize: 64 * 1024, // 64 KB
};

export const CHUNK_TERMINATOR: Buffer = Buffer.alloc(4, 0);
export const INSTREAM_COMMAND: Buffer = Buffer.from('zINSTREAM\0', 'latin1');
export const PING_COMMAND: Buffer = Buffer.from('PING\n', 'latin1');
export const VERSION_COMMAND: Buffer = Buffer.from('VERSION\n', 'latin1');

/**
 * Formats the 4-byte big-endian unsigned length header for a chunk.
 */
export function formatChunkHeader(length: number): Buffer {
  if (!Number.isInteger(length) || length < 0 || length > 0xffffffff) {
    throw new Error(`Invalid chunk length ${length}; must be an unsigned 32-bit integer`);
  }
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(length, 0);
  return buf;
}

/**
 * Deterministically parses a clamd response string into a typed result.
 * FAIL-CLOSED: ONLY exact 'stream: OK' produces 'CLEAN'.
 * Every other response produces 'FOUND' or 'ERROR'.
 */
export function parseClamAvResponse(rawInput: string): ClamAvParsedResponse {
  // Strip trailing null characters, newlines, and whitespace
  const raw = rawInput.replace(/\0+$/, '').trim();

  if (!raw) {
    return {
      status: 'ERROR',
      signature: null,
      error: 'Empty response received from clamd',
      raw: rawInput,
    };
  }

  // 1. Canonical clean check
  if (raw === 'stream: OK') {
    return {
      status: 'CLEAN',
      signature: null,
      error: null,
      raw,
    };
  }

  // 2. Malware signature detection: e.g. "stream: Eicar-Test-Signature FOUND"
  const foundMatch = /^stream:\s*(.+?)\s+FOUND$/i.exec(raw);
  if (foundMatch && foundMatch[1]) {
    return {
      status: 'FOUND',
      signature: foundMatch[1].trim(),
      error: null,
      raw,
    };
  }

  // 3. ClamAV error response: e.g. "stream: Size limit exceeded. ERROR" or "INSTREAM size limit exceeded. ERROR"
  const errorMatch = /^(?:stream:\s*)?(.+?)\s+ERROR$/i.exec(raw);
  if (errorMatch && errorMatch[1]) {
    return {
      status: 'ERROR',
      signature: null,
      error: errorMatch[1].trim(),
      raw,
    };
  }

  // 4. Any unexpected or unknown response is treated as fail-closed ERROR
  return {
    status: 'ERROR',
    signature: null,
    error: `Unrecognized response from clamd: '${raw}'`,
    raw,
  };
}

/**
 * Parses clamd VERSION response: e.g. "ClamAV 1.4.6/28136/Sun Sep 27 06:26:12 2026"
 */
export function parseClamAvVersion(rawInput: string): {
  version: string | null;
  dbVersion: number | null;
  dbDate: Date | null;
} {
  const raw = rawInput.replace(/\0+$/, '').trim();
  // Format: ClamAV <version>/<db_version>/<date_string>
  const match = /^ClamAV\s+([^/]+)(?:\/(\d+)\/(.+))?$/i.exec(raw);
  if (!match) {
    return { version: null, dbVersion: null, dbDate: null };
  }

  const version = match[1]?.trim() ?? null;
  const dbVersion = match[2] ? Number(match[2]) : null;
  let dbDate: Date | null = null;

  if (match[3]) {
    const parsed = new Date(match[3].trim());
    if (!Number.isNaN(parsed.getTime())) {
      dbDate = parsed;
    }
  }

  return { version, dbVersion, dbDate };
}

export class ClamAvScanner {
  readonly config: ClamAvConfig;

  constructor(customConfig?: Partial<ClamAvConfig>) {
    const envPort = process.env.CLAMAV_PORT ? Number(process.env.CLAMAV_PORT) : undefined;
    const envHost = process.env.CLAMAV_HOST || undefined;

    this.config = {
      host: customConfig?.host ?? envHost ?? DEFAULT_CLAMAV_CONFIG.host,
      port: customConfig?.port ?? envPort ?? DEFAULT_CLAMAV_CONFIG.port,
      connectTimeoutMs: customConfig?.connectTimeoutMs ?? DEFAULT_CLAMAV_CONFIG.connectTimeoutMs,
      scanTimeoutMs: customConfig?.scanTimeoutMs ?? DEFAULT_CLAMAV_CONFIG.scanTimeoutMs,
      chunkSize: customConfig?.chunkSize ?? DEFAULT_CLAMAV_CONFIG.chunkSize,
    };
  }

  /**
   * Healthcheck / connectivity probe using ClamAV PING command.
   */
  async ping(): Promise<boolean> {
    try {
      const response = await this.sendCommand(PING_COMMAND, 5000);
      return response.trim() === 'PONG';
    } catch {
      return false;
    }
  }

  /**
   * Queries clamd version and database metadata.
   */
  async version(): Promise<string> {
    return this.sendCommand(VERSION_COMMAND, 5000);
  }

  /**
   * Computes the age of the signature database in seconds.
   * If unavailable, returns available: false and ageSeconds: null (never silently 0).
   */
  async getSignatureAge(referenceTime = new Date()): Promise<ClamAvSignatureInfo> {
    try {
      const versionStr = await this.version();
      const { version, dbVersion, dbDate } = parseClamAvVersion(versionStr);

      if (!dbDate) {
        return {
          available: false,
          ageSeconds: null,
          version,
          dbVersion,
          dbDate: null,
          error: `Failed to parse database timestamp from version string '${versionStr}'`,
        };
      }

      const ageMs = referenceTime.getTime() - dbDate.getTime();
      const ageSeconds = Math.max(0, Math.floor(ageMs / 1000));

      return {
        available: true,
        ageSeconds,
        version,
        dbVersion,
        dbDate,
      };
    } catch (err) {
      return {
        available: false,
        ageSeconds: null,
        version: null,
        dbVersion: null,
        dbDate: null,
        error: (err as Error).message,
      };
    }
  }

  /**
   * Scans a readable stream using ClamAV's INSTREAM protocol.
   *
   * Security & resource guarantees:
   * - Does NOT buffer the complete stream in memory.
   * - Respects backpressure via socket drain events.
   * - Strict timeout enforcement.
   * - Guaranteed socket and timer cleanup.
   * - Fail-closed: errors, timeouts, and unknown responses never return CLEAN.
   */
  async scanStream(stream: Readable, options: ScanStreamOptions = {}): Promise<ClamAvScanResult> {
    const startTime = Date.now();
    const timeoutMs = options.scanTimeoutMs ?? this.config.scanTimeoutMs;

    return new Promise<ClamAvScanResult>((resolve) => {
      let resolved = false;
      let socket: net.Socket | null = null;
      let timeoutTimer: NodeJS.Timeout | null = null;
      let responseBuffer = '';

      const finalize = (result: ClamAvScanResult) => {
        if (resolved) return;
        resolved = true;

        if (timeoutTimer) {
          clearTimeout(timeoutTimer);
          timeoutTimer = null;
        }

        if (socket) {
          socket.removeAllListeners();
          if (!socket.destroyed) {
            socket.destroy();
          }
          socket = null;
        }

        resolve(result);
      };

      const failClosed = (errorMsg: string) => {
        finalize({
          status: 'ERROR',
          signature: null,
          durationMs: Date.now() - startTime,
          error: errorMsg,
        });
      };

      // Set overall scan timeout
      timeoutTimer = setTimeout(() => {
        failClosed(`ClamAV scan timed out after ${timeoutMs}ms`);
      }, timeoutMs);
      if (typeof timeoutTimer.unref === 'function') {
        timeoutTimer.unref();
      }

      // Establish TCP connection
      socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.config.connectTimeoutMs,
      });

      socket.on('timeout', () => {
        failClosed(
          `ClamAV connection timed out connecting to ${this.config.host}:${this.config.port}`,
        );
      });

      socket.on('error', (err: Error) => {
        failClosed(`ClamAV socket error: ${err.message}`);
      });

      socket.on('close', (hadError: boolean) => {
        if (!resolved) {
          if (responseBuffer.trim()) {
            const parsed = parseClamAvResponse(responseBuffer);
            finalize({
              status: parsed.status,
              signature: parsed.signature,
              rawResponse: parsed.raw,
              durationMs: Date.now() - startTime,
              error: parsed.error,
            });
          } else {
            failClosed(
              `ClamAV socket closed unexpectedly without sending response (hadError=${hadError})`,
            );
          }
        }
      });

      socket.on('data', (chunk: Buffer) => {
        responseBuffer += chunk.toString('utf8');
        // ClamAV responses terminate with '\0' or '\n'
        if (responseBuffer.includes('\0') || responseBuffer.includes('\n')) {
          const parsed = parseClamAvResponse(responseBuffer);
          finalize({
            status: parsed.status,
            signature: parsed.signature,
            rawResponse: parsed.raw,
            durationMs: Date.now() - startTime,
            error: parsed.error,
          });
        }
      });

      socket.on('connect', () => {
        if (!socket || resolved) return;

        // 1. Send INSTREAM command
        socket.write(INSTREAM_COMMAND, async (cmdErr?: Error | null) => {
          if (cmdErr || !socket || resolved) {
            if (cmdErr) failClosed(`Failed to send INSTREAM command: ${cmdErr.message}`);
            return;
          }

          try {
            // 2. Stream artifact chunks into clamd with backpressure control
            for await (const dataChunk of stream) {
              if (!socket || resolved) break;

              const buf = Buffer.isBuffer(dataChunk) ? dataChunk : Buffer.from(dataChunk);
              let offset = 0;
              const maxSlice = this.config.chunkSize;

              while (offset < buf.length && socket && !resolved) {
                const sliceEnd = Math.min(offset + maxSlice, buf.length);
                const slice = buf.subarray(offset, sliceEnd);
                offset = sliceEnd;

                const header = formatChunkHeader(slice.length);
                socket.write(header);
                const canWrite = socket.write(slice);

                if (!canWrite && socket && !resolved) {
                  await new Promise<void>((drainResolve) => {
                    const onDrain = () => {
                      cleanup();
                      drainResolve();
                    };
                    const onClose = () => {
                      cleanup();
                      drainResolve();
                    };
                    function cleanup() {
                      socket?.removeListener('drain', onDrain);
                      socket?.removeListener('close', onClose);
                      socket?.removeListener('error', onClose);
                    }
                    socket?.once('drain', onDrain);
                    socket?.once('close', onClose);
                    socket?.once('error', onClose);
                  });
                }
              }
            }

            if (socket && !resolved && !socket.destroyed) {
              // 3. Send 4-byte zero length chunk terminator
              socket.write(CHUNK_TERMINATOR, (termErr?: Error | null) => {
                if (termErr && !resolved) {
                  failClosed(`Failed to send chunk terminator: ${termErr.message}`);
                }
              });
            }
          } catch (streamErr: unknown) {
            if (!resolved) {
              const msg = streamErr instanceof Error ? streamErr.message : String(streamErr);
              failClosed(`Error in input artifact stream: ${msg}`);
            }
          }
        });
      });
    });
  }

  /**
   * Helper to execute simple one-line clamd commands (PING, VERSION).
   */
  private sendCommand(command: Buffer, timeoutMs: number): Promise<string> {
    return new Promise((resolve, reject) => {
      let resolved = false;
      const socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.config.connectTimeoutMs,
      });

      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          socket.destroy();
          reject(new Error(`Command timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();

      let response = '';

      socket.on('connect', () => {
        socket.write(command);
      });

      socket.on('data', (chunk: Buffer) => {
        response += chunk.toString('utf8');
      });

      socket.on('end', () => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          resolve(response.replace(/\0+$/, '').trim());
        }
      });

      socket.on('error', (err: Error) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          reject(err);
        }
      });

      socket.on('timeout', () => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          socket.destroy();
          reject(new Error(`Socket timeout connecting to ${this.config.host}:${this.config.port}`));
        }
      });
    });
  }
}
