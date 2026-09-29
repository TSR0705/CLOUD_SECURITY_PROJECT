import { describe, it, expect } from 'vitest';
import net from 'node:net';
import { Readable } from 'node:stream';
import {
  ClamAvScanner,
  formatChunkHeader,
  CHUNK_TERMINATOR,
  INSTREAM_COMMAND,
  PING_COMMAND,
  VERSION_COMMAND,
  parseClamAvResponse,
  parseClamAvVersion,
} from '@sug/scanner';

describe('ClamAV Scanner Unit Tests (P14)', () => {
  describe('Protocol Framing & Constants', () => {
    it('defines exact canonical commands and terminator', () => {
      expect(INSTREAM_COMMAND.toString('latin1')).toBe('zINSTREAM\0');
      expect(PING_COMMAND.toString('latin1')).toBe('PING\n');
      expect(VERSION_COMMAND.toString('latin1')).toBe('VERSION\n');
      expect(CHUNK_TERMINATOR.length).toBe(4);
      expect(CHUNK_TERMINATOR.readUInt32BE(0)).toBe(0);
    });

    it('encodes 4-byte big-endian unsigned chunk headers correctly', () => {
      const header0 = formatChunkHeader(0);
      expect(header0.readUInt32BE(0)).toBe(0);

      const header100 = formatChunkHeader(100);
      expect(header100.readUInt32BE(0)).toBe(100);

      const headerMax = formatChunkHeader(0xffffffff);
      expect(headerMax.readUInt32BE(0)).toBe(0xffffffff);
    });

    it('rejects invalid, negative, or non-integer chunk lengths', () => {
      expect(() => formatChunkHeader(-1)).toThrow(/unsigned 32-bit integer/);
      expect(() => formatChunkHeader(0x100000000)).toThrow(/unsigned 32-bit integer/);
      expect(() => formatChunkHeader(12.5)).toThrow(/unsigned 32-bit integer/);
      expect(() => formatChunkHeader(NaN)).toThrow(/unsigned 32-bit integer/);
    });
  });

  describe('Response Parser (Fail-Closed Invariant)', () => {
    it('parses canonical clean response as CLEAN', () => {
      const res1 = parseClamAvResponse('stream: OK');
      expect(res1.status).toBe('CLEAN');
      expect(res1.signature).toBeNull();
      expect(res1.error).toBeNull();

      // Handles trailing null or newline
      const res2 = parseClamAvResponse('stream: OK\0');
      expect(res2.status).toBe('CLEAN');

      const res3 = parseClamAvResponse('stream: OK\n');
      expect(res3.status).toBe('CLEAN');
    });

    it('parses malware detections as FOUND', () => {
      const res1 = parseClamAvResponse('stream: Eicar-Test-Signature FOUND');
      expect(res1.status).toBe('FOUND');
      expect(res1.signature).toBe('Eicar-Test-Signature');
      expect(res1.error).toBeNull();

      const res2 = parseClamAvResponse('stream: Win.Trojan.Agent-12345 FOUND\0');
      expect(res2.status).toBe('FOUND');
      expect(res2.signature).toBe('Win.Trojan.Agent-12345');

      const res3 = parseClamAvResponse('stream: Heuristics.Limits.Exceeded FOUND');
      expect(res3.status).toBe('FOUND');
      expect(res3.signature).toBe('Heuristics.Limits.Exceeded');
    });

    it('parses clamd ERROR responses as ERROR', () => {
      const res1 = parseClamAvResponse('stream: Size limit exceeded. ERROR');
      expect(res1.status).toBe('ERROR');
      expect(res1.error).toBe('Size limit exceeded.');
      expect(res1.signature).toBeNull();

      const res2 = parseClamAvResponse('stream: Parse error ERROR\0');
      expect(res2.status).toBe('ERROR');
      expect(res2.error).toBe('Parse error');
    });

    it('treats empty, malformed, or unknown responses as fail-closed ERROR', () => {
      const resEmpty = parseClamAvResponse('');
      expect(resEmpty.status).toBe('ERROR');

      const resWhitespace = parseClamAvResponse('   \0\n  ');
      expect(resWhitespace.status).toBe('ERROR');

      const resUnknown = parseClamAvResponse('UNKNOWN_PROTOCOL_RESPONSE');
      expect(resUnknown.status).toBe('ERROR');
      expect(resUnknown.error).toMatch(/Unrecognized response/);

      // Partial or typo responses must never be clean
      const resTypo = parseClamAvResponse('stream: OKAY');
      expect(resTypo.status).toBe('ERROR');
    });
  });

  describe('Version & Signature Age Parsing', () => {
    it('parses canonical ClamAV VERSION response string', () => {
      const parsed = parseClamAvVersion('ClamAV 1.4.6/28136/Sun Sep 27 06:26:12 2026\0');
      expect(parsed.version).toBe('1.4.6');
      expect(parsed.dbVersion).toBe(28136);
      expect(parsed.dbDate).toBeInstanceOf(Date);
      expect(parsed.dbDate?.getUTCFullYear()).toBe(2026);
    });

    it('handles version string without database metadata gracefully', () => {
      const parsed = parseClamAvVersion('ClamAV 1.4.6');
      expect(parsed.version).toBe('1.4.6');
      expect(parsed.dbVersion).toBeNull();
      expect(parsed.dbDate).toBeNull();
    });

    it('handles malformed version string without throwing', () => {
      const parsed = parseClamAvVersion('INVALID_VERSION_OUTPUT');
      expect(parsed.version).toBeNull();
      expect(parsed.dbVersion).toBeNull();
      expect(parsed.dbDate).toBeNull();
    });
  });

  describe('Mock TCP Server Protocol Simulation', () => {
    let server: net.Server;
    let serverPort: number;
    let activeSockets: net.Socket[] = [];

    const createMockServer = (handler: (socket: net.Socket) => void): Promise<number> => {
      activeSockets = [];
      return new Promise((resolve) => {
        server = net.createServer((sock) => {
          activeSockets.push(sock);
          sock.on('close', () => {
            activeSockets = activeSockets.filter((s) => s !== sock);
          });
          handler(sock);
        });
        server.listen(0, '127.0.0.1', () => {
          const addr = server.address() as net.AddressInfo;
          serverPort = addr.port;
          resolve(serverPort);
        });
      });
    };

    const closeMockServer = async () => {
      for (const sock of activeSockets) {
        sock.destroy();
      }
      activeSockets = [];
      await new Promise<void>((r) => server.close(() => r()));
    };

    it('handles clean stream scan over INSTREAM', async () => {
      await createMockServer((socket) => {
        let received = Buffer.alloc(0);
        socket.on('data', (chunk) => {
          received = Buffer.concat([received, chunk]);
          // If chunk terminator (4 zero bytes) received, respond OK
          if (
            received.length >= 14 &&
            received.subarray(received.length - 4).equals(CHUNK_TERMINATOR)
          ) {
            socket.write('stream: OK\0');
            socket.end();
          }
        });
      });

      const scanner = new ClamAvScanner({ port: serverPort, host: '127.0.0.1' });
      const stream = Readable.from([Buffer.from('Clean payload test content')]);

      const result = await scanner.scanStream(stream);
      expect(result.status).toBe('CLEAN');
      expect(result.signature).toBeNull();
      expect(result.error).toBeNull();

      await closeMockServer();
    });

    it('handles malware detection over INSTREAM', async () => {
      await createMockServer((socket) => {
        let received = Buffer.alloc(0);
        socket.on('data', (chunk) => {
          received = Buffer.concat([received, chunk]);
          if (
            received.length >= 14 &&
            received.subarray(received.length - 4).equals(CHUNK_TERMINATOR)
          ) {
            socket.write('stream: Simulated-Virus.Test FOUND\0');
            socket.end();
          }
        });
      });

      const scanner = new ClamAvScanner({ port: serverPort, host: '127.0.0.1' });
      const stream = Readable.from([Buffer.from('Infected simulated content')]);

      const result = await scanner.scanStream(stream);
      expect(result.status).toBe('FOUND');
      expect(result.signature).toBe('Simulated-Virus.Test');
      expect(result.error).toBeNull();

      await closeMockServer();
    });

    it('fails closed on mid-scan connection reset (server crash)', async () => {
      await createMockServer((socket) => {
        socket.on('data', () => {
          // Immediately destroy socket simulating server crash/SIGKILL
          socket.destroy();
        });
      });

      const scanner = new ClamAvScanner({ port: serverPort, host: '127.0.0.1' });
      const stream = Readable.from([Buffer.from('Some stream content that gets interrupted')]);

      const result = await scanner.scanStream(stream);
      expect(result.status).toBe('ERROR');
      expect(result.error).toBeDefined();

      await closeMockServer();
    });

    it('fails closed on scan timeout', async () => {
      await createMockServer(() => {
        // Do not respond at all
      });

      const scanner = new ClamAvScanner({
        port: serverPort,
        host: '127.0.0.1',
        scanTimeoutMs: 100, // 100ms test timeout
      });
      const stream = Readable.from([Buffer.from('Hanging scan content')]);

      const result = await scanner.scanStream(stream);
      expect(result.status).toBe('ERROR');
      expect(result.error).toMatch(/timed out/);

      await closeMockServer();
    });

    it('fails closed when clamd port is unavailable (connection refused)', async () => {
      // Pick a port where no server is listening
      const scanner = new ClamAvScanner({
        port: 65432,
        host: '127.0.0.1',
        connectTimeoutMs: 500,
      });
      const stream = Readable.from([Buffer.from('Test content')]);

      const result = await scanner.scanStream(stream);
      expect(result.status).toBe('ERROR');
      expect(result.error).toMatch(/ECONNREFUSED|connect/i);
    });

    it('calculates signature age correctly via getSignatureAge', async () => {
      await createMockServer((socket) => {
        socket.on('data', (d) => {
          if (d.toString().startsWith('VERSION')) {
            socket.write('ClamAV 1.4.6/28136/Sun Sep 27 06:26:12 2026\0');
            socket.end();
          }
        });
      });

      const scanner = new ClamAvScanner({ port: serverPort, host: '127.0.0.1' });
      const refTime = new Date('2026-09-29T16:00:00Z');
      const sigInfo = await scanner.getSignatureAge(refTime);

      expect(sigInfo.available).toBe(true);
      expect(sigInfo.version).toBe('1.4.6');
      expect(sigInfo.dbVersion).toBe(28136);
      expect(sigInfo.ageSeconds).toBeGreaterThan(0);

      await closeMockServer();
    });

    it('returns available: false (never 0) if getSignatureAge fails', async () => {
      const scanner = new ClamAvScanner({ port: 65431, host: '127.0.0.1' });
      const sigInfo = await scanner.getSignatureAge();

      expect(sigInfo.available).toBe(false);
      expect(sigInfo.ageSeconds).toBeNull();
      expect(sigInfo.error).toBeDefined();
    });
  });
});
