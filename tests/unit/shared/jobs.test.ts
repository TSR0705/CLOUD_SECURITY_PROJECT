import { describe, it, expect } from 'vitest';
import {
  calculateBackoff,
  generateWorkerId,
  DEFAULT_LEASE_TIMEOUT_MS,
  DEFAULT_REAPER_INTERVAL_MS,
  MAX_REAPER_INTERVAL_MS,
  CANONICAL_RECOVERY_SLA_MS,
  validateReaperInterval,
  validateRecoveryBound,
} from '@sug/shared/jobs';
import { ScannerWorker } from '../../../services/scanner/src/worker.js';
import type { DatabaseExecutor } from '@sug/shared';
import type { StorageProvider } from '@sug/storage';

const mockDb: DatabaseExecutor = {
  query: async () => ({ rows: [], rowCount: 0 }),
};

const mockStorage = {} as unknown as StorageProvider;

describe('Job Queue Unit Tests (P13)', () => {
  describe('calculateBackoff', () => {
    it('returns 0 for attempt 0 or negative', () => {
      expect(calculateBackoff(0)).toBe(0);
      expect(calculateBackoff(-1)).toBe(0);
    });

    it('calculates deterministic exponential backoff', () => {
      // baseMs = 1000, maxMs = 60000
      expect(calculateBackoff(1, 1000, 60_000)).toBe(1000); // 1000 * 2^0
      expect(calculateBackoff(2, 1000, 60_000)).toBe(2000); // 1000 * 2^1
      expect(calculateBackoff(3, 1000, 60_000)).toBe(4000); // 1000 * 2^2
      expect(calculateBackoff(4, 1000, 60_000)).toBe(8000); // 1000 * 2^3
      expect(calculateBackoff(5, 1000, 60_000)).toBe(16000); // 1000 * 2^4
      expect(calculateBackoff(6, 1000, 60_000)).toBe(32000); // 1000 * 2^5
      expect(calculateBackoff(7, 1000, 60_000)).toBe(60000); // capped at maxMs
      expect(calculateBackoff(10, 1000, 60_000)).toBe(60000);
    });

    it('respects custom base and max backoff', () => {
      expect(calculateBackoff(1, 500, 5000)).toBe(500);
      expect(calculateBackoff(2, 500, 5000)).toBe(1000);
      expect(calculateBackoff(3, 500, 5000)).toBe(2000);
      expect(calculateBackoff(4, 500, 5000)).toBe(4000);
      expect(calculateBackoff(5, 500, 5000)).toBe(5000); // capped
    });
  });

  describe('generateWorkerId', () => {
    it('generates a descriptive unique worker identifier', () => {
      const id1 = generateWorkerId();
      const id2 = generateWorkerId();

      expect(id1).toMatch(/^scanner-worker-[a-zA-Z0-9_-]+-\d+-[a-f0-9]{8}$/);
      expect(id2).toMatch(/^scanner-worker-[a-zA-Z0-9_-]+-\d+-[a-f0-9]{8}$/);
      expect(id1).not.toBe(id2);
    });

    it('supports custom prefix', () => {
      const id = generateWorkerId('test-worker');
      expect(id.startsWith('test-worker-')).toBe(true);
    });
  });

  describe('Canonical P13 Timing Bounds & Invariants', () => {
    it('defines exact canonical constants', () => {
      expect(DEFAULT_LEASE_TIMEOUT_MS).toBe(240_000); // 240 seconds
      expect(DEFAULT_REAPER_INTERVAL_MS).toBe(30_000); // 30 seconds
      expect(MAX_REAPER_INTERVAL_MS).toBe(30_000); // 30 seconds
      expect(CANONICAL_RECOVERY_SLA_MS).toBe(300_000); // 300 seconds (5 min)
    });

    it('satisfies mathematical recovery bound with 30s safety margin', () => {
      const worstCaseRecovery = DEFAULT_LEASE_TIMEOUT_MS + DEFAULT_REAPER_INTERVAL_MS;
      expect(worstCaseRecovery).toBe(270_000); // 270 seconds
      expect(worstCaseRecovery).toBeLessThanOrEqual(CANONICAL_RECOVERY_SLA_MS);
      expect(CANONICAL_RECOVERY_SLA_MS - worstCaseRecovery).toBe(30_000); // 30s margin
    });
  });

  describe('validateReaperInterval', () => {
    it('accepts valid reaper intervals <= 30_000ms', () => {
      expect(() => validateReaperInterval(1)).not.toThrow();
      expect(() => validateReaperInterval(10_000)).not.toThrow();
      expect(() => validateReaperInterval(30_000)).not.toThrow();
    });

    it('rejects reaper intervals exceeding MAX_REAPER_INTERVAL_MS (30_000ms)', () => {
      expect(() => validateReaperInterval(30_001)).toThrow(
        /exceeds maximum allowed threshold of 30000ms/,
      );
      expect(() => validateReaperInterval(60_000)).toThrow(
        /exceeds maximum allowed threshold of 30000ms/,
      );
    });

    it('rejects non-positive, NaN, or non-integer intervals', () => {
      expect(() => validateReaperInterval(0)).toThrow(/positive integer/);
      expect(() => validateReaperInterval(-100)).toThrow(/positive integer/);
      expect(() => validateReaperInterval(NaN)).toThrow(/positive integer/);
      expect(() => validateReaperInterval(15.5)).toThrow(/positive integer/);
    });
  });

  describe('validateRecoveryBound', () => {
    it('accepts valid configurations satisfying 300s SLA', () => {
      expect(() => validateRecoveryBound(240_000, 30_000)).not.toThrow();
      expect(() => validateRecoveryBound(200_000, 20_000)).not.toThrow();
      expect(() => validateRecoveryBound(200, 50)).not.toThrow();
    });

    it('rejects configurations where lease + reaper exceeds 300s SLA', () => {
      expect(() => validateRecoveryBound(280_000, 30_000)).toThrow(
        /exceeds canonical P13 maximum of 300000ms/,
      );
      expect(() => validateRecoveryBound(290_000, 20_000)).toThrow(
        /exceeds canonical P13 maximum of 300000ms/,
      );
    });

    it('rejects non-positive or non-integer lease timeouts', () => {
      expect(() => validateRecoveryBound(0, 10_000)).toThrow(/positive integer/);
      expect(() => validateRecoveryBound(-500, 10_000)).toThrow(/positive integer/);
      expect(() => validateRecoveryBound(NaN, 10_000)).toThrow(/positive integer/);
      expect(() => validateRecoveryBound(100.5, 10_000)).toThrow(/positive integer/);
    });
  });

  describe('ScannerWorker Configuration Validation', () => {
    it('instantiates successfully with default settings (240s lease, 30s reaper)', () => {
      const worker = new ScannerWorker({
        db: mockDb,
        storageProvider: mockStorage,
      });

      expect(worker.leaseTimeoutMs).toBe(240_000);
      expect(worker.reaperIntervalMs).toBe(30_000);
      expect(worker.leaseTimeoutMs + worker.reaperIntervalMs).toBe(270_000);
    });

    it('instantiates successfully with valid custom parameters', () => {
      const worker = new ScannerWorker({
        db: mockDb,
        storageProvider: mockStorage,
        leaseTimeoutMs: 200,
        reaperIntervalMs: 50,
      });

      expect(worker.leaseTimeoutMs).toBe(200);
      expect(worker.reaperIntervalMs).toBe(50);
    });

    it('rejects reaperIntervalMs exceeding 30_000ms', () => {
      expect(
        () =>
          new ScannerWorker({
            db: mockDb,
            storageProvider: mockStorage,
            reaperIntervalMs: 30_001,
          }),
      ).toThrow(/exceeds maximum allowed threshold of 30000ms/);

      expect(
        () =>
          new ScannerWorker({
            db: mockDb,
            storageProvider: mockStorage,
            reaperIntervalMs: 60_000,
          }),
      ).toThrow(/exceeds maximum allowed threshold of 30000ms/);
    });

    it('rejects configuration violating the canonical 300s recovery SLA', () => {
      expect(
        () =>
          new ScannerWorker({
            db: mockDb,
            storageProvider: mockStorage,
            leaseTimeoutMs: 280_000,
            reaperIntervalMs: 30_000,
          }),
      ).toThrow(/exceeds canonical P13 maximum of 300000ms/);
    });
  });
});
