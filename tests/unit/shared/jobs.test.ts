import { describe, it, expect } from 'vitest';
import { calculateBackoff, generateWorkerId } from '@sug/shared/jobs';

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
});
