import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  verifyAuditChain,
  computeEventHash,
  formatCanonicalRefs,
  formatCanonicalDetails,
  type AuditRecord,
} from '../../../packages/audit/src/index.js';

describe('packages/audit - verifyAuditChain (Unit)', () => {
  const zeroHash = Buffer.alloc(32, 0);

  function createTestEvent(
    seq: number,
    prevHash: Buffer,
    overrides: Partial<AuditRecord> = {},
  ): AuditRecord {
    const actorType = overrides.actor_type ?? 'service';
    const actorId = overrides.actor_id ?? 'test_worker';
    const action = overrides.action ?? 'TEST_ACTION';
    const occurredAtText = overrides.occurred_at_text ?? '2026-10-19 06:00:00.123456+00';
    const details = overrides.details ?? { test: true };
    const refs = {
      application_id: overrides.application_id ?? null,
      file_id: overrides.file_id ?? null,
      file_version_id: overrides.file_version_id ?? null,
      decision_id: overrides.decision_id ?? null,
      request_id: overrides.request_id ?? null,
      ip: overrides.ip ?? null,
    };
    const canonicalRefs = formatCanonicalRefs(refs);
    const canonicalDetails = formatCanonicalDetails(details);

    const eventHash = computeEventHash({
      prevHash,
      actorType,
      actorId,
      action,
      occurredAtText,
      refsText: canonicalRefs,
      detailsText: canonicalDetails,
    });

    return {
      seq: BigInt(seq),
      id: crypto.randomUUID(),
      occurred_at: new Date('2026-10-19T06:00:00.123Z'),
      actor_type: actorType,
      actor_id: actorId,
      action,
      details,
      prev_hash: prevHash,
      event_hash: overrides.event_hash ?? eventHash,
      occurred_at_text: occurredAtText,
      canonical_refs: canonicalRefs,
      canonical_details: canonicalDetails,
      ...overrides,
    };
  }

  it('verifies empty chain as valid with zero count', () => {
    const res = verifyAuditChain([]);
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.verifiedCount).toBe(0);
      expect(res.headHash).toBe('00'.repeat(32));
    }
  });

  it('verifies valid genesis event at seq 1 with zero prev_hash', () => {
    const root = createTestEvent(1, zeroHash);
    const res = verifyAuditChain([root]);
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.verifiedCount).toBe(1);
      expect(res.headHash).toBe(root.event_hash.toString('hex'));
      expect(res.fromSeq).toBe(1n);
      expect(res.toSeq).toBe(1n);
    }
  });

  it('rejects genesis event with non-zero prev_hash', () => {
    const nonZeroPrev = Buffer.alloc(32, 1);
    const root = createTestEvent(1, nonZeroPrev);
    const res = verifyAuditChain([root]);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.failureCategory).toBe('GENESIS_VIOLATION');
      expect(res.failedSeq).toBe(1n);
      expect(res.error).toContain('Root event at seq 1 must have zero prev_hash');
    }
  });

  it('rejects requireRootAtStart when first event seq is not 1', () => {
    const evt = createTestEvent(5, zeroHash);
    const res = verifyAuditChain([evt], { requireRootAtStart: true });
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.failureCategory).toBe('GENESIS_VIOLATION');
      expect(res.failedSeq).toBe(5n);
      expect(res.error).toContain('First event must be sequence 1, got 5');
    }
  });

  it('verifies multi-event valid chain completely', () => {
    const e1 = createTestEvent(1, zeroHash);
    const e2 = createTestEvent(2, e1.event_hash);
    const e3 = createTestEvent(3, e2.event_hash);
    const res = verifyAuditChain([e1, e2, e3]);
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.verifiedCount).toBe(3);
      expect(res.headHash).toBe(e3.event_hash.toString('hex'));
      expect(res.fromSeq).toBe(1n);
      expect(res.toSeq).toBe(3n);
    }
  });

  it('accepts legitimate PostgreSQL identity sequence gaps caused by aborted transactions', () => {
    // E.g., transaction seq 2 rolled back, so seq jumps from 1 to 3, but prev_hash links to 1
    const e1 = createTestEvent(1, zeroHash);
    const e3 = createTestEvent(3, e1.event_hash);
    const e7 = createTestEvent(7, e3.event_hash);

    const res = verifyAuditChain([e1, e3, e7]);
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.verifiedCount).toBe(3);
      expect(res.headHash).toBe(e7.event_hash.toString('hex'));
    }
  });

  it('rejects non-monotonic sequence ordering (currSeq <= prevSeq)', () => {
    const e1 = createTestEvent(1, zeroHash);
    const e2 = createTestEvent(1, e1.event_hash); // duplicate sequence number

    const res = verifyAuditChain([e1, e2]);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.failureCategory).toBe('SEQUENCE_VIOLATION');
      expect(res.failedSeq).toBe(1n);
      expect(res.error).toContain('Non-monotonic sequence order');
    }
  });

  it('rejects decreasing sequence order', () => {
    const e1 = createTestEvent(5, zeroHash);
    const e2 = createTestEvent(4, e1.event_hash);

    const res = verifyAuditChain([e1, e2]);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.failureCategory).toBe('SEQUENCE_VIOLATION');
      expect(res.failedSeq).toBe(4n);
    }
  });

  it('detects broken hash chain link at the exact sequence number', () => {
    const e1 = createTestEvent(1, zeroHash);
    const e2 = createTestEvent(2, e1.event_hash);
    const wrongPrev = Buffer.alloc(32, 0xaa);
    const e3 = createTestEvent(3, wrongPrev);

    const res = verifyAuditChain([e1, e2, e3]);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.failureCategory).toBe('CHAIN_BROKEN');
      expect(res.failedSeq).toBe(3n);
      expect(res.error).toContain('Hash chain broken at seq 3');
    }
  });

  it('detects payload tampering when event_hash was not updated', () => {
    const e1 = createTestEvent(1, zeroHash);
    const e2 = createTestEvent(2, e1.event_hash);

    // Tamper with e2's details without updating event_hash
    const tamperedE2: AuditRecord = {
      ...e2,
      canonical_details: '{"tampered": true}',
    };

    const res = verifyAuditChain([e1, tamperedE2]);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.failureCategory).toBe('HASH_MISMATCH');
      expect(res.failedSeq).toBe(2n);
      expect(res.error).toContain('Event hash mismatch at seq 2');
    }
  });

  it('detects actor_id tampering', () => {
    const e1 = createTestEvent(1, zeroHash);
    const tamperedE1: AuditRecord = {
      ...e1,
      actor_id: 'malicious_impersonator',
    };

    const res = verifyAuditChain([tamperedE1]);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.failureCategory).toBe('HASH_MISMATCH');
      expect(res.failedSeq).toBe(1n);
    }
  });

  it('detects malformed hash lengths', () => {
    const shortPrev = Buffer.alloc(16, 0);
    const e1 = createTestEvent(1, shortPrev);
    const res = verifyAuditChain([e1]);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.failureCategory).toBe('MALFORMED_RECORD');
      expect(res.error).toContain('Invalid prev_hash length');
    }

    const shortHash = Buffer.alloc(16, 1);
    const e2 = createTestEvent(1, zeroHash, { event_hash: shortHash });
    const res2 = verifyAuditChain([e2]);
    expect(res2.valid).toBe(false);
    if (!res2.valid) {
      expect(res2.failureCategory).toBe('MALFORMED_RECORD');
      expect(res2.error).toContain('Invalid event_hash length');
    }
  });

  it('verifies non-root chain slice using expectedPredecessorHash', () => {
    const e1 = createTestEvent(1, zeroHash);
    const e2 = createTestEvent(2, e1.event_hash);
    const e3 = createTestEvent(3, e2.event_hash);

    // Verify slice [e2, e3] given e1's event_hash
    const res = verifyAuditChain([e2, e3], {
      expectedPredecessorHash: e1.event_hash,
    });
    expect(res.valid).toBe(true);

    // Verify slice with wrong predecessor hash fails
    const wrongPred = Buffer.alloc(32, 0xff);
    const resFail = verifyAuditChain([e2, e3], {
      expectedPredecessorHash: wrongPred,
    });
    expect(resFail.valid).toBe(false);
    if (!resFail.valid) {
      expect(resFail.failureCategory).toBe('CHAIN_BROKEN');
      expect(resFail.failedSeq).toBe(2n);
    }
  });
});
