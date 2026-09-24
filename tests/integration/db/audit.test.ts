import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import crypto from 'node:crypto';
import type pg from 'pg';
import { createPool } from './helpers.js';
import { verifyAuditChain, type AuditRecord } from '@sug/audit';

describe('Audit Event Hash Chain & Concurrency (DB-08, DB-09, DB-10, Tamper)', () => {
  let pool: pg.Pool;

  beforeAll(async () => {
    pool = createPool('sug_admin', 'sug_dev_password', 25);
  });

  afterAll(async () => {
    await pool.end();
  });

  it('DB-08: First audit event has 32-byte zero previous hash', async () => {
    // Inspect the very first audit event in the database (seq = 1)
    const firstRes = await pool.query<AuditRecord>(
      'SELECT * FROM audit_events ORDER BY seq ASC LIMIT 1',
    );

    if (firstRes.rows.length === 0) {
      // If table empty, append one event
      await pool.query(
        `SELECT audit_append('service', 'test_setup', 'FIRST_EVENT', '{}'::jsonb, '{}'::jsonb)`,
      );
    }

    const rootRes = await pool.query<AuditRecord>(
      'SELECT * FROM audit_events ORDER BY seq ASC LIMIT 1',
    );
    const root = rootRes.rows[0];
    expect(root).toBeDefined();
    expect(root.seq).toBeDefined();

    const zeroBuf = Buffer.alloc(32, 0);
    expect(Buffer.isBuffer(root.prev_hash)).toBe(true);
    expect(root.prev_hash.length).toBe(32);
    expect(root.prev_hash.equals(zeroBuf)).toBe(true);
  });

  it('DB-09: Second audit event links to first event hash', async () => {
    // Append two consecutive events
    const s1 = await pool.query<{ seq: string }>(
      `SELECT audit_append('service', 'test_worker', 'CHAIN_TEST_1', '{}'::jsonb, '{"step": 1}'::jsonb) as seq`,
    );
    const seq1 = s1.rows[0].seq;

    const s2 = await pool.query<{ seq: string }>(
      `SELECT audit_append('service', 'test_worker', 'CHAIN_TEST_2', '{}'::jsonb, '{"step": 2}'::jsonb) as seq`,
    );
    const seq2 = s2.rows[0].seq;

    const events = await pool.query<AuditRecord>(
      'SELECT * FROM audit_events WHERE seq IN ($1, $2) ORDER BY seq ASC',
      [seq1, seq2],
    );

    expect(events.rows.length).toBe(2);
    const e1 = events.rows[0];
    const e2 = events.rows[1];

    expect(Buffer.isBuffer(e1.event_hash)).toBe(true);
    expect(Buffer.isBuffer(e2.prev_hash)).toBe(true);
    expect(e2.prev_hash.equals(e1.event_hash)).toBe(true);
  });

  it('DB-10: 1,000 concurrent audit_append calls produce an unbroken chain', async () => {
    const BATCH_SIZE = 1000;
    const testTag = `batch_${Date.now()}`;

    // Execute 1,000 concurrent audit_append invocations across connection pool
    const promises: Promise<pg.QueryResult<{ seq: string }>>[] = [];
    for (let i = 0; i < BATCH_SIZE; i++) {
      promises.push(
        pool.query(
          `SELECT audit_append('service', 'load_tester', 'CONCURRENT_STRESS', '{}'::jsonb, $1::jsonb) as seq`,
          [JSON.stringify({ tag: testTag, idx: i })],
        ),
      );
    }

    const results = await Promise.all(promises);
    expect(results.length).toBe(BATCH_SIZE);

    const insertedSeqs = results.map((r) => BigInt(r.rows[0].seq)).sort((a, b) => (a < b ? -1 : 1));
    const minSeq = insertedSeqs[0].toString();
    const maxSeq = insertedSeqs[insertedSeqs.length - 1].toString();

    // Fetch all events in this range
    const fetched = await pool.query<AuditRecord>(
      `SELECT * FROM audit_events WHERE seq >= $1 AND seq <= $2 ORDER BY seq ASC`,
      [minSeq, maxSeq],
    );

    expect(fetched.rows.length).toBeGreaterThanOrEqual(BATCH_SIZE);
    const tagEvents = fetched.rows.filter((r) => (r.details as { tag?: string })?.tag === testTag);
    expect(tagEvents.length).toBe(BATCH_SIZE);

    // Verify every single event links perfectly to its predecessor across the entire range
    for (let i = 1; i < fetched.rows.length; i++) {
      const prev = fetched.rows[i - 1];
      const curr = fetched.rows[i];

      expect(BigInt(curr.seq)).toBe(BigInt(prev.seq) + 1n);
      expect(curr.prev_hash.equals(prev.event_hash)).toBe(true);
    }
  }, 30000); // 30s timeout for 1000 concurrent DB transactions

  describe('Audit Chain Tamper Detection', () => {
    it('verifyAuditChain validates an unbroken audit chain slice', async () => {
      const rows = await pool.query<AuditRecord>(
        'SELECT * FROM audit_events ORDER BY seq ASC LIMIT 200',
      );
      const result = verifyAuditChain(rows.rows);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.verifiedCount).toBe(rows.rows.length);
        expect(result.headHash).toBe(rows.rows[rows.rows.length - 1].event_hash.toString('hex'));
      }
    });

    it('detects in-memory hash modification at the exact sequence number', async () => {
      const rows = await pool.query<AuditRecord>(
        'SELECT * FROM audit_events ORDER BY seq ASC LIMIT 20',
      );
      expect(rows.rows.length).toBeGreaterThanOrEqual(10);

      // Clone events
      const tampered: AuditRecord[] = rows.rows.map((r) => ({
        ...r,
        prev_hash: Buffer.from(r.prev_hash),
        event_hash: Buffer.from(r.event_hash),
      }));

      // Tamper event_hash at index 5
      const tamperedIndex = 5;
      tampered[tamperedIndex].event_hash[0] ^= 0xff; // Flip bits

      const verifyRes = verifyAuditChain(tampered);
      expect(verifyRes.valid).toBe(false);
      if (!verifyRes.valid) {
        // Next sequence should fail because its prev_hash doesn't match the tampered hash
        expect(verifyRes.failedSeq.toString()).toBe(tampered[tamperedIndex + 1].seq.toString());
        expect(verifyRes.error).toContain('Hash chain broken');
      }
    });

    it('detects root zero-hash violation', async () => {
      const rows = await pool.query<AuditRecord>(
        'SELECT * FROM audit_events ORDER BY seq ASC LIMIT 5',
      );

      const tampered: AuditRecord[] = rows.rows.map((r) => ({
        ...r,
        prev_hash: Buffer.from(r.prev_hash),
        event_hash: Buffer.from(r.event_hash),
      }));

      // Corrupt root prev_hash
      tampered[0].prev_hash[0] = 0x01;

      const verifyRes = verifyAuditChain(tampered);
      expect(verifyRes.valid).toBe(false);
      if (!verifyRes.valid) {
        expect(verifyRes.failedSeq.toString()).toBe(tampered[0].seq.toString());
        expect(verifyRes.error).toContain('Root event');
      }
    });

    it('detects database-level data tampering', async () => {
      // Create a specific record to tamper
      const res = await pool.query<{ seq: string }>(
        `SELECT audit_append('service', 'tamper_target', 'PRE_TAMPER', '{}'::jsonb, '{}'::jsonb) as seq`,
      );
      const targetSeq = res.rows[0].seq;

      // Append one more event so target is an interior link
      await pool.query(
        `SELECT audit_append('service', 'tamper_follower', 'POST_TAMPER', '{}'::jsonb, '{}'::jsonb)`,
      );

      // Superuser bypasses trigger temporarily to simulate an adversary tampering with the database
      const client = await pool.connect();
      try {
        await client.query('ALTER TABLE audit_events DISABLE TRIGGER ALL');
        const tamperedHash = crypto.randomBytes(32);
        await client.query(
          `UPDATE audit_events
           SET event_hash = $1
           WHERE seq = $2`,
          [tamperedHash, targetSeq],
        );
        await client.query('ALTER TABLE audit_events ENABLE TRIGGER ALL');

        // Fetch events around the target
        const auditSlice = await pool.query<AuditRecord>(
          `SELECT * FROM audit_events
           WHERE seq >= ($1::bigint - 2) AND seq <= ($1::bigint + 2)
           ORDER BY seq ASC`,
          [targetSeq],
        );

        // Verification fails at the row following targetSeq
        const nextSeq = (BigInt(targetSeq) + 1n).toString();
        const verification = verifyAuditChain(auditSlice.rows);

        // Note: because auditSlice doesn't start at seq=1, verifyAuditChain on a non-root slice
        // checks prev_hash from the first element in slice onwards
        expect(verification.valid).toBe(false);
        if (!verification.valid) {
          expect(verification.failedSeq.toString()).toBe(nextSeq);
        }
      } finally {
        // Restore table state and trigger in case of failure
        await client.query('ALTER TABLE audit_events ENABLE TRIGGER ALL');
        client.release();
      }
    });
  });
});
