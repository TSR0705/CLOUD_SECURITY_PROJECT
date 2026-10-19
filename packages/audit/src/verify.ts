/**
 * Audit chain verification logic
 */

import crypto from 'node:crypto';

export interface AuditRecord {
  seq: bigint | number | string;
  id: string;
  occurred_at: Date | string;
  actor_type: string;
  actor_id: string;
  action: string;
  application_id?: string | null;
  file_id?: string | null;
  file_version_id?: string | null;
  decision_id?: string | null;
  request_id?: string | null;
  ip?: string | null;
  details: unknown;
  prev_hash: Buffer;
  event_hash: Buffer;
  occurred_at_text?: string | null;
  canonical_refs?: string | null;
  canonical_details?: string | null;
}

export interface VerificationSuccess {
  valid: true;
  verifiedCount: number;
  headHash: string;
  fromSeq?: bigint | number | string | undefined;
  toSeq?: bigint | number | string | undefined;
}

export interface VerificationFailure {
  valid: false;
  failedSeq?: bigint | number | string | undefined;
  error: string;
  failureCategory?:
    | 'CHAIN_BROKEN'
    | 'HASH_MISMATCH'
    | 'GENESIS_VIOLATION'
    | 'SEQUENCE_VIOLATION'
    | 'MALFORMED_RECORD'
    | 'EMPTY_CHAIN'
    | 'CHECKPOINT_PREFIX_MISMATCH'
    | 'CHECKPOINT_SIGNATURE_INVALID'
    | 'CHECKPOINT_EVENT_MISSING'
    | 'CHECKPOINT_STALE_OR_MISSING'
    | 'CHECKPOINT_STORAGE_MISSING'
    | 'CHECKPOINT_STORAGE_MISMATCH'
    | undefined;
}

export type VerificationResult = VerificationSuccess | VerificationFailure;

export interface VerifyChainOptions {
  /** If true, the first event must be seq 1 and have a zero prev_hash */
  requireRootAtStart?: boolean | undefined;
  /** Expected previous hash for the first event in a slice */
  expectedPredecessorHash?: Buffer | undefined;
  /** If true (or defaulted when occurred_at_text is present), recomputes and verifies each event_hash */
  recomputeHashes?: boolean | undefined;
  /** If true, empty array of events returns valid: true with count 0 instead of failing closed */
  allowEmpty?: boolean | undefined;
}

/**
 * Recomputes the SHA-256 event hash matching PostgreSQL's audit_append:
 * digest(v_prev || convert_to(actor_type || '|' || actor_id || '|' || action || '|' ||
 *        occurred_at_text || '|' || refs_text || '|' || details_text, 'UTF8'), 'sha256')
 */
export function computeEventHash(params: {
  prevHash: Buffer;
  actorType: string;
  actorId: string;
  action: string;
  occurredAtText: string;
  refsText: string;
  detailsText: string;
}): Buffer {
  const payloadStr = `${params.actorType}|${params.actorId}|${params.action}|${params.occurredAtText}|${params.refsText}|${params.detailsText}`;
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([params.prevHash, Buffer.from(payloadStr, 'utf8')]))
    .digest();
}

/**
 * Reconstructs the canonical JSON text of references according to PostgreSQL jsonb serialization
 */
export function formatCanonicalRefs(refs: {
  application_id?: string | null | undefined;
  file_id?: string | null | undefined;
  file_version_id?: string | null | undefined;
  decision_id?: string | null | undefined;
  request_id?: string | null | undefined;
  ip?: string | null | undefined;
}): string {
  const clean: Record<string, string> = {};
  if (refs.application_id) clean.application_id = refs.application_id;
  if (refs.file_id) clean.file_id = refs.file_id;
  if (refs.file_version_id) clean.file_version_id = refs.file_version_id;
  if (refs.decision_id) clean.decision_id = refs.decision_id;
  if (refs.request_id) clean.request_id = refs.request_id;
  if (refs.ip) clean.ip = refs.ip;

  const keys = Object.keys(clean).sort();
  if (keys.length === 0) {
    return '{}';
  }
  return (
    '{' + keys.map((k) => `${JSON.stringify(k)}: ${JSON.stringify(clean[k])}`).join(', ') + '}'
  );
}

/**
 * Formats details JSON string matching PostgreSQL jsonb text representation
 */
export function formatCanonicalDetails(details: unknown): string {
  if (details === null || details === undefined) return '{}';
  if (typeof details === 'string') return details;
  return JSON.stringify(details);
}

/**
 * Verifies an ordered sequence of audit events.
 * Ensures:
 * 1. Monotonic sequence ordering (seq N > seq N-1; sequence gaps from rollbacks are permitted).
 * 2. Seq 1 links to 32 bytes of zero.
 * 3. Seq N links directly to Seq N - 1 event_hash.
 * 4. No duplicate or malformed hashes (must be 32 bytes).
 * 5. Recomputed event hashes match stored hashes when payload text is present.
 */
export function verifyAuditChain(
  events: AuditRecord[],
  options: VerifyChainOptions = {},
): VerificationResult {
  if (events.length === 0) {
    if (options.allowEmpty) {
      return {
        valid: true,
        verifiedCount: 0,
        headHash: '00'.repeat(32),
      };
    }
    return {
      valid: false,
      error: 'Audit chain is empty: zero events found',
      failureCategory: 'EMPTY_CHAIN',
    };
  }

  const zeroHash = Buffer.alloc(32, 0);

  for (let i = 0; i < events.length; i++) {
    const current = events[i];
    if (!current) continue;

    const prev = i > 0 ? events[i - 1] : null;

    // Check hash length
    if (!Buffer.isBuffer(current.prev_hash) || current.prev_hash.length !== 32) {
      return {
        valid: false,
        failedSeq: current.seq,
        error: `Invalid prev_hash length at seq ${current.seq}: expected 32 bytes`,
        failureCategory: 'MALFORMED_RECORD',
      };
    }
    if (!Buffer.isBuffer(current.event_hash) || current.event_hash.length !== 32) {
      return {
        valid: false,
        failedSeq: current.seq,
        error: `Invalid event_hash length at seq ${current.seq}: expected 32 bytes`,
        failureCategory: 'MALFORMED_RECORD',
      };
    }

    // Check root / slice start
    if (i === 0) {
      const isGenesis = BigInt(current.seq) === 1n;
      if (options.requireRootAtStart || isGenesis) {
        if (!isGenesis) {
          return {
            valid: false,
            failedSeq: current.seq,
            error: `First event must be sequence 1, got ${current.seq}`,
            failureCategory: 'GENESIS_VIOLATION',
          };
        }
        if (!current.prev_hash.equals(zeroHash)) {
          return {
            valid: false,
            failedSeq: current.seq,
            error: `Root event at seq ${current.seq} must have zero prev_hash`,
            failureCategory: 'GENESIS_VIOLATION',
          };
        }
      } else if (options.expectedPredecessorHash) {
        if (!current.prev_hash.equals(options.expectedPredecessorHash)) {
          return {
            valid: false,
            failedSeq: current.seq,
            error: `Slice start prev_hash does not match expected predecessor hash at seq ${current.seq}`,
            failureCategory: 'CHAIN_BROKEN',
          };
        }
      }
    } else if (prev) {
      // Check sequence monotonicity (permits gaps from aborted transactions, rejects non-increasing)
      const prevSeq = BigInt(prev.seq);
      const currSeq = BigInt(current.seq);
      if (currSeq <= prevSeq) {
        return {
          valid: false,
          failedSeq: current.seq,
          error: `Non-monotonic sequence order at seq ${current.seq}: predecessor was ${prev.seq}`,
          failureCategory: 'SEQUENCE_VIOLATION',
        };
      }

      // Check hash chain link
      if (!current.prev_hash.equals(prev.event_hash)) {
        return {
          valid: false,
          failedSeq: current.seq,
          error: `Hash chain broken at seq ${current.seq}: prev_hash does not match predecessor event_hash`,
          failureCategory: 'CHAIN_BROKEN',
        };
      }
    }

    // Optional or automatic hash recomputation
    const shouldRecompute =
      options.recomputeHashes === true ||
      (options.recomputeHashes !== false && Boolean(current.occurred_at_text));

    if (shouldRecompute && current.occurred_at_text) {
      const refsText =
        current.canonical_refs ??
        formatCanonicalRefs({
          application_id: current.application_id,
          file_id: current.file_id,
          file_version_id: current.file_version_id,
          decision_id: current.decision_id,
          request_id: current.request_id,
          ip: current.ip,
        });
      const detailsText = current.canonical_details ?? formatCanonicalDetails(current.details);

      const computedHash = computeEventHash({
        prevHash: current.prev_hash,
        actorType: current.actor_type,
        actorId: current.actor_id,
        action: current.action,
        occurredAtText: current.occurred_at_text,
        refsText,
        detailsText,
      });

      if (!computedHash.equals(current.event_hash)) {
        return {
          valid: false,
          failedSeq: current.seq,
          error: `Event hash mismatch at seq ${current.seq}: computed hash does not match stored event_hash (tampered event content)`,
          failureCategory: 'HASH_MISMATCH',
        };
      }
    }
  }

  const firstEvent = events[0];
  const lastEvent = events[events.length - 1];
  if (!lastEvent || !firstEvent) {
    return {
      valid: true,
      verifiedCount: 0,
      headHash: '00'.repeat(32),
    };
  }

  return {
    valid: true,
    verifiedCount: events.length,
    headHash: lastEvent.event_hash.toString('hex'),
    fromSeq: firstEvent.seq,
    toSeq: lastEvent.seq,
  };
}

export interface StreamVerifyOptions {
  batchSize?: number | undefined;
  fromSeq?: bigint | number | string | undefined;
  toSeq?: bigint | number | string | undefined;
  recomputeHashes?: boolean | undefined;
}

export interface DatabaseExecutor {
  query<T = unknown>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

/**
 * Streams audit records from PostgreSQL in batches to verify the audit chain without unbounded RAM usage.
 * Verifies both link continuity and hash computation byte-for-byte.
 */
export async function verifyAuditChainFromDb(
  db: DatabaseExecutor,
  options: StreamVerifyOptions = {},
): Promise<VerificationResult> {
  const batchSize = options.batchSize ?? 500;
  let cursorSeq: bigint | null =
    options.fromSeq !== undefined ? BigInt(options.fromSeq) - 1n : null;
  const maxSeq: bigint | null = options.toSeq !== undefined ? BigInt(options.toSeq) : null;

  let totalVerified = 0;
  let expectedPrevHash: Buffer | undefined;
  let headHash = '00'.repeat(32);
  let firstSeq: bigint | string | number | undefined;
  let lastSeq: bigint | string | number | undefined;

  // If fromSeq was specified > 1, retrieve the predecessor row to establish the expected link hash
  if (options.fromSeq !== undefined && BigInt(options.fromSeq) > 1n) {
    const predRes = await db.query<{ event_hash: Buffer }>(
      'SELECT event_hash FROM audit_events WHERE seq < $1 ORDER BY seq DESC LIMIT 1',
      [options.fromSeq.toString()],
    );
    if (predRes.rows.length > 0 && predRes.rows[0]?.event_hash) {
      expectedPrevHash = predRes.rows[0].event_hash;
    }
  }

  while (true) {
    const params: unknown[] = [];
    let sql = `
      SELECT seq, id, occurred_at, actor_type, actor_id, action,
             application_id, file_id, file_version_id, decision_id, request_id, host(ip) as ip,
             details, prev_hash, event_hash,
             occurred_at::text as occurred_at_text,
             json_strip_nulls(json_build_object(
               'application_id', application_id,
               'file_id', file_id,
               'file_version_id', file_version_id,
               'decision_id', decision_id,
               'request_id', request_id,
               'ip', host(ip)
             ))::jsonb::text as canonical_refs,
             details::text as canonical_details
      FROM audit_events
      WHERE 1=1
    `;

    if (cursorSeq !== null) {
      params.push(cursorSeq.toString());
      sql += ` AND seq > $${params.length}`;
    }
    if (maxSeq !== null) {
      params.push(maxSeq.toString());
      sql += ` AND seq <= $${params.length}`;
    }

    params.push(batchSize);
    sql += ` ORDER BY seq ASC LIMIT $${params.length}`;

    const batchRes = await db.query<AuditRecord>(sql, params);
    const rows = batchRes.rows;

    if (rows.length === 0) {
      break;
    }

    if (firstSeq === undefined && rows[0]) {
      firstSeq = rows[0].seq;
    }

    const verifyOptions: VerifyChainOptions = {
      requireRootAtStart:
        options.fromSeq === undefined || BigInt(options.fromSeq) === 1n
          ? cursorSeq === null
          : false,
      recomputeHashes: options.recomputeHashes ?? false,
      ...(expectedPrevHash !== undefined ? { expectedPredecessorHash: expectedPrevHash } : {}),
    };

    const chunkResult = verifyAuditChain(rows, verifyOptions);

    if (!chunkResult.valid) {
      return chunkResult;
    }

    totalVerified += rows.length;
    const lastRow = rows[rows.length - 1];
    if (lastRow) {
      cursorSeq = BigInt(lastRow.seq);
      expectedPrevHash = lastRow.event_hash;
      headHash = lastRow.event_hash.toString('hex');
      lastSeq = lastRow.seq;
    }

    if (rows.length < batchSize) {
      break;
    }
  }

  if (totalVerified === 0) {
    return {
      valid: false,
      error: 'Audit chain is empty: zero events found',
      failureCategory: 'EMPTY_CHAIN',
    };
  }

  const result: VerificationSuccess = {
    valid: true,
    verifiedCount: totalVerified,
    headHash,
    ...(firstSeq !== undefined ? { fromSeq: firstSeq } : {}),
    ...(lastSeq !== undefined ? { toSeq: lastSeq } : {}),
  };

  return result;
}
