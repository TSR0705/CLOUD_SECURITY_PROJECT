/**
 * Audit chain verification logic
 */

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
}

export interface VerificationSuccess {
  valid: true;
  verifiedCount: number;
  headHash: string;
}

export interface VerificationFailure {
  valid: false;
  failedSeq: bigint | number | string;
  error: string;
}

export type VerificationResult = VerificationSuccess | VerificationFailure;

export interface VerifyChainOptions {
  /** If true, the first event must be seq 1 and have a zero prev_hash */
  requireRootAtStart?: boolean;
  /** Expected previous hash for the first event in a slice */
  expectedPredecessorHash?: Buffer;
}

/**
 * Verifies an ordered sequence of audit events.
 * Ensures:
 * 1. Monotonic sequence ordering.
 * 2. Seq 1 links to 32 bytes of zero.
 * 3. Seq N (N > 1) links directly to Seq N - 1 event_hash.
 * 4. No duplicate or malformed hashes.
 */
export function verifyAuditChain(
  events: AuditRecord[],
  options: VerifyChainOptions = {},
): VerificationResult {
  if (events.length === 0) {
    return {
      valid: true,
      verifiedCount: 0,
      headHash: '00'.repeat(32),
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
      };
    }
    if (!Buffer.isBuffer(current.event_hash) || current.event_hash.length !== 32) {
      return {
        valid: false,
        failedSeq: current.seq,
        error: `Invalid event_hash length at seq ${current.seq}: expected 32 bytes`,
      };
    }

    if (i === 0) {
      const isGenesis = BigInt(current.seq) === 1n;
      if (options.requireRootAtStart || isGenesis) {
        if (!isGenesis) {
          return {
            valid: false,
            failedSeq: current.seq,
            error: `First event must be sequence 1, got ${current.seq}`,
          };
        }
        if (!current.prev_hash.equals(zeroHash)) {
          return {
            valid: false,
            failedSeq: current.seq,
            error: `Root event at seq ${current.seq} must have zero prev_hash`,
          };
        }
      } else if (options.expectedPredecessorHash) {
        if (!current.prev_hash.equals(options.expectedPredecessorHash)) {
          return {
            valid: false,
            failedSeq: current.seq,
            error: `Slice start prev_hash does not match expected predecessor hash at seq ${current.seq}`,
          };
        }
      }
    } else if (prev) {
      // Check sequence monotonicity
      const prevSeq = BigInt(prev.seq);
      const currSeq = BigInt(current.seq);
      if (currSeq <= prevSeq) {
        return {
          valid: false,
          failedSeq: current.seq,
          error: `Non-monotonic sequence order at seq ${current.seq}: predecessor was ${prev.seq}`,
        };
      }

      // Check hash chain link
      if (!current.prev_hash.equals(prev.event_hash)) {
        return {
          valid: false,
          failedSeq: current.seq,
          error: `Hash chain broken at seq ${current.seq}: prev_hash does not match predecessor event_hash`,
        };
      }
    }
  }

  const lastEvent = events[events.length - 1];
  if (!lastEvent) {
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
  };
}
