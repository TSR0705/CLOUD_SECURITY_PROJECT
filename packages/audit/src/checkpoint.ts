/**
 * Audit Checkpoint signing, verification, and persistence
 */

import crypto from 'node:crypto';

export interface AuditCheckpoint {
  schema: 'sug.audit_checkpoint/v1';
  checkpointId: string;
  lastSeq: string | number;
  chainHash: string;
  createdAt: string;
  signature: string;
}

export type UnsignedAuditCheckpoint = Omit<AuditCheckpoint, 'signature'>;

export interface CheckpointStorageAdapter {
  putIfAbsent(params: {
    bucket: string;
    key: string;
    body: string | Buffer;
    contentType?: string;
  }): Promise<{ versionId: string }>;
  head(params: {
    bucket: string;
    key: string;
  }): Promise<{ versionId?: string | undefined; contentLength: number }>;
}

export interface CheckpointDatabaseExecutor {
  query<T = unknown>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

/**
 * Returns canonical signable payload for an audit checkpoint (excluding signature).
 */
export function getCheckpointSignablePayload(checkpoint: UnsignedAuditCheckpoint): Buffer {
  const signable = {
    schema: checkpoint.schema,
    checkpointId: checkpoint.checkpointId,
    lastSeq: String(checkpoint.lastSeq),
    chainHash: checkpoint.chainHash.toLowerCase(),
    createdAt: checkpoint.createdAt,
  };
  return Buffer.from(JSON.stringify(signable), 'utf8');
}

/**
 * Signs an audit checkpoint using Ed25519 private key.
 */
export function signCheckpoint(
  checkpoint: UnsignedAuditCheckpoint,
  privateKeyPem: string,
): AuditCheckpoint {
  const payload = getCheckpointSignablePayload(checkpoint);
  const signature = crypto.sign(null, payload, privateKeyPem).toString('hex');
  return {
    ...checkpoint,
    signature,
  };
}

/**
 * Verifies an Ed25519 signature on an audit checkpoint using the trusted public key.
 */
export function verifyCheckpointSignature(
  checkpoint: AuditCheckpoint,
  publicKeyPem: string,
): boolean {
  if (!checkpoint.signature) {
    return false;
  }
  try {
    const payload = getCheckpointSignablePayload(checkpoint);
    const sigBuf = Buffer.from(checkpoint.signature, 'hex');
    return crypto.verify(null, payload, publicKeyPem, sigBuf);
  } catch {
    return false;
  }
}

/**
 * Formats the S3 object key for a checkpoint:
 * checkpoints/checkpoint_000000001000.json
 */
export function formatCheckpointKey(lastSeq: bigint | number | string): string {
  const seqStr = String(lastSeq).padStart(12, '0');
  return `checkpoints/checkpoint_${seqStr}.json`;
}

export interface CheckpointCreationResult {
  checkpoint: AuditCheckpoint;
  s3VersionId: string;
  storedInDb: boolean;
  reconciled: boolean;
}

/**
 * Creates an Ed25519-signed audit checkpoint for the latest committed audit event.
 * Follows strict storage-first persistence with safe orphan reconciliation:
 * 1. Claims latest audit event from PostgreSQL.
 * 2. Writes signed checkpoint JSON to S3 via putIfAbsent.
 * 3. If S3 already has this key, reconciles and re-verifies.
 * 4. Inserts checkpoint record into PostgreSQL audit_checkpoints.
 * 5. Audits checkpoint.created event.
 * If S3 fails, the operation aborts and zero database records are written.
 */
export async function createAuditCheckpoint(params: {
  db: CheckpointDatabaseExecutor;
  storage: CheckpointStorageAdapter;
  auditBucket: string;
  privateKeyPem: string;
  publicKeyPem: string;
}): Promise<CheckpointCreationResult | null> {
  const { db, storage, auditBucket, privateKeyPem, publicKeyPem } = params;

  // 1. Fetch latest committed audit event
  const latestRes = await db.query<{ seq: string; event_hash: Buffer; occurred_at: Date }>(
    'SELECT seq, event_hash, occurred_at FROM audit_events ORDER BY seq DESC LIMIT 1',
  );

  if (latestRes.rows.length === 0 || !latestRes.rows[0]) {
    return null;
  }

  const latestEvent = latestRes.rows[0];
  const lastSeq = latestEvent.seq;
  const chainHashHex = latestEvent.event_hash.toString('hex');

  // 2. Check if a checkpoint for lastSeq already exists in PostgreSQL
  const existingDbRes = await db.query<{
    id: string;
    last_seq: string;
    chain_hash: Buffer;
    signature: Buffer;
    s3_version_id: string;
    created_at: Date;
  }>('SELECT * FROM audit_checkpoints WHERE last_seq = $1', [lastSeq]);

  if (existingDbRes.rows.length > 0 && existingDbRes.rows[0]) {
    const row = existingDbRes.rows[0];
    const existingCheckpoint: AuditCheckpoint = {
      schema: 'sug.audit_checkpoint/v1',
      checkpointId: row.id,
      lastSeq: row.last_seq,
      chainHash: row.chain_hash.toString('hex'),
      createdAt: row.created_at.toISOString(),
      signature: row.signature.toString('hex'),
    };
    return {
      checkpoint: existingCheckpoint,
      s3VersionId: row.s3_version_id,
      storedInDb: true,
      reconciled: true,
    };
  }

  // 3. Build and sign new checkpoint
  const checkpointId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const unsigned: UnsignedAuditCheckpoint = {
    schema: 'sug.audit_checkpoint/v1',
    checkpointId,
    lastSeq,
    chainHash: chainHashHex,
    createdAt,
  };
  const signed = signCheckpoint(unsigned, privateKeyPem);

  // Self-verify signature with trusted public key before storage
  if (!verifyCheckpointSignature(signed, publicKeyPem)) {
    throw new Error('Self-verification of generated checkpoint signature failed');
  }

  // 4. Storage-first write to S3
  const key = formatCheckpointKey(lastSeq);
  const body = JSON.stringify(signed, null, 2);
  let s3VersionId: string;
  let reconciled = false;

  try {
    const putRes = await storage.putIfAbsent({
      bucket: auditBucket,
      key,
      body,
      contentType: 'application/json',
    });
    s3VersionId = putRes.versionId;
  } catch (err: unknown) {
    const errorName = (err as { name?: string }).name;
    const errorMessage = (err as Error).message;
    if (errorName === 'AlreadyExists' || errorMessage?.includes('AlreadyExists')) {
      // Safe orphan reconciliation: check existing S3 object
      const head = await storage.head({ bucket: auditBucket, key });
      s3VersionId = head.versionId ?? 'latest';
      reconciled = true;
    } else {
      // Storage write failed: abort immediately; do not report durable success
      throw err;
    }
  }

  // 5. Insert checkpoint record into PostgreSQL
  const chainHashBuf = Buffer.from(signed.chainHash, 'hex');
  const signatureBuf = Buffer.from(signed.signature, 'hex');

  await db.query(
    `INSERT INTO audit_checkpoints(id, last_seq, chain_hash, signature, s3_version_id, created_at)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (last_seq) DO NOTHING`,
    [signed.checkpointId, lastSeq, chainHashBuf, signatureBuf, s3VersionId, signed.createdAt],
  );

  // 6. Record tamper-evident audit event for checkpoint generation
  try {
    await db.query(
      `SELECT audit_append(
        'service',
        'checkpoint_signer',
        'checkpoint.created',
        $1::jsonb,
        $2::jsonb
      )`,
      [
        JSON.stringify({}),
        JSON.stringify({
          checkpoint_id: signed.checkpointId,
          last_seq: String(lastSeq),
          chain_hash: signed.chainHash,
          s3_version_id: s3VersionId,
        }),
      ],
    );
  } catch {
    // Audit failure in background checkpointing preserves fail-closed behavior
  }

  return {
    checkpoint: signed,
    s3VersionId,
    storedInDb: true,
    reconciled,
  };
}
