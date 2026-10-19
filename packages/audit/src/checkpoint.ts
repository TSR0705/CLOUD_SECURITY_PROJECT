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
    versionId?: string | undefined;
  }): Promise<{ versionId?: string | undefined; contentLength: number }>;
  getByVersion(params: {
    bucket: string;
    key: string;
    versionId: string;
  }): Promise<{ body: unknown; versionId?: string | undefined }>;
}

export interface CheckpointDatabaseExecutor {
  query<T = unknown>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

/**
 * Safely converts diverse stream/buffer/string storage payloads into a single Buffer.
 */
async function readBodyToBuffer(body: unknown): Promise<Buffer> {
  if (Buffer.isBuffer(body)) {
    return body;
  }
  if (typeof body === 'string') {
    return Buffer.from(body, 'utf8');
  }
  if (body && typeof (body as { transformToString?: unknown }).transformToString === 'function') {
    const str = await (body as { transformToString: () => Promise<string> }).transformToString();
    return Buffer.from(str, 'utf8');
  }
  if (
    body &&
    typeof (body as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === 'function'
  ) {
    const chunks: Buffer[] = [];
    for await (const chunk of body as AsyncIterable<Uint8Array | Buffer | string>) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
  if (body && typeof (body as { on?: unknown }).on === 'function') {
    return new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = [];
      const stream = body as NodeJS.ReadableStream;
      stream.on('data', (c: unknown) => {
        chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c as string | Uint8Array));
      });
      stream.on('end', () => resolve(Buffer.concat(chunks)));
      stream.on('error', reject);
    });
  }
  throw new Error('Unsupported storage body format');
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
 * 3. If S3 already has this key, reconciles and cryptographically verifies S3 payload.
 * 4. Inserts checkpoint record into PostgreSQL audit_checkpoints.
 * 5. Audits audit.checkpoint_created event.
 * If S3 fails or existing S3 content fails signature/identity checks, the operation aborts fail-closed.
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
    const key = formatCheckpointKey(lastSeq);

    // Cryptographically verify existing S3 object matches DB record
    const getRes = await storage.getByVersion({
      bucket: auditBucket,
      key,
      versionId: row.s3_version_id,
    });
    const rawBytes = await readBodyToBuffer(getRes.body);
    let s3Cp: AuditCheckpoint;
    try {
      s3Cp = JSON.parse(rawBytes.toString('utf8'));
    } catch {
      throw new Error(
        `Integrity error: existing S3 checkpoint for seq ${lastSeq} contains invalid JSON`,
      );
    }
    if (s3Cp.schema !== 'sug.audit_checkpoint/v1') {
      throw new Error(`Integrity error: S3 checkpoint schema invalid for seq ${lastSeq}`);
    }
    if (!verifyCheckpointSignature(s3Cp, publicKeyPem)) {
      throw new Error(
        `Integrity error: existing S3 checkpoint signature invalid for seq ${lastSeq}`,
      );
    }
    if (s3Cp.checkpointId !== row.id) {
      throw new Error(
        `Integrity error: S3 checkpoint ID (${s3Cp.checkpointId}) does not match DB record (${row.id})`,
      );
    }
    if (s3Cp.chainHash.toLowerCase() !== row.chain_hash.toString('hex').toLowerCase()) {
      throw new Error(
        `Integrity error: S3 checkpoint chainHash does not match DB record for seq ${lastSeq}`,
      );
    }
    if (String(s3Cp.lastSeq) !== String(lastSeq)) {
      throw new Error(
        `Integrity error: S3 checkpoint lastSeq (${s3Cp.lastSeq}) does not match expected (${lastSeq})`,
      );
    }

    return {
      checkpoint: s3Cp,
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
  let signed = signCheckpoint(unsigned, privateKeyPem);

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
    if (
      errorName === 'AlreadyExists' ||
      errorMessage?.includes('AlreadyExists') ||
      errorMessage?.includes('PreconditionFailed')
    ) {
      // Safe orphan reconciliation: retrieve exact S3 version and cryptographically verify
      const head = await storage.head({ bucket: auditBucket, key });
      const existingVersionId = head.versionId;
      if (!existingVersionId) {
        throw new Error(
          `Orphan reconciliation failed: missing versionId for existing S3 checkpoint at ${key}`,
        );
      }

      const getRes = await storage.getByVersion({
        bucket: auditBucket,
        key,
        versionId: existingVersionId,
      });
      const rawBytes = await readBodyToBuffer(getRes.body);

      let existingCp: AuditCheckpoint;
      try {
        existingCp = JSON.parse(rawBytes.toString('utf8'));
      } catch {
        throw new Error(
          `Orphan reconciliation failed: existing S3 checkpoint at ${key} contains invalid JSON`,
        );
      }

      if (existingCp.schema !== 'sug.audit_checkpoint/v1') {
        throw new Error(
          `Orphan reconciliation failed: invalid schema ${existingCp.schema} at ${key}`,
        );
      }

      if (!verifyCheckpointSignature(existingCp, publicKeyPem)) {
        throw new Error(
          `Orphan reconciliation failed: cryptographic signature invalid on existing S3 checkpoint at ${key}`,
        );
      }

      if (String(existingCp.lastSeq) !== String(lastSeq)) {
        throw new Error(
          `Orphan reconciliation mismatch: existing S3 checkpoint lastSeq ${existingCp.lastSeq} does not match expected ${lastSeq}`,
        );
      }

      if (existingCp.chainHash.toLowerCase() !== chainHashHex.toLowerCase()) {
        throw new Error(
          `Orphan reconciliation mismatch: existing S3 checkpoint chainHash ${existingCp.chainHash} does not match expected ${chainHashHex}`,
        );
      }

      signed = existingCp;
      s3VersionId = getRes.versionId ?? existingVersionId;
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
        'audit.checkpoint_created',
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
