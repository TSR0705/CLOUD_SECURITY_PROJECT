import { describe, it, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  signCheckpoint,
  verifyCheckpointSignature,
  formatCheckpointKey,
  createAuditCheckpoint,
  type UnsignedAuditCheckpoint,
  type AuditCheckpoint,
  type CheckpointStorageAdapter,
  type CheckpointDatabaseExecutor,
} from '../../../packages/audit/src/index.js';

describe('packages/audit - Checkpoints (Unit)', () => {
  const privateKeyPem = fs.readFileSync(
    path.resolve(process.cwd(), 'secrets/checkpoint_private_key.pem'),
    'utf8',
  );
  const publicKeyPem = fs.readFileSync(
    path.resolve(process.cwd(), 'secrets/checkpoint_public_key.pem'),
    'utf8',
  );

  // Generate another distinct Ed25519 key pair for adversarial negative tests
  const { privateKey: otherPrivKey, publicKey: otherPubKey } = crypto.generateKeyPairSync(
    'ed25519',
    {
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    },
  );

  const unsignedSample: UnsignedAuditCheckpoint = {
    schema: 'sug.audit_checkpoint/v1',
    checkpointId: crypto.randomUUID(),
    lastSeq: 1000,
    chainHash: 'a'.repeat(64),
    createdAt: new Date().toISOString(),
  };

  it('signs and verifies a valid checkpoint using Ed25519', () => {
    const signed = signCheckpoint(unsignedSample, privateKeyPem);
    expect(signed.signature).toBeDefined();
    expect(signed.signature.length).toBe(128); // 64 bytes in hex = 128 chars

    const isValid = verifyCheckpointSignature(signed, publicKeyPem);
    expect(isValid).toBe(true);
  });

  it('rejects tampered checkpoint payload (lastSeq altered)', () => {
    const signed = signCheckpoint(unsignedSample, privateKeyPem);
    const tampered: AuditCheckpoint = {
      ...signed,
      lastSeq: 1001,
    };

    expect(verifyCheckpointSignature(tampered, publicKeyPem)).toBe(false);
  });

  it('rejects tampered checkpoint payload (chainHash altered)', () => {
    const signed = signCheckpoint(unsignedSample, privateKeyPem);
    const tampered: AuditCheckpoint = {
      ...signed,
      chainHash: 'b'.repeat(64),
    };

    expect(verifyCheckpointSignature(tampered, publicKeyPem)).toBe(false);
  });

  it('rejects tampered checkpoint payload (checkpointId altered)', () => {
    const signed = signCheckpoint(unsignedSample, privateKeyPem);
    const tampered: AuditCheckpoint = {
      ...signed,
      checkpointId: crypto.randomUUID(),
    };

    expect(verifyCheckpointSignature(tampered, publicKeyPem)).toBe(false);
  });

  it('rejects corrupted signature bytes', () => {
    const signed = signCheckpoint(unsignedSample, privateKeyPem);
    const sigBuf = Buffer.from(signed.signature, 'hex');
    sigBuf[0] ^= 0xff; // flip bits
    const tampered: AuditCheckpoint = {
      ...signed,
      signature: sigBuf.toString('hex'),
    };

    expect(verifyCheckpointSignature(tampered, publicKeyPem)).toBe(false);
  });

  it('rejects signature verified with the wrong public key', () => {
    const signed = signCheckpoint(unsignedSample, privateKeyPem);
    // Verifying with unrelated Ed25519 public key
    expect(verifyCheckpointSignature(signed, otherPubKey)).toBe(false);
  });

  it('rejects checkpoint signed with an unauthorized private key', () => {
    const maliciousSigned = signCheckpoint(unsignedSample, otherPrivKey);
    // Verifying against official SUG checkpoint public key
    expect(verifyCheckpointSignature(maliciousSigned, publicKeyPem)).toBe(false);
  });

  it('formats deterministic 12-digit zero-padded S3 object keys', () => {
    expect(formatCheckpointKey(1)).toBe('checkpoints/checkpoint_000000000001.json');
    expect(formatCheckpointKey(1000)).toBe('checkpoints/checkpoint_000000001000.json');
    expect(formatCheckpointKey('999999999999')).toBe('checkpoints/checkpoint_999999999999.json');
  });

  describe('createAuditCheckpoint lifecycle & orphan reconciliation', () => {
    it('returns null if no audit events exist in the database', async () => {
      const mockDb: CheckpointDatabaseExecutor = {
        query: vi.fn().mockResolvedValue({ rows: [] }),
      };
      const mockStorage: CheckpointStorageAdapter = {
        putIfAbsent: vi.fn(),
        head: vi.fn(),
      };

      const result = await createAuditCheckpoint({
        db: mockDb,
        storage: mockStorage,
        auditBucket: 'sug-audit-local',
        privateKeyPem,
        publicKeyPem,
      });

      expect(result).toBeNull();
      expect(mockStorage.putIfAbsent).not.toHaveBeenCalled();
    });

    it('returns existing checkpoint if already recorded in PostgreSQL and verified against S3 (idempotent)', async () => {
      const existingId = crypto.randomUUID();
      const existingChainHashHex = '11'.repeat(32);
      const existingUnsigned: UnsignedAuditCheckpoint = {
        schema: 'sug.audit_checkpoint/v1',
        checkpointId: existingId,
        lastSeq: 500,
        chainHash: existingChainHashHex,
        createdAt: '2026-10-19T06:00:00.000Z',
      };
      const existingSigned = signCheckpoint(existingUnsigned, privateKeyPem);

      const existingRow = {
        id: existingId,
        last_seq: '500',
        chain_hash: Buffer.from(existingChainHashHex, 'hex'),
        signature: Buffer.from(existingSigned.signature, 'hex'),
        s3_version_id: 'v123',
        created_at: new Date('2026-10-19T06:00:00.000Z'),
      };

      const mockDb: CheckpointDatabaseExecutor = {
        query: vi.fn().mockImplementation((sql: string) => {
          if (sql.includes('SELECT seq, event_hash')) {
            return Promise.resolve({
              rows: [{ seq: '500', event_hash: existingRow.chain_hash, occurred_at: new Date() }],
            });
          }
          if (sql.includes('SELECT * FROM audit_checkpoints')) {
            return Promise.resolve({ rows: [existingRow] });
          }
          return Promise.resolve({ rows: [] });
        }),
      };
      const mockStorage: CheckpointStorageAdapter = {
        putIfAbsent: vi.fn(),
        head: vi.fn(),
        getByVersion: vi.fn().mockResolvedValue({
          body: Buffer.from(JSON.stringify(existingSigned), 'utf8'),
          versionId: 'v123',
        }),
      };

      const res = await createAuditCheckpoint({
        db: mockDb,
        storage: mockStorage,
        auditBucket: 'sug-audit-local',
        privateKeyPem,
        publicKeyPem,
      });

      expect(res).toBeDefined();
      expect(res?.checkpoint.lastSeq).toBe(500);
      expect(res?.reconciled).toBe(true);
      expect(mockStorage.putIfAbsent).not.toHaveBeenCalled();
      expect(mockStorage.getByVersion).toHaveBeenCalledWith({
        bucket: 'sug-audit-local',
        key: 'checkpoints/checkpoint_000000000500.json',
        versionId: 'v123',
      });
    });

    it('creates new checkpoint, writes to S3 first, then DB, and audits audit.checkpoint_created', async () => {
      const eventRow = {
        seq: '750',
        event_hash: Buffer.alloc(32, 0x33),
        occurred_at: new Date(),
      };

      const queries: string[] = [];
      const mockDb: CheckpointDatabaseExecutor = {
        query: vi.fn().mockImplementation((sql: string) => {
          queries.push(sql);
          if (sql.includes('SELECT seq, event_hash')) {
            return Promise.resolve({ rows: [eventRow] });
          }
          if (sql.includes('SELECT * FROM audit_checkpoints')) {
            return Promise.resolve({ rows: [] });
          }
          return Promise.resolve({ rows: [] });
        }),
      };

      const mockStorage: CheckpointStorageAdapter = {
        putIfAbsent: vi.fn().mockResolvedValue({ versionId: 's3-ver-750' }),
        head: vi.fn(),
        getByVersion: vi.fn(),
      };

      const res = await createAuditCheckpoint({
        db: mockDb,
        storage: mockStorage,
        auditBucket: 'sug-audit-local',
        privateKeyPem,
        publicKeyPem,
      });

      expect(res).toBeDefined();
      expect(res?.checkpoint.lastSeq).toBe('750');
      expect(res?.s3VersionId).toBe('s3-ver-750');
      expect(res?.storedInDb).toBe(true);
      expect(mockStorage.putIfAbsent).toHaveBeenCalledWith(
        expect.objectContaining({
          bucket: 'sug-audit-local',
          key: 'checkpoints/checkpoint_000000000750.json',
        }),
      );

      // Verify audit_append was called with audit.checkpoint_created
      const auditCall = queries.find((q) => q.includes('audit.checkpoint_created'));
      expect(auditCall).toBeDefined();
    });

    it('aborts without creating DB record if S3 write fails', async () => {
      const eventRow = {
        seq: '800',
        event_hash: Buffer.alloc(32, 0x44),
        occurred_at: new Date(),
      };

      const queries: string[] = [];
      const mockDb: CheckpointDatabaseExecutor = {
        query: vi.fn().mockImplementation((sql: string) => {
          queries.push(sql);
          if (sql.includes('SELECT seq, event_hash')) {
            return Promise.resolve({ rows: [eventRow] });
          }
          if (sql.includes('SELECT * FROM audit_checkpoints')) {
            return Promise.resolve({ rows: [] });
          }
          return Promise.resolve({ rows: [] });
        }),
      };

      const mockStorage: CheckpointStorageAdapter = {
        putIfAbsent: vi.fn().mockRejectedValue(new Error('S3 connection timeout')),
        head: vi.fn(),
        getByVersion: vi.fn(),
      };

      await expect(
        createAuditCheckpoint({
          db: mockDb,
          storage: mockStorage,
          auditBucket: 'sug-audit-local',
          privateKeyPem,
          publicKeyPem,
        }),
      ).rejects.toThrow('S3 connection timeout');

      // Verify no INSERT into audit_checkpoints was made
      const insertCall = queries.find((q) => q.includes('INSERT INTO audit_checkpoints'));
      expect(insertCall).toBeUndefined();
    });

    it('safely reconciles orphan when S3 returns AlreadyExists and S3 payload is authentic', async () => {
      const eventRow = {
        seq: '900',
        event_hash: Buffer.alloc(32, 0x55),
        occurred_at: new Date(),
      };

      const authenticUnsigned: UnsignedAuditCheckpoint = {
        schema: 'sug.audit_checkpoint/v1',
        checkpointId: crypto.randomUUID(),
        lastSeq: '900',
        chainHash: eventRow.event_hash.toString('hex'),
        createdAt: new Date().toISOString(),
      };
      const authenticSigned = signCheckpoint(authenticUnsigned, privateKeyPem);

      const mockDb: CheckpointDatabaseExecutor = {
        query: vi.fn().mockImplementation((sql: string) => {
          if (sql.includes('SELECT seq, event_hash')) {
            return Promise.resolve({ rows: [eventRow] });
          }
          if (sql.includes('SELECT * FROM audit_checkpoints')) {
            return Promise.resolve({ rows: [] });
          }
          return Promise.resolve({ rows: [] });
        }),
      };

      const alreadyExistsErr = new Error('Object already exists');
      alreadyExistsErr.name = 'AlreadyExists';

      const mockStorage: CheckpointStorageAdapter = {
        putIfAbsent: vi.fn().mockRejectedValue(alreadyExistsErr),
        head: vi.fn().mockResolvedValue({ versionId: 'existing-ver-900', contentLength: 256 }),
        getByVersion: vi.fn().mockResolvedValue({
          body: Buffer.from(JSON.stringify(authenticSigned), 'utf8'),
          versionId: 'existing-ver-900',
        }),
      };

      const res = await createAuditCheckpoint({
        db: mockDb,
        storage: mockStorage,
        auditBucket: 'sug-audit-local',
        privateKeyPem,
        publicKeyPem,
      });

      expect(res).toBeDefined();
      expect(res?.s3VersionId).toBe('existing-ver-900');
      expect(res?.reconciled).toBe(true);
      expect(mockStorage.head).toHaveBeenCalled();
      expect(mockStorage.getByVersion).toHaveBeenCalledWith({
        bucket: 'sug-audit-local',
        key: 'checkpoints/checkpoint_000000000900.json',
        versionId: 'existing-ver-900',
      });
    });

    it('rejects orphan reconciliation if existing S3 checkpoint signature is INVALID', async () => {
      const eventRow = {
        seq: '910',
        event_hash: Buffer.alloc(32, 0x55),
        occurred_at: new Date(),
      };

      // Checkpoint signed by unauthorized key
      const forgedUnsigned: UnsignedAuditCheckpoint = {
        schema: 'sug.audit_checkpoint/v1',
        checkpointId: crypto.randomUUID(),
        lastSeq: '910',
        chainHash: eventRow.event_hash.toString('hex'),
        createdAt: new Date().toISOString(),
      };
      const forgedSigned = signCheckpoint(forgedUnsigned, otherPrivKey);

      const mockDb: CheckpointDatabaseExecutor = {
        query: vi.fn().mockImplementation((sql: string) => {
          if (sql.includes('SELECT seq, event_hash')) {
            return Promise.resolve({ rows: [eventRow] });
          }
          if (sql.includes('SELECT * FROM audit_checkpoints')) {
            return Promise.resolve({ rows: [] });
          }
          return Promise.resolve({ rows: [] });
        }),
      };

      const alreadyExistsErr = new Error('Object already exists');
      alreadyExistsErr.name = 'AlreadyExists';

      const mockStorage: CheckpointStorageAdapter = {
        putIfAbsent: vi.fn().mockRejectedValue(alreadyExistsErr),
        head: vi.fn().mockResolvedValue({ versionId: 'ver-910', contentLength: 256 }),
        getByVersion: vi.fn().mockResolvedValue({
          body: Buffer.from(JSON.stringify(forgedSigned), 'utf8'),
          versionId: 'ver-910',
        }),
      };

      await expect(
        createAuditCheckpoint({
          db: mockDb,
          storage: mockStorage,
          auditBucket: 'sug-audit-local',
          privateKeyPem,
          publicKeyPem,
        }),
      ).rejects.toThrow('Orphan reconciliation failed: cryptographic signature invalid');
    });

    it('rejects orphan reconciliation if existing S3 checkpoint chainHash does not match database', async () => {
      const eventRow = {
        seq: '920',
        event_hash: Buffer.alloc(32, 0x55),
        occurred_at: new Date(),
      };

      const mismatchUnsigned: UnsignedAuditCheckpoint = {
        schema: 'sug.audit_checkpoint/v1',
        checkpointId: crypto.randomUUID(),
        lastSeq: '920',
        chainHash: 'ff'.repeat(32), // Mismatched chainHash
        createdAt: new Date().toISOString(),
      };
      const mismatchSigned = signCheckpoint(mismatchUnsigned, privateKeyPem);

      const mockDb: CheckpointDatabaseExecutor = {
        query: vi.fn().mockImplementation((sql: string) => {
          if (sql.includes('SELECT seq, event_hash')) {
            return Promise.resolve({ rows: [eventRow] });
          }
          if (sql.includes('SELECT * FROM audit_checkpoints')) {
            return Promise.resolve({ rows: [] });
          }
          return Promise.resolve({ rows: [] });
        }),
      };

      const alreadyExistsErr = new Error('Object already exists');
      alreadyExistsErr.name = 'AlreadyExists';

      const mockStorage: CheckpointStorageAdapter = {
        putIfAbsent: vi.fn().mockRejectedValue(alreadyExistsErr),
        head: vi.fn().mockResolvedValue({ versionId: 'ver-920', contentLength: 256 }),
        getByVersion: vi.fn().mockResolvedValue({
          body: Buffer.from(JSON.stringify(mismatchSigned), 'utf8'),
          versionId: 'ver-920',
        }),
      };

      await expect(
        createAuditCheckpoint({
          db: mockDb,
          storage: mockStorage,
          auditBucket: 'sug-audit-local',
          privateKeyPem,
          publicKeyPem,
        }),
      ).rejects.toThrow('Orphan reconciliation mismatch: existing S3 checkpoint chainHash');
    });

    it('rejects orphan reconciliation if existing S3 checkpoint body is corrupted JSON', async () => {
      const eventRow = {
        seq: '930',
        event_hash: Buffer.alloc(32, 0x55),
        occurred_at: new Date(),
      };

      const mockDb: CheckpointDatabaseExecutor = {
        query: vi.fn().mockImplementation((sql: string) => {
          if (sql.includes('SELECT seq, event_hash')) {
            return Promise.resolve({ rows: [eventRow] });
          }
          if (sql.includes('SELECT * FROM audit_checkpoints')) {
            return Promise.resolve({ rows: [] });
          }
          return Promise.resolve({ rows: [] });
        }),
      };

      const alreadyExistsErr = new Error('Object already exists');
      alreadyExistsErr.name = 'AlreadyExists';

      const mockStorage: CheckpointStorageAdapter = {
        putIfAbsent: vi.fn().mockRejectedValue(alreadyExistsErr),
        head: vi.fn().mockResolvedValue({ versionId: 'ver-930', contentLength: 256 }),
        getByVersion: vi.fn().mockResolvedValue({
          body: Buffer.from('{ corrupt json ]', 'utf8'),
          versionId: 'ver-930',
        }),
      };

      await expect(
        createAuditCheckpoint({
          db: mockDb,
          storage: mockStorage,
          auditBucket: 'sug-audit-local',
          privateKeyPem,
          publicKeyPem,
        }),
      ).rejects.toThrow('contains invalid JSON');
    });
  });
});
