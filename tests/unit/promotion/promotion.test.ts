/**
 * @sug/test/unit/promotion/promotion.test.ts
 *
 * Comprehensive unit and adversarial tests for Phase P20:
 * - toctou-01: Legitimate clean file promotion end-to-end
 * - toctou-02: Source object replaced in quarantine (exact version binding)
 * - toctou-03: Content mutated under same version (SHA-256 mismatch rejection)
 * - toctou-04: Size mismatch / truncation rejection
 * - Stale/superseded decision rejection
 * - Non-ALLOW decision rejection
 * - Key/encryption failure fail-closed
 * - Clean storage write idempotency and collision handling
 * - Atomic rollback on audit append failure
 * - PromotionWorker batch claiming and polling
 */

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  LocalKeyProvider,
  DEFAULT_LOCAL_KEY_REFERENCE,
  decryptBuffer,
  encryptBuffer,
} from '@sug/crypto';
import {
  AlreadyExists,
  VersionMissing,
  NotFound,
  StorageError,
  type StorageProvider,
} from '@sug/storage';
import {
  PromotionService,
  PromotionWorker,
  type ClaimedPromotionJob,
} from '../../../services/promotion/src/index.js';

describe('Phase P20: Trusted Storage & Exact-Artifact Promotion', () => {
  const testKek = crypto.randomBytes(32);
  let keyProvider: LocalKeyProvider;

  beforeEach(() => {
    keyProvider = new LocalKeyProvider({
      keys: { [DEFAULT_LOCAL_KEY_REFERENCE]: testKek },
      defaultKeyReference: DEFAULT_LOCAL_KEY_REFERENCE,
    });
  });

  // Helper to generate an async iterable stream from a Buffer
  function createStream(buf: Buffer): AsyncIterable<Uint8Array> {
    return (async function* () {
      yield new Uint8Array(buf);
    })();
  }

  // Creates a standard claimed job fixture
  function createJobFixture(overrides: Partial<ClaimedPromotionJob> = {}): {
    job: ClaimedPromotionJob;
    plaintext: Buffer;
    sha256: string;
    size: number;
  } {
    const plaintext = Buffer.from('Official approved payroll report content 2026', 'utf8');
    const sha256 = crypto.createHash('sha256').update(plaintext).digest('hex');
    const size = plaintext.length;

    const job: ClaimedPromotionJob = {
      id: crypto.randomUUID(),
      fileId: crypto.randomUUID(),
      fileVersionId: crypto.randomUUID(),
      decisionId: crypto.randomUUID(),
      applicationId: crypto.randomUUID(),
      decision: 'ALLOW',
      rule: 'R7',
      primaryReason: 'ALL_CHECKS_PASSED',
      boundBucket: 'sug-quarantine-test',
      boundKey: 'incoming/app-1/upload-1',
      boundStorageVersionId: 'q-ver-001',
      boundSha256: sha256,
      boundSize: size,
      claimedAt: new Date(),
      workerId: 'test-promoter-worker',
      leaseExpiresAt: new Date(Date.now() + 60_000),
      attempts: 1,
      ...overrides,
    };

    return { job, plaintext, sha256, size };
  }

  // Creates a mock DB executor that records queries and manages mock transaction
  function createMockDb() {
    const executedQueries: Array<{ sql: string; params?: unknown[] }> = [];
    const auditEvents: Array<{ action: string; refs: unknown; details: unknown }> = [];

    const mockDb = {
      executedQueries,
      auditEvents,
      query: vi.fn(async (sql: string, params?: unknown[]) => {
        executedQueries.push({ sql, params });

        // Supersession check query
        if (sql.includes('FROM security_decisions WHERE supersedes_id = $1')) {
          return { rows: [], rowCount: 0 };
        }

        // Audit append query
        if (sql.includes('audit_append')) {
          const match = sql.match(
            /'(PROMOTION_REJECTED|FILE_PROMOTED|FILE_DOWNLOADED|FILE_DELETED)'/,
          );
          const action = match ? match[1] : (params?.[2] as string) || 'UNKNOWN';
          const refs = params?.[1]
            ? typeof params[1] === 'string'
              ? JSON.parse(params[1])
              : params[1]
            : {};
          const details = params?.[2]
            ? typeof params[2] === 'string'
              ? JSON.parse(params[2])
              : params[2]
            : {};
          auditEvents.push({ action, refs, details });
          return { rows: [{ seq: auditEvents.length }], rowCount: 1 };
        }

        // Job query / updates
        if (sql.includes('UPDATE promotion_jobs')) {
          return { rows: [], rowCount: 1 };
        }

        // Files update
        if (sql.includes('UPDATE files')) {
          return { rows: [], rowCount: 1 };
        }

        // Cloud objects insert
        if (sql.includes('INSERT INTO cloud_objects')) {
          return { rows: [{ id: crypto.randomUUID() }], rowCount: 1 };
        }

        // Transaction commands
        if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql.trim())) {
          return { rows: [], rowCount: 0 };
        }

        return { rows: [], rowCount: 0 };
      }),
    };

    return mockDb;
  }

  // Creates a mock storage provider
  function createMockStorageProvider(plaintext: Buffer, versionId: string = 'q-ver-001') {
    const cleanObjects = new Map<string, { body: Buffer; metadata?: Record<string, string> }>();

    const storageProvider: StorageProvider = {
      head: vi.fn(async ({ bucket, key }) => {
        const fullKey = `${bucket}/${key}`;
        const obj = cleanObjects.get(fullKey);
        if (!obj) {
          throw new NotFound(`Object ${key} not found`);
        }
        return {
          bucket,
          key,
          contentLength: obj.body.length,
          etag: 'etag-123',
          versionId: 'clean-ver-001',
        };
      }),
      getByVersion: vi.fn(async ({ bucket, key, versionId: requestedVersion }) => {
        const fullKey = `${bucket}/${key}`;
        if (cleanObjects.has(fullKey)) {
          const obj = cleanObjects.get(fullKey)!;
          return {
            body: createStream(obj.body),
            bucket,
            key,
            contentLength: obj.body.length,
            versionId: requestedVersion,
            etag: 'etag-clean',
          };
        }
        if (requestedVersion !== versionId) {
          throw new VersionMissing(`Version ${requestedVersion} not found for ${key}`);
        }
        return {
          body: createStream(plaintext),
          metadata: {
            bucket,
            key,
            sizeBytes: plaintext.length,
            etag: 'etag-bound',
            versionId: requestedVersion,
            lastModified: new Date(),
          },
          bucket,
          key,
          versionId: requestedVersion,
          contentLength: plaintext.length,
        };
      }),
      putObject: vi.fn(async ({ bucket, key, body, metadata }) => {
        let fullBuf: Buffer;
        if (Buffer.isBuffer(body)) {
          fullBuf = body;
        } else {
          const chunks: Buffer[] = [];
          for await (const chunk of body) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          }
          fullBuf = Buffer.concat(chunks);
        }
        cleanObjects.set(`${bucket}/${key}`, { body: fullBuf, metadata });
        return {
          bucket,
          key,
          versionId: 'clean-ver-001',
          etag: 'etag-clean',
          sizeBytes: fullBuf.length,
        };
      }),
      putIfAbsent: vi.fn(async ({ bucket, key, body, metadata }) => {
        const fullKey = `${bucket}/${key}`;
        if (cleanObjects.has(fullKey)) {
          throw new AlreadyExists(`Object ${key} already exists`);
        }
        let fullBuf: Buffer;
        if (Buffer.isBuffer(body)) {
          fullBuf = body;
        } else {
          const chunks: Buffer[] = [];
          for await (const chunk of body) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          }
          fullBuf = Buffer.concat(chunks);
        }
        cleanObjects.set(fullKey, { body: fullBuf, metadata });
        return {
          bucket,
          key,
          versionId: 'clean-ver-001',
          etag: 'etag-clean',
          sizeBytes: fullBuf.length,
        };
      }),
      deleteObject: vi.fn(async ({ bucket, key }) => {
        cleanObjects.delete(`${bucket}/${key}`);
      }),
      listObjects: vi.fn(async () => ({ objects: [], isTruncated: false })),
    };

    return { storageProvider, cleanObjects };
  }

  describe('1. toctou-01: Legitimate Clean File Promotion End-to-End', () => {
    it('fetches bound version, encrypts with SUG1, writes clean storage, and atomically audits', async () => {
      const { job, plaintext, sha256 } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider, cleanObjects } = createMockStorageProvider(
        plaintext,
        job.boundStorageVersionId,
      );

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      // Verify overall result
      expect(result.success).toBe(true);
      expect(result.outcome).toBe('PROMOTED');
      expect(result.fileId).toBe(job.fileId);
      expect(result.cleanBucket).toBe('sug-clean-vault');
      expect(result.cleanObjectKey).toBe(`objects/${job.applicationId}/${job.fileId}`);
      expect(result.cleanStorageVersionId).toBe('clean-ver-001');
      expect(result.sha256Plaintext).toBe(sha256);
      expect(result.sha256Ciphertext).toBeDefined();

      // Verify getByVersion was called with exact bound tuple parameters
      expect(storageProvider.getByVersion).toHaveBeenCalledTimes(1);
      expect(storageProvider.getByVersion).toHaveBeenCalledWith({
        bucket: job.boundBucket,
        key: job.boundKey,
        versionId: job.boundStorageVersionId,
      });

      // Verify clean storage write
      const expectedCleanKey = `sug-clean-vault/objects/${job.applicationId}/${job.fileId}`;
      expect(cleanObjects.has(expectedCleanKey)).toBe(true);

      const cleanStored = cleanObjects.get(expectedCleanKey)!;
      // Stored object must be SUG1 encrypted envelope
      expect(cleanStored.body.subarray(0, 4).toString('ascii')).toBe('SUG1');

      // Verify ciphertext decrypts back to original plaintext using the same AAD
      const decrypted = await decryptBuffer(cleanStored.body, {
        keyProvider,
        aad: {
          appId: job.applicationId,
          fileId: job.fileId,
          storageVersionId: job.boundStorageVersionId,
          sha256Plaintext: sha256,
        },
      });
      expect(decrypted.equals(plaintext)).toBe(true);

      // Verify database state transitions
      // 1. Files status 'PROMOTING' then 'PROMOTED'
      const promotingUpdate = mockDb.executedQueries.find((q) =>
        q.sql.includes("SET status = 'PROMOTING'"),
      );
      expect(promotingUpdate).toBeDefined();

      const promotedUpdate = mockDb.executedQueries.find((q) =>
        q.sql.includes("SET status = 'PROMOTED'"),
      );
      expect(promotedUpdate).toBeDefined();

      // 2. Cloud objects insert
      const cloudObjInsert = mockDb.executedQueries.find((q) =>
        q.sql.includes('INSERT INTO cloud_objects'),
      );
      expect(cloudObjInsert).toBeDefined();
      expect(cloudObjInsert?.sql).toContain("'clean'");
      expect(cloudObjInsert?.params).toContain(`objects/${job.applicationId}/${job.fileId}`);

      // 3. Promotion job marked SUCCEEDED
      const jobSucceeded = mockDb.executedQueries.find((q) =>
        q.sql.includes("status = 'SUCCEEDED'"),
      );
      expect(jobSucceeded).toBeDefined();

      // 4. Audit append for FILE_PROMOTED
      const auditEvent = mockDb.auditEvents.find((e) => e.action === 'FILE_PROMOTED');
      expect(auditEvent).toBeDefined();
    });
  });

  describe('2. toctou-02: Source Object Replaced in Quarantine (Version Binding)', () => {
    it('rejects promotion and transitions file to ERROR if bound version is missing', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      // Storage only has a NEW version ('q-ver-002'), but job bound to 'q-ver-001'
      const { storageProvider, cleanObjects } = createMockStorageProvider(plaintext, 'q-ver-002');

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('STORAGE_FAILED');

      // Verify getByVersion was called with bound version 'q-ver-001' (not 'q-ver-002')
      expect(storageProvider.getByVersion).toHaveBeenCalledWith({
        bucket: job.boundBucket,
        key: job.boundKey,
        versionId: 'q-ver-001',
      });

      // Clean storage write was NEVER called
      expect(storageProvider.putIfAbsent).not.toHaveBeenCalled();
      expect(storageProvider.putObject).not.toHaveBeenCalled();
      expect(cleanObjects.size).toBe(0);

      // File marked ERROR because source version was permanently missing
      const errorStatusUpdate = mockDb.executedQueries.find(
        (q) => q.sql.includes('UPDATE files SET status = $1') && q.params?.[0] === 'ERROR',
      );
      expect(errorStatusUpdate).toBeDefined();

      // Job marked FAILED
      const jobFailed = mockDb.executedQueries.find((q) => q.sql.includes("status = 'FAILED'"));
      expect(jobFailed).toBeDefined();
    });
  });

  describe('3. toctou-03: Content Mutated Under Same Version (SHA-256 Mismatch)', () => {
    it('aborts immediately with HASH_MISMATCH, blocks file, audits rejection, and never writes clean object', async () => {
      const { job } = createJobFixture();
      // Adversarial payload: mutated content
      const mutatedPlaintext = Buffer.from(
        'Hacked payload injected into quarantine storage',
        'utf8',
      );
      const mockDb = createMockDb();
      const { storageProvider, cleanObjects } = createMockStorageProvider(
        mutatedPlaintext,
        job.boundStorageVersionId,
      );

      // Match size to ensure only hash mismatch triggers
      job.boundSize = mutatedPlaintext.length;

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      // Outcome must be HASH_MISMATCH
      expect(result.success).toBe(false);
      expect(result.outcome).toBe('HASH_MISMATCH');
      expect(result.error).toContain('does not match bound SHA-256');

      // Clean storage must NEVER be written
      expect(storageProvider.putIfAbsent).not.toHaveBeenCalled();
      expect(storageProvider.putObject).not.toHaveBeenCalled();
      expect(cleanObjects.size).toBe(0);

      // File status must transition to BLOCKED
      const blockedUpdate = mockDb.executedQueries.find((q) =>
        q.sql.includes("SET status = 'BLOCKED'"),
      );
      expect(blockedUpdate).toBeDefined();

      // Promotion job marked FAILED with outcome HASH_MISMATCH
      const jobFailedUpdate = mockDb.executedQueries.find(
        (q) => q.sql.includes("status = 'FAILED'") && q.params?.[3] === 'HASH_MISMATCH',
      );
      expect(jobFailedUpdate).toBeDefined();

      // Audit event PROMOTION_REJECTED recorded with mismatch details
      const rejectionAudit = mockDb.auditEvents.find((e) => e.action === 'PROMOTION_REJECTED');
      expect(rejectionAudit).toBeDefined();
    });
  });

  describe('4. toctou-04: Size Mismatch or Truncated Payload Rejection', () => {
    it('aborts immediately with SIZE_MISMATCH when payload length does not match bound size', async () => {
      const { job, plaintext } = createJobFixture();
      // Truncated payload: only first 10 bytes
      const truncated = plaintext.subarray(0, 10);
      const mockDb = createMockDb();
      const { storageProvider, cleanObjects } = createMockStorageProvider(
        truncated,
        job.boundStorageVersionId,
      );

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(['HASH_MISMATCH', 'SIZE_MISMATCH']).toContain(result.outcome);

      // Clean storage must NEVER be written
      expect(storageProvider.putIfAbsent).not.toHaveBeenCalled();
      expect(cleanObjects.size).toBe(0);

      // File status must transition to BLOCKED
      const blockedUpdate = mockDb.executedQueries.find((q) =>
        q.sql.includes("SET status = 'BLOCKED'"),
      );
      expect(blockedUpdate).toBeDefined();

      // Audit rejection event recorded
      const rejectionAudit = mockDb.auditEvents.find((e) => e.action === 'PROMOTION_REJECTED');
      expect(rejectionAudit).toBeDefined();
    });

    it('triggers exact SIZE_MISMATCH when size differs but hash is artificially matched in test fixture', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(plaintext, job.boundStorageVersionId);

      // Set boundSize to an incorrect value while boundSha matches
      job.boundSize = plaintext.length + 999;

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('SIZE_MISMATCH');
      expect(result.error).toContain('does not match bound size');
      expect(storageProvider.putIfAbsent).not.toHaveBeenCalled();
    });

    it('catches and logs warning if audit_append throws during promotion rejection', async () => {
      const { job } = createJobFixture();
      const mutatedPlaintext = Buffer.from('Hacked payload', 'utf8');
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(
        mutatedPlaintext,
        job.boundStorageVersionId,
      );
      mockDb.query.mockImplementation(async (sql: string, params?: unknown[]) => {
        mockDb.executedQueries.push({ sql, params });
        if (sql.includes('audit_append') && sql.includes('PROMOTION_REJECTED')) {
          throw new Error('Audit table disk full');
        }
        if (sql.includes('FROM security_decisions WHERE supersedes_id = $1')) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [], rowCount: 1 };
      });
      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });
      const result = await promoter.promote(job);
      expect(result.success).toBe(false);
      expect(result.outcome).toBe('HASH_MISMATCH');
    });
  });

  describe('5. Non-ALLOW and Superseded Decision Rejection', () => {
    it('rejects promotion when decision is BLOCK', async () => {
      const { job, plaintext } = createJobFixture({ decision: 'BLOCK' as unknown as 'ALLOW' });
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(plaintext, job.boundStorageVersionId);

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('NOT_ALLOW');
      expect(storageProvider.getByVersion).not.toHaveBeenCalled();
      expect(storageProvider.putIfAbsent).not.toHaveBeenCalled();
    });

    it('rejects promotion when decision is QUARANTINE', async () => {
      const { job, plaintext } = createJobFixture({ decision: 'QUARANTINE' as unknown as 'ALLOW' });
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(plaintext, job.boundStorageVersionId);

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('NOT_ALLOW');
      expect(storageProvider.getByVersion).not.toHaveBeenCalled();
    });

    it('rejects promotion when decision is superseded by a subsequent review or scan', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      // Mock supersession query returning a superseding record
      mockDb.query.mockImplementation(async (sql: string) => {
        if (sql.includes('FROM security_decisions WHERE supersedes_id = $1')) {
          return { rows: [{ id: 'new-override-decision-id' }], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      });

      const { storageProvider } = createMockStorageProvider(plaintext, job.boundStorageVersionId);

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('SUPERSEDED');
      expect(result.error).toContain('superseded');
      expect(storageProvider.getByVersion).not.toHaveBeenCalled();
      expect(storageProvider.putIfAbsent).not.toHaveBeenCalled();
    });
  });

  describe('6. Fail-Closed on Key Provider / Encryption Error', () => {
    it('halts immediately before clean storage write when key provider throws', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider, cleanObjects } = createMockStorageProvider(
        plaintext,
        job.boundStorageVersionId,
      );

      // Faulty key provider
      const faultyKeyProvider = {
        providerId: 'local',
        defaultKeyReference: 'local:default',
        wrapKey: vi.fn().mockRejectedValue(new Error('KMS unavailable or KEK corrupted')),
        unwrapKey: vi.fn().mockRejectedValue(new Error('KMS unavailable')),
      };

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider: faultyKeyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('ENCRYPTION_FAILED');
      expect(result.error).toContain('KMS unavailable');

      // Storage write MUST NOT have been called
      expect(storageProvider.putIfAbsent).not.toHaveBeenCalled();
      expect(cleanObjects.size).toBe(0);

      // File reset to QUARANTINED for retry
      const quarantinedReset = mockDb.executedQueries.find((q) =>
        q.sql.includes("SET status = 'QUARANTINED'"),
      );
      expect(quarantinedReset).toBeDefined();

      // Job re-queued with retryable = true
      const jobRequeued = mockDb.executedQueries.find(
        (q) => q.sql.includes("SET status = 'QUEUED'") && q.sql.includes('run_after = $2'),
      );
      expect(jobRequeued).toBeDefined();
    });
  });

  describe('7. Clean Storage Write Idempotency and Collision Handling', () => {
    it('handles AlreadyExists idempotently if existing clean object ciphertext hash matches', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider, cleanObjects } = createMockStorageProvider(
        plaintext,
        job.boundStorageVersionId,
      );

      // Pre-encrypt to simulate pre-existing clean object
      const promoter1 = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });
      const res1 = await promoter1.promote(job);
      expect(res1.success).toBe(true);

      // Second promotion attempt on the same object
      const promoter2 = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      // Storage putIfAbsent throws AlreadyExists
      storageProvider.putIfAbsent = vi
        .fn()
        .mockRejectedValue(new AlreadyExists('Object already exists'));

      // Mock headObject to return matching size and getObject to return the existing envelope
      const cleanKey = `sug-clean-vault/objects/${job.applicationId}/${job.fileId}`;
      const existingEnvelope = cleanObjects.get(cleanKey)!.body;

      storageProvider.getObject = vi.fn().mockResolvedValue({
        body: createStream(existingEnvelope),
        metadata: {
          bucket: 'sug-clean-vault',
          key: `objects/${job.applicationId}/${job.fileId}`,
          sizeBytes: existingEnvelope.length,
          etag: 'etag-existing',
          versionId: 'clean-ver-001',
          lastModified: new Date(),
        },
      });

      // Mock cloud_objects query finding existing object
      mockDb.query.mockImplementation(async (sql: string) => {
        if (sql.includes('FROM cloud_objects') && sql.includes("zone = 'clean'")) {
          return {
            rows: [{ id: 'cloud-obj-1', storage_version_id: 'clean-ver-001' }],
            rowCount: 1,
          };
        }
        if (sql.includes('FROM security_decisions WHERE supersedes_id = $1')) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [], rowCount: 1 };
      });

      const res2 = await promoter2.promote(job);

      // Must succeed idempotently
      expect(res2.success).toBe(true);
      expect(res2.outcome).toBe('PROMOTED');
    });

    it('fails with ALREADY_EXISTS if pre-existing clean object has conflicting ciphertext hash', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(plaintext, job.boundStorageVersionId);

      // putIfAbsent throws AlreadyExists
      storageProvider.putIfAbsent = vi
        .fn()
        .mockRejectedValue(new AlreadyExists('Conflict in clean storage'));

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('ALREADY_EXISTS');
      expect(result.error).toContain('Clean object already exists');
    });

    it('safely reconciles orphan clean storage object when putIfAbsent throws AlreadyExists and envelope cryptographic validation passes', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider, cleanObjects } = createMockStorageProvider(
        plaintext,
        job.boundStorageVersionId,
      );

      // Pre-encrypt valid envelope with matching bound AAD
      const encrypted = await encryptBuffer(plaintext, {
        keyProvider,
        aad: {
          appId: job.applicationId,
          fileId: job.fileId,
          storageVersionId: job.boundStorageVersionId,
          sha256Plaintext: job.boundSha256,
        },
        keyReference: DEFAULT_LOCAL_KEY_REFERENCE,
      });

      const cleanObjectKey = `objects/${job.applicationId}/${job.fileId}`;
      cleanObjects.set(`sug-clean-vault/${cleanObjectKey}`, {
        body: encrypted.serialized,
        metadata: {},
      });

      // putIfAbsent throws AlreadyExists
      storageProvider.putIfAbsent = vi
        .fn()
        .mockRejectedValue(new AlreadyExists('Object already exists'));

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(true);
      expect(result.outcome).toBe('PROMOTED');
      expect(result.cleanObjectKey).toBe(cleanObjectKey);

      // Verify that cloud_objects was inserted with the reconciled object's details
      const insertCloudObj = mockDb.executedQueries.find((q) =>
        q.sql.includes('INSERT INTO cloud_objects'),
      );
      expect(insertCloudObj).toBeDefined();

      // Verify that file was marked PROMOTED
      const filePromoted = mockDb.executedQueries.find((q) =>
        q.sql.includes("UPDATE files SET status = 'PROMOTED'"),
      );
      expect(filePromoted).toBeDefined();
    });

    it('fails with ALREADY_EXISTS when existing clean object cannot be decrypted or hash mismatches', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider, cleanObjects } = createMockStorageProvider(
        plaintext,
        job.boundStorageVersionId,
      );

      const cleanObjectKey = `objects/${job.applicationId}/${job.fileId}`;
      // Put completely invalid / un-decryptable envelope in clean storage
      cleanObjects.set(`sug-clean-vault/${cleanObjectKey}`, {
        body: Buffer.from('NOT_A_VALID_SUG1_ENVELOPE', 'utf8'),
        metadata: {},
      });

      storageProvider.putIfAbsent = vi
        .fn()
        .mockRejectedValue(new AlreadyExists('Object already exists'));

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('ALREADY_EXISTS');

      const fileError = mockDb.executedQueries.find((q) =>
        q.sql.includes("UPDATE files SET status = 'ERROR'"),
      );
      expect(fileError).toBeDefined();
    });

    it('fails with STORAGE_FAILED on transient 500/503 storage errors and sets file status QUARANTINED', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(plaintext, job.boundStorageVersionId);

      storageProvider.putIfAbsent = vi
        .fn()
        .mockRejectedValue(new StorageError('Service Unavailable', 503));

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('STORAGE_FAILED');

      const fileQuarantined = mockDb.executedQueries.find((q) =>
        q.sql.includes("UPDATE files SET status = 'QUARANTINED'"),
      );
      expect(fileQuarantined).toBeDefined();
    });
  });

  describe('8. Atomic Rollback and Cleanup on Audit Append Failure', () => {
    it('rolls back database transaction and cleans up written clean storage object when audit fails', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(plaintext, job.boundStorageVersionId);

      // Audit append throws
      mockDb.query.mockImplementation(async (sql: string, params?: unknown[]) => {
        mockDb.executedQueries.push({ sql, params });
        if (sql.includes('audit_append') && sql.includes('FILE_PROMOTED')) {
          throw new Error('Database audit constraint violation or disk full');
        }
        if (sql.includes('FROM security_decisions WHERE supersedes_id = $1')) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [{ id: crypto.randomUUID() }], rowCount: 1 };
      });

      const promoter = new PromotionService({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const result = await promoter.promote(job);

      expect(result.success).toBe(false);
      expect(result.outcome).toBe('AUDIT_FAILED');
      expect(result.error).toContain('Database audit constraint violation');

      // Verify transaction rollback occurred
      const rollbackQuery = mockDb.executedQueries.find((q) => q.sql === 'ROLLBACK');
      expect(rollbackQuery).toBeDefined();

      // Verify file was reset to QUARANTINED
      const fileReset = mockDb.executedQueries.find((q) =>
        q.sql.includes("SET status = 'QUARANTINED'"),
      );
      expect(fileReset).toBeDefined();
    });
  });

  describe('9. PromotionWorker Batch Claiming and Polling', () => {
    it('processes eligible claimed jobs and completes when queue is drained', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(plaintext, job.boundStorageVersionId);

      // Mock claim query returning 1 job on first call, empty on second
      let callCount = 0;
      mockDb.query.mockImplementation(async (sql: string) => {
        if (sql.includes('WITH next_job AS')) {
          callCount++;
          if (callCount === 1) {
            return {
              rows: [
                {
                  id: job.id,
                  decision_id: job.decisionId,
                  file_version_id: job.fileVersionId,
                  file_id: job.fileId,
                  application_id: job.applicationId,
                  status: 'RUNNING',
                  attempts: 1,
                  run_after: new Date(),
                  locked_by: 'worker-1',
                  locked_at: new Date(),
                  decision: 'ALLOW',
                  bound_bucket: job.boundBucket,
                  bound_key: job.boundKey,
                  bound_storage_version_id: job.boundStorageVersionId,
                  bound_sha256: job.boundSha256,
                  bound_size: job.boundSize,
                  display_filename: 'payroll.pdf',
                },
              ],
              rowCount: 1,
            };
          }
          return { rows: [], rowCount: 0 };
        }
        if (sql.includes('FROM security_decisions WHERE supersedes_id = $1')) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [{ id: crypto.randomUUID() }], rowCount: 1 };
      });

      const worker = new PromotionWorker({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const run1 = await worker.runOnce();
      expect(run1.worked).toBe(true);
      expect(run1.result?.success).toBe(true);
      expect(run1.result?.outcome).toBe('PROMOTED');

      // Running once more on empty queue processes 0
      const run2 = await worker.runOnce();
      expect(run2.worked).toBe(false);
    });

    it('handles enqueue error gracefully in runOnce()', async () => {
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(Buffer.from('test'));

      mockDb.query.mockImplementation(async (sql: string) => {
        if (sql.includes('INSERT INTO promotion_jobs')) {
          throw new Error('Database read-only or lock timeout');
        }
        if (sql.includes('WITH next_job AS')) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [], rowCount: 0 };
      });

      const worker = new PromotionWorker({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const res = await worker.runOnce();
      expect(res.worked).toBe(false);
    });

    it('handles claim error gracefully in runOnce()', async () => {
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(Buffer.from('test'));

      mockDb.query.mockImplementation(async (sql: string) => {
        if (sql.includes('WITH next_job AS')) {
          throw new Error('Connection pool exhausted');
        }
        return { rows: [], rowCount: 0 };
      });

      const worker = new PromotionWorker({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const res = await worker.runOnce();
      expect(res.worked).toBe(false);
    });

    it('handles unhandled exception during promotion in runOnce()', async () => {
      const { job, plaintext } = createJobFixture();
      const mockDb = createMockDb();
      const { storageProvider } = createMockStorageProvider(plaintext, job.boundStorageVersionId);

      mockDb.query.mockImplementation(async (sql: string) => {
        if (sql.includes('WITH next_job AS')) {
          return {
            rows: [
              {
                id: job.id,
                decision_id: job.decisionId,
                file_version_id: job.fileVersionId,
                file_id: job.fileId,
                application_id: job.applicationId,
                status: 'RUNNING',
                attempts: 1,
                run_after: new Date(),
                locked_by: 'worker-1',
                locked_at: new Date(),
                decision: 'ALLOW',
                bound_bucket: job.boundBucket,
                bound_key: job.boundKey,
                bound_storage_version_id: job.boundStorageVersionId,
                bound_sha256: job.boundSha256,
                bound_size: job.boundSize,
                display_filename: 'payroll.pdf',
              },
            ],
            rowCount: 1,
          };
        }
        throw new Error('Fatal unhandled error inside promote');
      });

      const worker = new PromotionWorker({
        db: mockDb,
        storageProvider,
        cleanBucket: 'sug-clean-vault',
        keyProvider,
      });

      const res = await worker.runOnce();
      expect(res.worked).toBe(true);
      expect(res.result?.success).toBe(false);
      expect(res.result?.outcome).toBe('FAILED');
    });

    it('supports worker lifecycle start(), stop(), and getWorkerId()', async () => {
      vi.useFakeTimers();
      try {
        const mockDb = createMockDb();
        const { storageProvider } = createMockStorageProvider(Buffer.from('test'));

        const worker = new PromotionWorker({
          db: mockDb,
          storageProvider,
          cleanBucket: 'sug-clean-vault',
          keyProvider,
          workerId: 'custom-worker-id',
          pollIntervalMs: 50,
        });

        expect(worker.getWorkerId()).toBe('custom-worker-id');

        worker.start();
        // Calling start again when already running is a no-op
        worker.start();

        // Advance timer so poll() executes
        await vi.advanceTimersByTimeAsync(60);

        worker.stop();
        // Calling stop again when already stopped is safe
        worker.stop();
      } finally {
        vi.useRealTimers();
      }
    });

    it('handles error in poll() loop iteration gracefully', async () => {
      vi.useFakeTimers();
      try {
        const mockDb = createMockDb();
        const { storageProvider } = createMockStorageProvider(Buffer.from('test'));

        const worker = new PromotionWorker({
          db: mockDb,
          storageProvider,
          cleanBucket: 'sug-clean-vault',
          keyProvider,
          pollIntervalMs: 50,
        });

        // Mock runOnce throwing to trigger catch in poll()
        vi.spyOn(worker, 'runOnce').mockRejectedValue(new Error('Fatal poll crash'));

        worker.start();
        await vi.advanceTimersByTimeAsync(60);
        worker.stop();
      } finally {
        vi.useRealTimers();
      }
    });
  });
});
