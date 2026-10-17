/**
 * @sug/service-promotion/promoter
 * Core exact-artifact promotion service implementing TOCTOU protection,
 * envelope encryption, trusted clean storage publication, and atomic auditing.
 */

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import type { DatabaseExecutor } from '@sug/shared';
import { timingSafeSha256Equal, completePromotionJob, failPromotionJob } from '@sug/shared';
import { AlreadyExists, VersionMissing, NotFound, StorageError } from '@sug/storage';
import { encryptBuffer, decryptBuffer, parseSug1Header, extractCiphertext } from '@sug/crypto';
import type {
  ClaimedPromotionJob,
  PromotionResult,
  PromotionServiceOptions,
  PromotionLogger,
} from './types.js';

/**
 * Interface representing a transactional database client with BEGIN/COMMIT/ROLLBACK.
 */
interface TransactionalClient extends DatabaseExecutor {
  query<T = unknown>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[]; rowCount?: number | null }>;
}

export class PromotionService {
  private readonly db: DatabaseExecutor;
  private readonly storageProvider: PromotionServiceOptions['storageProvider'];
  private readonly cleanBucket: string;
  private readonly keyProvider: PromotionServiceOptions['keyProvider'];
  private readonly kekId: string;
  private readonly workerId: string;
  private readonly provider: 'aws' | 'minio' | 'gcp';
  private readonly logger: PromotionLogger | undefined;

  constructor(options: PromotionServiceOptions) {
    this.db = options.db;
    this.storageProvider = options.storageProvider;
    this.cleanBucket = options.cleanBucket;
    this.keyProvider = options.keyProvider;
    this.kekId = options.kekId ?? 'local:default';
    this.workerId =
      options.workerId ?? `promoter-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    this.provider = options.provider ?? 'aws';
    this.logger = options.logger;
  }

  /**
   * Promotes an artifact corresponding to a claimed promotion job.
   *
   * Enforces the canonical P20 protocol:
   * 1. Validates that the decision is un-superseded ALLOW.
   * 2. Sets file status to 'PROMOTING'.
   * 3. Re-fetches the exact bound source version from quarantine (never latest).
   * 4. Re-computes SHA-256 and byte size, rejecting any TOCTOU mismatch with HASH_MISMATCH.
   * 5. Encrypts the payload via AES-256-GCM envelope encryption (SUG1).
   * 6. Writes to trusted clean storage at objects/<app_id>/<file_id> using putIfAbsent (If-None-Match: *).
   * 7. Atomically records cloud_objects, files status 'PROMOTED', promotion_job 'SUCCEEDED', and FILE_PROMOTED audit.
   */
  async promote(
    job: ClaimedPromotionJob,
    options: { dbClient?: TransactionalClient } = {},
  ): Promise<PromotionResult> {
    const executor = options.dbClient ?? this.db;

    // 1. Verify that the decision is ALLOW
    if (job.decision !== 'ALLOW') {
      this.logger?.warn('Promotion aborted: decision is not ALLOW', {
        jobId: job.id,
        decisionId: job.decisionId,
        decision: job.decision,
      });

      await failPromotionJob(executor, job.id, {
        error: `Decision is ${job.decision}, cannot promote non-ALLOW file`,
        outcome: 'NOT_ALLOW',
        retryable: false,
      });

      return {
        success: false,
        outcome: 'NOT_ALLOW',
        fileId: job.fileId,
        fileVersionId: job.fileVersionId,
        error: `Decision is ${job.decision}, expected ALLOW`,
      };
    }

    // Verify non-supersession: check if another decision supersedes this decision
    const supersessionCheck = await executor.query<{ id: string }>(
      `SELECT id FROM security_decisions WHERE supersedes_id = $1 LIMIT 1`,
      [job.decisionId],
    );

    if (supersessionCheck.rows.length > 0) {
      this.logger?.warn('Promotion aborted: decision has been superseded', {
        jobId: job.id,
        decisionId: job.decisionId,
        supersededBy: supersessionCheck.rows[0]?.id,
      });

      await failPromotionJob(executor, job.id, {
        error: `Decision ${job.decisionId} was superseded by ${supersessionCheck.rows[0]?.id}`,
        outcome: 'SUPERSEDED',
        retryable: false,
      });

      return {
        success: false,
        outcome: 'SUPERSEDED',
        fileId: job.fileId,
        fileVersionId: job.fileVersionId,
        error: 'Decision superseded by subsequent review or scan',
      };
    }

    // 2. Transition file status to 'PROMOTING'
    await executor.query(`UPDATE files SET status = 'PROMOTING' WHERE id = $1`, [job.fileId]);

    // 3. Re-fetch exact bound source artifact from quarantine (never latest)
    let plaintextBuffer: Buffer;
    try {
      this.logger?.info('Re-fetching bound source artifact from quarantine', {
        bucket: job.boundBucket,
        key: job.boundKey,
        versionId: job.boundStorageVersionId,
      });

      const getRes = await this.storageProvider.getByVersion({
        bucket: job.boundBucket,
        key: job.boundKey,
        versionId: job.boundStorageVersionId,
      });

      // Stream into buffer
      const chunks: Buffer[] = [];
      for await (const chunk of getRes.body) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      plaintextBuffer = Buffer.concat(chunks);
    } catch (err) {
      const isMissing = err instanceof VersionMissing || err instanceof NotFound;
      const isRetryable = !isMissing && err instanceof StorageError && err.statusCode >= 500;

      this.logger?.error('Failed to retrieve bound artifact from quarantine', {
        error: (err as Error).message,
        isMissing,
        isRetryable,
      });

      await failPromotionJob(executor, job.id, {
        error: (err as Error).message,
        outcome: isMissing ? 'FAILED' : 'STORAGE_FAILED',
        retryable: isRetryable,
      });

      // Reset file status back to QUARANTINED if retryable, or ERROR if permanently missing
      await executor.query(`UPDATE files SET status = $1 WHERE id = $2`, [
        isMissing ? 'ERROR' : 'QUARANTINED',
        job.fileId,
      ]);

      return {
        success: false,
        outcome: 'STORAGE_FAILED',
        fileId: job.fileId,
        fileVersionId: job.fileVersionId,
        error: (err as Error).message,
      };
    }

    // 4. Re-calculate SHA-256 and byte size before encryption or clean storage write (Anti-TOCTOU)
    const recomputedSha = crypto.createHash('sha256').update(plaintextBuffer).digest('hex');
    const recomputedSize = plaintextBuffer.length;

    const shaMatches = timingSafeSha256Equal(recomputedSha, job.boundSha256);
    const sizeMatches = recomputedSize === job.boundSize;

    if (!shaMatches || !sizeMatches) {
      const outcome = !shaMatches ? 'HASH_MISMATCH' : 'SIZE_MISMATCH';
      const reasonDetail = !shaMatches
        ? `Recomputed SHA-256 '${recomputedSha}' does not match bound SHA-256 '${job.boundSha256}'`
        : `Recomputed byte size ${recomputedSize} does not match bound size ${job.boundSize}`;

      this.logger?.error(`TOCTOU violation detected during promotion: ${outcome}`, {
        jobId: job.id,
        fileId: job.fileId,
        boundSha: job.boundSha256,
        actualSha: recomputedSha,
        boundSize: job.boundSize,
        actualSize: recomputedSize,
      });

      // Transition file status to 'BLOCKED'
      await executor.query(`UPDATE files SET status = 'BLOCKED' WHERE id = $1`, [job.fileId]);

      // Record audit event for promotion rejection
      const refs = {
        application_id: job.applicationId,
        file_id: job.fileId,
        file_version_id: job.fileVersionId,
        decision_id: job.decisionId,
      };
      const details = {
        reason: outcome,
        expected_sha256: job.boundSha256,
        actual_sha256: recomputedSha,
        expected_size: job.boundSize,
        actual_size: recomputedSize,
        bound_storage_version_id: job.boundStorageVersionId,
      };

      try {
        await executor.query(
          `SELECT audit_append('service', $1, 'PROMOTION_REJECTED', $2::jsonb, $3::jsonb)`,
          [this.workerId, JSON.stringify(refs), JSON.stringify(details)],
        );
      } catch (auditErr) {
        this.logger?.error('Failed to append audit event for promotion rejection', {
          error: (auditErr as Error).message,
        });
      }

      // Mark promotion job FAILED with the mismatch outcome
      await failPromotionJob(executor, job.id, {
        error: reasonDetail,
        outcome,
        retryable: false,
      });

      return {
        success: false,
        outcome,
        fileId: job.fileId,
        fileVersionId: job.fileVersionId,
        error: reasonDetail,
      };
    }

    // 5. Encrypt verified plaintext via AES-256-GCM envelope encryption (@sug/crypto)
    let encrypted;
    let cipherShaHex: string;
    try {
      encrypted = await encryptBuffer(plaintextBuffer, {
        keyProvider: this.keyProvider,
        aad: {
          appId: job.applicationId,
          fileId: job.fileId,
          storageVersionId: job.boundStorageVersionId,
          sha256Plaintext: job.boundSha256,
        },
        keyReference: this.kekId,
      });
      cipherShaHex = crypto.createHash('sha256').update(encrypted.serialized).digest('hex');
    } catch (encryptErr) {
      this.logger?.error('Envelope encryption failed before clean storage publication', {
        error: (encryptErr as Error).message,
      });

      await failPromotionJob(executor, job.id, {
        error: `Encryption failed: ${(encryptErr as Error).message}`,
        outcome: 'ENCRYPTION_FAILED',
        retryable: true,
      });

      await executor.query(`UPDATE files SET status = 'QUARANTINED' WHERE id = $1`, [job.fileId]);

      return {
        success: false,
        outcome: 'ENCRYPTION_FAILED',
        fileId: job.fileId,
        fileVersionId: job.fileVersionId,
        error: (encryptErr as Error).message,
      };
    } finally {
      // Securely wipe plaintext from memory
      plaintextBuffer.fill(0);
    }

    // 6. Publish ciphertext to trusted clean storage using putIfAbsent (objects/<app_id>/<file_id>)
    const cleanObjectKey = `objects/${job.applicationId}/${job.fileId}`;
    let putResult;
    try {
      this.logger?.info('Publishing encrypted envelope to trusted clean storage', {
        cleanBucket: this.cleanBucket,
        cleanObjectKey,
        ciphertextLength: encrypted.serialized.length,
      });

      putResult = await this.storageProvider.putIfAbsent({
        bucket: this.cleanBucket,
        key: cleanObjectKey,
        body: encrypted.serialized,
        contentLength: encrypted.serialized.length,
        contentType: 'application/octet-stream',
        checksumSha256: cipherShaHex,
      });
    } catch (putErr) {
      if (putErr instanceof AlreadyExists) {
        this.logger?.warn(
          'Destination clean key already exists in clean storage (HTTP 412 / AlreadyExists)',
          {
            cleanBucket: this.cleanBucket,
            cleanObjectKey,
          },
        );

        // Check if this file_version is already recorded in cloud_objects (idempotent duplicate run)
        const existingCloudObj = await executor.query<{ id: string; storage_version_id: string }>(
          `SELECT id, storage_version_id FROM cloud_objects
           WHERE file_version_id = $1 AND zone = 'clean' AND bucket = $2 AND object_key = $3`,
          [job.fileVersionId, this.cleanBucket, cleanObjectKey],
        );

        if (existingCloudObj.rows.length > 0) {
          // Idempotent recovery: object already recorded in DB for this version
          await completePromotionJob(executor, job.id, 'PROMOTED');
          await executor.query(`UPDATE files SET status = 'PROMOTED' WHERE id = $1`, [job.fileId]);

          return {
            success: true,
            outcome: 'PROMOTED',
            fileId: job.fileId,
            fileVersionId: job.fileVersionId,
            cleanBucket: this.cleanBucket,
            cleanObjectKey,
            cleanStorageVersionId: existingCloudObj.rows[0]?.storage_version_id,
            sha256Ciphertext: cipherShaHex,
            sha256Plaintext: job.boundSha256,
            envelopeLength: encrypted.serialized.length,
          };
        }

        // Safe Orphan Reconciliation:
        // Storage write previously succeeded, but database transaction rolled back or crashed before commit.
        // We never assume DB rollback reverses object storage. Instead, verify the existing envelope cryptographically.
        let isReconciledOrphan = false;
        try {
          const headRes = await this.storageProvider.head({
            bucket: this.cleanBucket,
            key: cleanObjectKey,
          });

          if (headRes.versionId) {
            const getExisting = await this.storageProvider.getByVersion({
              bucket: this.cleanBucket,
              key: cleanObjectKey,
              versionId: headRes.versionId,
            });

            const chunks: Buffer[] = [];
            for await (const chunk of getExisting.body) {
              chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            }
            const existingEnvelope = Buffer.concat(chunks);

            // Cryptographically verify existing envelope using decryptBuffer and exact bound AAD
            const decryptedExisting = await decryptBuffer(existingEnvelope, {
              keyProvider: this.keyProvider,
              aad: {
                appId: job.applicationId,
                fileId: job.fileId,
                storageVersionId: job.boundStorageVersionId,
                sha256Plaintext: job.boundSha256,
              },
            });

            const existingPlainSha = crypto
              .createHash('sha256')
              .update(decryptedExisting)
              .digest('hex');
            if (timingSafeSha256Equal(existingPlainSha, job.boundSha256)) {
              this.logger?.info(
                'Safely reconciled orphan clean storage object from prior attempt',
                {
                  cleanObjectKey,
                  cleanStorageVersionId: headRes.versionId,
                },
              );

              isReconciledOrphan = true;
              putResult = {
                bucket: this.cleanBucket,
                key: cleanObjectKey,
                versionId: headRes.versionId,
                etag: headRes.etag,
                size: existingEnvelope.length,
              };
              cipherShaHex = crypto.createHash('sha256').update(existingEnvelope).digest('hex');
              const parsedHeader = parseSug1Header(existingEnvelope);
              const parsedCiphertext = extractCiphertext(existingEnvelope, parsedHeader);
              encrypted = {
                serialized: existingEnvelope,
                ciphertext: parsedCiphertext,
                header: parsedHeader,
                keyReference: this.kekId,
              };
            }
          }
        } catch (orphanErr) {
          this.logger?.warn('Failed to verify or adopt existing clean storage object', {
            error: (orphanErr as Error).message,
          });
        }

        if (!isReconciledOrphan) {
          await failPromotionJob(executor, job.id, {
            error: `Clean storage key '${cleanObjectKey}' already exists with conflicting or unverified content`,
            outcome: 'ALREADY_EXISTS',
            retryable: false,
          });

          await executor.query(`UPDATE files SET status = 'ERROR' WHERE id = $1`, [job.fileId]);

          return {
            success: false,
            outcome: 'ALREADY_EXISTS',
            fileId: job.fileId,
            fileVersionId: job.fileVersionId,
            error: 'Clean object already exists',
          };
        }
      } else {
        // Transient or unexpected storage error
        this.logger?.error('Storage putIfAbsent failed during clean publication', {
          error: (putErr as Error).message,
        });

        const isRetryable = putErr instanceof StorageError ? putErr.statusCode >= 500 : true;

        await failPromotionJob(executor, job.id, {
          error: (putErr as Error).message,
          outcome: 'STORAGE_FAILED',
          retryable: isRetryable,
        });

        await executor.query(`UPDATE files SET status = 'QUARANTINED' WHERE id = $1`, [job.fileId]);

        return {
          success: false,
          outcome: 'STORAGE_FAILED',
          fileId: job.fileId,
          fileVersionId: job.fileVersionId,
          error: (putErr as Error).message,
        };
      }
    }

    if (!putResult) {
      throw new Error(
        'Unexpected: putResult must be defined when progressing to database transaction',
      );
    }

    // 7. Atomic Database Transaction: cloud_objects, files, promotion_jobs, audit_append
    const boundShaBuffer = Buffer.from(job.boundSha256, 'hex');
    const cipherShaBuffer = Buffer.from(cipherShaHex, 'hex');
    const refs = {
      application_id: job.applicationId,
      file_id: job.fileId,
      file_version_id: job.fileVersionId,
      decision_id: job.decisionId,
    };
    const details = {
      bucket: this.cleanBucket,
      key: cleanObjectKey,
      storage_version_id: putResult.versionId,
      sha256_cipher: cipherShaHex,
      sha256_plain: job.boundSha256,
      size_bytes: encrypted.serialized.length,
      kek_id: this.kekId,
    };

    try {
      await executor.query('BEGIN');

      // 7a. Insert clean cloud_objects
      await executor.query(
        `INSERT INTO cloud_objects (
           file_version_id, zone, provider, bucket, object_key,
           storage_version_id, etag, size_bytes, sha256_plain, sha256_cipher,
           kek_id, enc_alg
         ) VALUES (
           $1, 'clean', $2, $3, $4,
           $5, $6, $7, $8, $9,
           $10, 'AES-256-GCM'
         )
         ON CONFLICT (file_version_id, zone, provider)
         DO UPDATE SET
           bucket = EXCLUDED.bucket,
           object_key = EXCLUDED.object_key,
           storage_version_id = EXCLUDED.storage_version_id,
           etag = EXCLUDED.etag,
           size_bytes = EXCLUDED.size_bytes,
           sha256_plain = EXCLUDED.sha256_plain,
           sha256_cipher = EXCLUDED.sha256_cipher`,
        [
          job.fileVersionId,
          this.provider,
          this.cleanBucket,
          cleanObjectKey,
          putResult.versionId,
          putResult.etag ?? null,
          encrypted.serialized.length,
          boundShaBuffer,
          cipherShaBuffer,
          this.kekId,
        ],
      );

      // 7b. Update file status to 'PROMOTED'
      await executor.query(`UPDATE files SET status = 'PROMOTED' WHERE id = $1`, [job.fileId]);

      // 7c. Update promotion_jobs status to 'SUCCEEDED'
      await executor.query(
        `UPDATE promotion_jobs
         SET status = 'SUCCEEDED',
             outcome = 'PROMOTED',
             finished_at = now(),
             locked_by = NULL,
             locked_at = NULL
         WHERE id = $1`,
        [job.id],
      );

      // 7d. Append audit event
      await executor.query(
        `SELECT audit_append('service', $1, 'FILE_PROMOTED', $2::jsonb, $3::jsonb)`,
        [this.workerId, JSON.stringify(refs), JSON.stringify(details)],
      );

      await executor.query('COMMIT');

      this.logger?.info('Artifact successfully promoted to trusted clean storage', {
        jobId: job.id,
        fileId: job.fileId,
        cleanKey: cleanObjectKey,
        storageVersionId: putResult.versionId,
      });

      return {
        success: true,
        outcome: 'PROMOTED',
        fileId: job.fileId,
        fileVersionId: job.fileVersionId,
        cleanBucket: this.cleanBucket,
        cleanObjectKey,
        cleanStorageVersionId: putResult.versionId,
        sha256Ciphertext: cipherShaHex,
        sha256Plaintext: job.boundSha256,
        envelopeLength: encrypted.serialized.length,
      };
    } catch (txErr) {
      await executor.query('ROLLBACK');

      this.logger?.error('Atomic transaction failed during promotion completion', {
        cleanKey: cleanObjectKey,
        error: (txErr as Error).message,
      });

      await failPromotionJob(executor, job.id, {
        error: `Database transaction rollback: ${(txErr as Error).message}`,
        outcome: 'AUDIT_FAILED',
        retryable: true,
      });

      // Ensure file does not remain falsely marked as PROMOTED
      await executor.query(`UPDATE files SET status = 'QUARANTINED' WHERE id = $1`, [job.fileId]);

      return {
        success: false,
        outcome: 'AUDIT_FAILED',
        fileId: job.fileId,
        fileVersionId: job.fileVersionId,
        error: (txErr as Error).message,
      };
    }
  }
}
