import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import {
  type DatabaseExecutor,
  type ClaimedScanJob,
  claimScanJob,
  completeScanJob,
  failScanJob,
  generateWorkerId,
  timingSafeSha256Equal,
} from '@sug/shared';
import type { StorageProvider } from '@sug/storage';
import { VersionMissing, NotFound, InvalidRequest } from '@sug/storage';

export interface ScannerLogger {
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
  debug?(message: string, meta?: Record<string, unknown>): void;
}

export interface ScannerWorkerOptions {
  db: DatabaseExecutor;
  storageProvider: StorageProvider;
  workerId?: string;
  leaseTimeoutMs?: number;
  pollIntervalMs?: number;
  tempDir?: string;
  logger?: ScannerLogger;
  now?: () => Date;
}

export interface ProcessJobResult {
  success: boolean;
  verified: boolean;
  sha256?: string;
  size?: number;
  error?: string;
}

export class ScannerWorker {
  readonly workerId: string;
  private readonly db: DatabaseExecutor;
  private readonly storageProvider: StorageProvider;
  private readonly leaseTimeoutMs: number;
  private readonly pollIntervalMs: number;
  private readonly tempDir: string;
  private readonly logger: ScannerLogger;
  private readonly now: () => Date;
  private running = false;
  private activePromise: Promise<void> | null = null;
  private sleepResolve: (() => void) | null = null;

  constructor(options: ScannerWorkerOptions) {
    this.db = options.db;
    this.storageProvider = options.storageProvider;
    this.workerId = options.workerId ?? generateWorkerId();
    this.leaseTimeoutMs = options.leaseTimeoutMs ?? 300_000;
    this.pollIntervalMs = options.pollIntervalMs ?? 1000;
    this.tempDir =
      options.tempDir ??
      process.env.SCANNER_TMPFS_DIR ??
      (process.platform === 'win32' ? path.join(os.tmpdir(), 'sug-scan') : '/tmp/sug-scan');
    this.now = options.now ?? (() => new Date());
    this.logger = options.logger ?? {
      info: () => {},
      warn: () => {},
      error: () => {},
    };
  }

  /**
   * Claims and processes a single job if available.
   * Returns the processed job or null if no job was claimed.
   */
  async runOnce(): Promise<{ job: ClaimedScanJob | null; result?: ProcessJobResult }> {
    const job = await claimScanJob(this.db, {
      workerId: this.workerId,
      leaseTimeoutMs: this.leaseTimeoutMs,
      now: this.now,
    });

    if (!job) {
      return { job: null };
    }

    const result = await this.processJob(job);
    return { job, result };
  }

  /**
   * Starts the continuous background polling and processing loop.
   */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.activePromise = this.loop();
  }

  /**
   * Initiates graceful shutdown, allowing any currently executing job to conclude.
   */
  async stop(): Promise<void> {
    if (!this.running) return;
    this.running = false;
    if (this.sleepResolve) {
      this.sleepResolve();
      this.sleepResolve = null;
    }
    if (this.activePromise) {
      await this.activePromise;
      this.activePromise = null;
    }
  }

  isRunning(): boolean {
    return this.running;
  }

  /**
   * Processes a claimed scan job with exact-version storage retrieval,
   * local staging in per-job tmpfs directory, cryptographic identity verification,
   * and placeholder finding persistence.
   */
  async processJob(job: ClaimedScanJob): Promise<ProcessJobResult> {
    const startTime = this.now().getTime();
    const { bucket, objectKey, storageVersionId, sizeBytes, sha256Ingest } = job.artifact;

    this.logger.info('Processing scan job', {
      jobId: job.id,
      fileVersionId: job.fileVersionId,
      workerId: this.workerId,
      attempt: job.attempts,
    });

    // 1. Fail closed if storageVersionId is missing or invalid
    if (
      !storageVersionId ||
      storageVersionId.trim() === '' ||
      storageVersionId.toLowerCase() === 'null' ||
      storageVersionId.toLowerCase() === 'latest'
    ) {
      const err = new Error(
        `Invalid or missing storage version ID '${storageVersionId}'; failing closed`,
      );
      this.logger.error(err.message, { jobId: job.id });
      await failScanJob(this.db, job.id, {
        workerId: this.workerId,
        error: err,
        retryable: false,
        now: this.now,
      });
      return { success: false, verified: false, error: err.message };
    }

    // 2. Prepare isolated per-job temporary directory
    const jobDir = path.join(this.tempDir, job.id);
    await fs.promises.mkdir(jobDir, { recursive: true });
    const localArtifactPath = path.join(jobDir, 'artifact.bin');

    try {
      // 3. Fetch exact VersionId from StorageProvider
      let getResult;
      try {
        getResult = await this.storageProvider.getByVersion({
          bucket,
          key: objectKey,
          versionId: storageVersionId,
        });
      } catch (storageErr) {
        const isNonRetryable =
          storageErr instanceof VersionMissing ||
          storageErr instanceof NotFound ||
          storageErr instanceof InvalidRequest;

        this.logger.error('Storage getByVersion failed', {
          jobId: job.id,
          error: (storageErr as Error).message,
          retryable: !isNonRetryable,
        });

        await failScanJob(this.db, job.id, {
          workerId: this.workerId,
          error: storageErr as Error,
          retryable: !isNonRetryable,
          now: this.now,
        });

        return {
          success: false,
          verified: false,
          error: (storageErr as Error).message,
        };
      }

      // 4. Stream to local file while computing SHA-256 and byte count in real time
      const hash = crypto.createHash('sha256');
      let byteCount = 0;

      const fileWriteStream = fs.createWriteStream(localArtifactPath);
      getResult.body.on('data', (chunk: Buffer) => {
        hash.update(chunk);
        byteCount += chunk.length;
      });

      await pipeline(getResult.body, fileWriteStream);

      const calculatedSha256 = hash.digest('hex').toLowerCase();
      const calculatedSize = byteCount;
      const durationMs = this.now().getTime() - startTime;

      // 5. Cryptographic Identity Verification against ingest metadata
      const shaMatches = timingSafeSha256Equal(calculatedSha256, sha256Ingest);
      const sizeMatches = calculatedSize === sizeBytes;
      const versionMatches = getResult.versionId === storageVersionId;

      if (!shaMatches || !sizeMatches || !versionMatches) {
        const mismatchReason = `Cryptographic identity mismatch: shaMatch=${shaMatches}, sizeMatch=${sizeMatches}, versionMatch=${versionMatches}`;
        this.logger.error(mismatchReason, {
          jobId: job.id,
          calculatedSha256,
          expectedSha256: sha256Ingest,
          calculatedSize,
          expectedSize: sizeBytes,
        });

        // Persist mismatch finding in scan_results
        await this.db.query(
          `INSERT INTO scan_results (
             scan_job_id, file_version_id, check_id, engine, engine_version,
             outcome, reason_code, severity, confidence, evidence,
             scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
           ) VALUES (
             $1, $2, 'scanner.skeleton', 'scanner.skeleton', '0.1.0',
             'FAIL', 'IDENTITY_MISMATCH', 'CRITICAL', 'CONFIRMED', $3::jsonb,
             $4, $5, $6, $7
           )`,
          [
            job.id,
            job.fileVersionId,
            JSON.stringify({
              verified: false,
              calculatedSha256,
              expectedSha256: sha256Ingest,
              calculatedSize,
              expectedSize: sizeBytes,
            }),
            storageVersionId,
            Buffer.from(calculatedSha256, 'hex'),
            calculatedSize,
            durationMs,
          ],
        );

        // Terminal failure: corrupted or modified artifact in quarantine
        await failScanJob(this.db, job.id, {
          workerId: this.workerId,
          error: new Error(mismatchReason),
          retryable: false,
          now: this.now,
        });

        return {
          success: false,
          verified: false,
          sha256: calculatedSha256,
          size: calculatedSize,
          error: mismatchReason,
        };
      }

      // 6. Identity matches! Persist canonical placeholder finding
      await this.db.query(
        `INSERT INTO scan_results (
           scan_job_id, file_version_id, check_id, engine, engine_version,
           outcome, reason_code, severity, confidence, evidence,
           scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
         ) VALUES (
           $1, $2, 'scanner.skeleton', 'scanner.skeleton', '0.1.0',
           'PASS', 'IDENTITY_VERIFIED', 'INFO', 'CONFIRMED', $3::jsonb,
           $4, $5, $6, $7
         )`,
        [
          job.id,
          job.fileVersionId,
          JSON.stringify({
            verified: true,
            matchedIngestIdentity: true,
            sha256: calculatedSha256,
            sizeBytes: calculatedSize,
          }),
          storageVersionId,
          Buffer.from(calculatedSha256, 'hex'),
          calculatedSize,
          durationMs,
        ],
      );

      // 7. Transition job to SUCCEEDED
      await completeScanJob(this.db, job.id, {
        workerId: this.workerId,
        now: this.now,
      });

      this.logger.info('Scan job succeeded and verified', {
        jobId: job.id,
        durationMs,
        sha256: calculatedSha256,
      });

      return {
        success: true,
        verified: true,
        sha256: calculatedSha256,
        size: calculatedSize,
      };
    } catch (unexpectedErr) {
      this.logger.error('Unexpected error processing scan job', {
        jobId: job.id,
        error: (unexpectedErr as Error).message,
      });

      await failScanJob(this.db, job.id, {
        workerId: this.workerId,
        error: unexpectedErr as Error,
        retryable: true,
        now: this.now,
      });

      return {
        success: false,
        verified: false,
        error: (unexpectedErr as Error).message,
      };
    } finally {
      // 8. Always clean up isolated per-job working directory
      try {
        await fs.promises.rm(jobDir, { recursive: true, force: true });
      } catch (cleanupErr) {
        this.logger.warn('Failed to clean up job directory', {
          jobDir,
          error: (cleanupErr as Error).message,
        });
      }
    }
  }

  private async loop(): Promise<void> {
    while (this.running) {
      try {
        const { job } = await this.runOnce();
        if (!job && this.running) {
          await this.sleep(this.pollIntervalMs);
        }
      } catch (err) {
        this.logger.error('Error in scanner worker loop iteration', {
          error: (err as Error).message,
        });
        if (this.running) {
          await this.sleep(this.pollIntervalMs);
        }
      }
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      this.sleepResolve = resolve;
      setTimeout(() => {
        if (this.sleepResolve === resolve) {
          this.sleepResolve = null;
        }
        resolve();
      }, ms);
    });
  }
}
