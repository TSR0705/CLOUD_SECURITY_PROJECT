import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import {
  type DatabaseExecutor,
  type ClaimedScanJob,
  type ReaperResult,
  claimScanJob,
  completeScanJob,
  failScanJob,
  reapExpiredJobs,
  generateWorkerId,
  timingSafeSha256Equal,
  DEFAULT_LEASE_TIMEOUT_MS,
  DEFAULT_REAPER_INTERVAL_MS,
  MAX_REAPER_INTERVAL_MS,
  CANONICAL_RECOVERY_SLA_MS,
  validateRecoveryBound,
  validateReaperInterval,
} from '@sug/shared';
import type { StorageProvider } from '@sug/storage';
import { VersionMissing, NotFound, InvalidRequest } from '@sug/storage';
import { ClamAvScanner, type ClamAvScanResult } from '@sug/scanner';

export {
  DEFAULT_LEASE_TIMEOUT_MS,
  DEFAULT_REAPER_INTERVAL_MS,
  MAX_REAPER_INTERVAL_MS,
  CANONICAL_RECOVERY_SLA_MS,
  validateRecoveryBound,
  validateReaperInterval,
};

export interface ScannerLogger {
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
  debug?(message: string, meta?: Record<string, unknown>): void;
}

export interface ScannerWorkerOptions {
  db: DatabaseExecutor;
  storageProvider: StorageProvider;
  clamavScanner?: ClamAvScanner;
  enableClamAv?: boolean;
  workerId?: string;
  leaseTimeoutMs?: number;
  pollIntervalMs?: number;
  reaperIntervalMs?: number;
  enableReaper?: boolean;
  tempDir?: string;
  logger?: ScannerLogger;
  now?: () => Date;
}

export interface ProcessJobResult {
  success: boolean;
  verified: boolean;
  clamav?: ClamAvScanResult;
  sha256?: string;
  size?: number;
  error?: string;
}

export class ScannerWorker {
  readonly workerId: string;
  readonly leaseTimeoutMs: number;
  readonly reaperIntervalMs: number;
  readonly clamavScanner?: ClamAvScanner | undefined;
  readonly enableClamAv: boolean;
  private readonly db: DatabaseExecutor;
  private readonly storageProvider: StorageProvider;
  private readonly pollIntervalMs: number;
  private readonly enableReaper: boolean;
  private readonly tempDir: string;
  private readonly logger: ScannerLogger;
  private readonly now: () => Date;
  private running = false;
  private activePromise: Promise<void> | null = null;
  private reaperPromise: Promise<void> | null = null;
  private sleepResolve: (() => void) | null = null;
  private reaperSleepResolve: (() => void) | null = null;
  private reaperExecuting = false;

  constructor(options: ScannerWorkerOptions) {
    this.db = options.db;
    this.storageProvider = options.storageProvider;
    this.workerId = options.workerId ?? generateWorkerId();
    this.leaseTimeoutMs = options.leaseTimeoutMs ?? DEFAULT_LEASE_TIMEOUT_MS;
    this.pollIntervalMs = options.pollIntervalMs ?? 1000;

    if (
      options.enableClamAv ||
      (options.enableClamAv === undefined && options.clamavScanner !== undefined)
    ) {
      this.clamavScanner = options.clamavScanner ?? new ClamAvScanner();
      this.enableClamAv = true;
    } else {
      this.clamavScanner = undefined;
      this.enableClamAv = false;
    }

    const rawReaperInterval =
      options.reaperIntervalMs ??
      (process.env.SCANNER_REAPER_INTERVAL_MS !== undefined
        ? Number(process.env.SCANNER_REAPER_INTERVAL_MS)
        : DEFAULT_REAPER_INTERVAL_MS);

    // Enforce canonical P13 reaper interval and recovery bound
    validateRecoveryBound(this.leaseTimeoutMs, rawReaperInterval);
    this.reaperIntervalMs = rawReaperInterval;
    this.enableReaper = options.enableReaper ?? true;

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
   * Starts the continuous background polling and processing loop, as well as the
   * periodic reaper sweep loop if enabled.
   */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.activePromise = this.loop();
    if (this.enableReaper) {
      this.reaperPromise = this.reaperLoop();
    }
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
    if (this.reaperSleepResolve) {
      this.reaperSleepResolve();
      this.reaperSleepResolve = null;
    }
    if (this.activePromise) {
      await this.activePromise;
      this.activePromise = null;
    }
    if (this.reaperPromise) {
      await this.reaperPromise;
      this.reaperPromise = null;
    }
  }

  /**
   * Triggers an immediate one-off reaper execution.
   */
  async reapNow(): Promise<ReaperResult> {
    return reapExpiredJobs(this.db, {
      leaseTimeoutMs: this.leaseTimeoutMs,
      now: this.now,
    });
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

      // 7. If ClamAV scanning is enabled, scan local staged artifact via INSTREAM
      if (this.enableClamAv && this.clamavScanner) {
        this.logger.info('Invoking ClamAV INSTREAM scan', { jobId: job.id });
        const clamStream = fs.createReadStream(localArtifactPath);
        const clamavResult = await this.clamavScanner.scanStream(clamStream);

        if (clamavResult.status === 'CLEAN') {
          await this.db.query(
            `INSERT INTO scan_results (
               scan_job_id, file_version_id, check_id, engine, engine_version,
               outcome, reason_code, severity, confidence, evidence,
               scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
             ) VALUES (
               $1, $2, 'scanner.clamav', 'clamav', '1.4.6',
               'PASS', 'CLEAN', 'INFO', 'CONFIRMED', $3::jsonb,
               $4, $5, $6, $7
             )`,
            [
              job.id,
              job.fileVersionId,
              JSON.stringify({
                status: 'CLEAN',
                rawResponse: clamavResult.rawResponse,
              }),
              storageVersionId,
              Buffer.from(calculatedSha256, 'hex'),
              calculatedSize,
              clamavResult.durationMs,
            ],
          );

          await completeScanJob(this.db, job.id, {
            workerId: this.workerId,
            now: this.now,
          });

          this.logger.info('Scan job passed ClamAV scan', {
            jobId: job.id,
            durationMs: clamavResult.durationMs,
          });

          return {
            success: true,
            verified: true,
            clamav: clamavResult,
            sha256: calculatedSha256,
            size: calculatedSize,
          };
        } else if (clamavResult.status === 'FOUND') {
          this.logger.warn('ClamAV detected malware signature', {
            jobId: job.id,
            signature: clamavResult.signature,
          });

          await this.db.query(
            `INSERT INTO scan_results (
               scan_job_id, file_version_id, check_id, engine, engine_version,
               outcome, reason_code, severity, confidence, evidence,
               scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
             ) VALUES (
               $1, $2, 'scanner.clamav', 'clamav', '1.4.6',
               'FAIL', 'MALWARE_DETECTED', 'CRITICAL', 'CONFIRMED', $3::jsonb,
               $4, $5, $6, $7
             )`,
            [
              job.id,
              job.fileVersionId,
              JSON.stringify({
                status: 'FOUND',
                signature: clamavResult.signature,
                rawResponse: clamavResult.rawResponse,
              }),
              storageVersionId,
              Buffer.from(calculatedSha256, 'hex'),
              calculatedSize,
              clamavResult.durationMs,
            ],
          );

          // Job completed execution; malware finding recorded for future decision engine
          await completeScanJob(this.db, job.id, {
            workerId: this.workerId,
            now: this.now,
          });

          return {
            success: true,
            verified: true,
            clamav: clamavResult,
            sha256: calculatedSha256,
            size: calculatedSize,
          };
        } else {
          // ClamAV scanner ERROR: fail closed
          this.logger.error('ClamAV scan failed with error', {
            jobId: job.id,
            error: clamavResult.error,
          });

          await this.db.query(
            `INSERT INTO scan_results (
               scan_job_id, file_version_id, check_id, engine, engine_version,
               outcome, reason_code, severity, confidence, evidence,
               scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
             ) VALUES (
               $1, $2, 'scanner.clamav', 'clamav', '1.4.6',
               'ERROR', 'SCANNER_ERROR', 'HIGH', 'CONFIRMED', $3::jsonb,
               $4, $5, $6, $7
             )`,
            [
              job.id,
              job.fileVersionId,
              JSON.stringify({
                status: 'ERROR',
                error: clamavResult.error,
                rawResponse: clamavResult.rawResponse,
              }),
              storageVersionId,
              Buffer.from(calculatedSha256, 'hex'),
              calculatedSize,
              clamavResult.durationMs,
            ],
          );

          const scanError = new Error(clamavResult.error || 'ClamAV scanner error');
          await failScanJob(this.db, job.id, {
            workerId: this.workerId,
            error: scanError,
            retryable: true,
            now: this.now,
          });

          return {
            success: false,
            verified: true,
            clamav: clamavResult,
            sha256: calculatedSha256,
            size: calculatedSize,
            error: scanError.message,
          };
        }
      }

      // 8. Transition job to SUCCEEDED (baseline skeleton / compatibility mode)
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

  private async reaperLoop(): Promise<void> {
    while (this.running) {
      if (!this.reaperExecuting) {
        this.reaperExecuting = true;
        try {
          const result = await this.reapNow();
          if (result.reapedCount > 0) {
            this.logger.info('Reaper sweep completed', {
              reapedCount: result.reapedCount,
              requeuedCount: result.requeuedCount,
              deadCount: result.deadCount,
            });
          }
        } catch (err) {
          this.logger.error('Error in reaper loop sweep', {
            error: (err as Error).message,
          });
        } finally {
          this.reaperExecuting = false;
        }
      }

      if (this.running) {
        await this.sleepReaper(this.reaperIntervalMs);
      }
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      let timer: NodeJS.Timeout | null = null;
      const onWake = () => {
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
        if (this.sleepResolve === onWake) {
          this.sleepResolve = null;
        }
        resolve();
      };
      this.sleepResolve = onWake;
      timer = setTimeout(onWake, ms);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
    });
  }

  private sleepReaper(ms: number): Promise<void> {
    return new Promise((resolve) => {
      let timer: NodeJS.Timeout | null = null;
      const onWake = () => {
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
        if (this.reaperSleepResolve === onWake) {
          this.reaperSleepResolve = null;
        }
        resolve();
      };
      this.reaperSleepResolve = onWake;
      timer = setTimeout(onWake, ms);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
    });
  }
}
