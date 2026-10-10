import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import {
  type DatabaseExecutor,
  type ClaimedScanJob,
  type ReaperResult,
  type SeverityLevel,
  type ConfidenceLevel,
  type CheckId,
  type CanonicalReasonCode,
  type FindingOutcome,
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
import {
  ClamAvScanner,
  type ClamAvScanResult,
  YaraScanner,
  type YaraScanResult,
} from '@sug/scanner';
import {
  inspectArchive,
  type ArchiveInspectionResult,
  type ArchiveInspectionBudget,
  inspectPdf,
  type PdfCheckResult,
  inspectOoxml,
  type OoxmlMacroResult,
  type OoxmlRelationshipResult,
  inspectImageTrailing,
  type ImageTrailingResult,
  inspectEmbeddedSignatures,
  type EmbeddedSignatureResult,
  inspectPolyglot,
  type PolyglotResult,
} from '@sug/security-engine';

export {
  DEFAULT_LEASE_TIMEOUT_MS,
  DEFAULT_REAPER_INTERVAL_MS,
  MAX_REAPER_INTERVAL_MS,
  CANONICAL_RECOVERY_SLA_MS,
  validateRecoveryBound,
  validateReaperInterval,
};

export const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export const CONFIDENCE_ORDER: Record<ConfidenceLevel, number> = {
  CONFIRMED: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
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
  yaraScanner?: YaraScanner;
  enableYara?: boolean;
  enableArchive?: boolean;
  archiveBudget?: Partial<ArchiveInspectionBudget>;
  archiveAllowed?: boolean;
  enableFormatChecks?: boolean;
  rulesDir?: string;
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
  clamav?: ClamAvScanResult | undefined;
  yara?: YaraScanResult | undefined;
  archive?: ArchiveInspectionResult | undefined;
  pdf?: PdfCheckResult | undefined;
  ooxmlMacro?: OoxmlMacroResult | undefined;
  ooxmlRelationship?: OoxmlRelationshipResult | undefined;
  imageTrailing?: ImageTrailingResult | undefined;
  embeddedSig?: EmbeddedSignatureResult | undefined;
  polyglot?: PolyglotResult | undefined;
  sha256?: string | undefined;
  size?: number | undefined;
  error?: string | undefined;
}

export class ScannerWorker {
  readonly workerId: string;
  readonly leaseTimeoutMs: number;
  readonly reaperIntervalMs: number;
  readonly clamavScanner?: ClamAvScanner | undefined;
  readonly enableClamAv: boolean;
  readonly yaraScanner?: YaraScanner | undefined;
  readonly enableYara: boolean;
  readonly enableArchive: boolean;
  readonly archiveBudget?: Partial<ArchiveInspectionBudget> | undefined;
  readonly archiveAllowed?: boolean | undefined;
  readonly enableFormatChecks: boolean;
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

    if (
      options.enableYara ||
      (options.enableYara === undefined && options.yaraScanner !== undefined)
    ) {
      this.yaraScanner =
        options.yaraScanner ??
        new YaraScanner({
          rulesPath: options.rulesDir,
        });
      this.enableYara = true;
    } else {
      this.yaraScanner = undefined;
      this.enableYara = false;
    }

    this.enableArchive = options.enableArchive ?? true;
    this.archiveBudget = options.archiveBudget;
    this.archiveAllowed = options.archiveAllowed;
    this.enableFormatChecks =
      options.enableFormatChecks ?? process.env.SCANNER_ENABLE_FORMAT_CHECKS === 'true';

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
   * Persists a deterministic scan finding record to scan_results with idempotency.
   */
  async recordFinding(params: {
    jobId: string;
    fileVersionId: string;
    checkId: CheckId;
    engine: string;
    engineVersion?: string | undefined;
    signatureVersion?: string | undefined;
    outcome: FindingOutcome;
    reasonCode: CanonicalReasonCode;
    severity: SeverityLevel;
    confidence: ConfidenceLevel;
    evidence: Record<string, unknown>;
    storageVersionId: string;
    sha256Hex: string;
    sizeBytes: number;
    durationMs: number;
  }): Promise<void> {
    const existing = await this.db.query<{
      file_version_id: string;
      scanned_storage_version_id: string;
      scanned_sha256: Buffer | string;
      scanned_size: string | number;
    }>(
      `SELECT file_version_id, scanned_storage_version_id, scanned_sha256, scanned_size
       FROM scan_results
       WHERE scan_job_id = $1 AND check_id = $2`,
      [params.jobId, params.checkId],
    );

    if (existing.rows.length > 0) {
      const row = existing.rows[0]!;
      const existingSha = Buffer.isBuffer(row.scanned_sha256)
        ? row.scanned_sha256.toString('hex').toLowerCase()
        : String(row.scanned_sha256)
            .replace(/^(?:0x|\\x)/i, '')
            .toLowerCase();

      if (
        row.file_version_id !== params.fileVersionId ||
        row.scanned_storage_version_id !== params.storageVersionId ||
        existingSha !== params.sha256Hex.toLowerCase() ||
        Number(row.scanned_size) !== params.sizeBytes
      ) {
        throw new Error(
          `Artifact identity conflict on scan job retry: existing finding for check '${params.checkId}' belongs to a different artifact identity (file_version_id=${row.file_version_id}, storage_version_id=${row.scanned_storage_version_id}, sha256=${existingSha}) than current scan attempt (file_version_id=${params.fileVersionId}, storage_version_id=${params.storageVersionId}, sha256=${params.sha256Hex})`,
        );
      }
      // Exact same artifact identity: idempotent retry, preserve existing finding
      return;
    }

    await this.db.query(
      `INSERT INTO scan_results (
         scan_job_id, file_version_id, check_id, engine, engine_version,
         signature_version, outcome, reason_code, severity, confidence,
         evidence, scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
       ) VALUES (
         $1, $2, $3, $4, $5,
         $6, $7, $8, $9, $10,
         $11::jsonb, $12, $13, $14, $15
       )
       ON CONFLICT (scan_job_id, check_id) DO NOTHING`,
      [
        params.jobId,
        params.fileVersionId,
        params.checkId,
        params.engine,
        params.engineVersion ?? null,
        params.signatureVersion ?? null,
        params.outcome,
        params.reasonCode,
        params.severity,
        params.confidence,
        JSON.stringify(params.evidence),
        params.storageVersionId,
        Buffer.from(params.sha256Hex, 'hex'),
        params.sizeBytes,
        params.durationMs,
      ],
    );
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

      // 6. Identity matches! Check that any pre-existing findings on retry match the verified identity
      const priorFindings = await this.db.query<{
        check_id: string;
        file_version_id: string;
        scanned_storage_version_id: string;
        scanned_sha256: Buffer | string;
        scanned_size: string | number;
      }>(
        `SELECT check_id, file_version_id, scanned_storage_version_id, scanned_sha256, scanned_size
         FROM scan_results WHERE scan_job_id = $1`,
        [job.id],
      );

      for (const prior of priorFindings.rows) {
        const priorSha = Buffer.isBuffer(prior.scanned_sha256)
          ? prior.scanned_sha256.toString('hex').toLowerCase()
          : String(prior.scanned_sha256)
              .replace(/^(?:0x|\\x)/i, '')
              .toLowerCase();

        if (
          prior.file_version_id !== job.fileVersionId ||
          prior.scanned_storage_version_id !== storageVersionId ||
          priorSha !== calculatedSha256 ||
          Number(prior.scanned_size) !== calculatedSize
        ) {
          const conflictReason = `Artifact identity conflict on scan retry: pre-existing finding for check '${prior.check_id}' belongs to mismatched artifact identity; failing closed`;
          this.logger.error(conflictReason, { jobId: job.id, priorFinding: prior });
          await failScanJob(this.db, job.id, {
            workerId: this.workerId,
            error: new Error(conflictReason),
            retryable: false,
            now: this.now,
          });
          return {
            success: false,
            verified: false,
            sha256: calculatedSha256,
            size: calculatedSize,
            error: conflictReason,
          };
        }
      }

      // Persist canonical placeholder finding
      await this.db.query(
        `INSERT INTO scan_results (
           scan_job_id, file_version_id, check_id, engine, engine_version,
           outcome, reason_code, severity, confidence, evidence,
           scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
         ) VALUES (
           $1, $2, 'scanner.skeleton', 'scanner.skeleton', '0.1.0',
           'PASS', 'IDENTITY_VERIFIED', 'INFO', 'CONFIRMED', $3::jsonb,
           $4, $5, $6, $7
         )
         ON CONFLICT (scan_job_id, check_id) DO NOTHING`,
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

      let clamavResult: ClamAvScanResult | undefined;

      // 7. If ClamAV scanning is enabled, scan local staged artifact via INSTREAM
      if (this.enableClamAv && this.clamavScanner) {
        this.logger.info('Invoking ClamAV INSTREAM scan', { jobId: job.id });
        const clamStream = fs.createReadStream(localArtifactPath);
        clamavResult = await this.clamavScanner.scanStream(clamStream);

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

          this.logger.info('Scan job passed ClamAV scan', {
            jobId: job.id,
            durationMs: clamavResult.durationMs,
          });
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

      let yaraResult: YaraScanResult | undefined;

      // 8. If YARA scanning is enabled, scan local staged artifact with YARA-X
      if (this.enableYara && this.yaraScanner) {
        this.logger.info('Invoking YARA-X scan', { jobId: job.id });
        yaraResult = await this.yaraScanner.scanFile(localArtifactPath);

        if (yaraResult.status === 'CLEAN') {
          await this.db.query(
            `INSERT INTO scan_results (
               scan_job_id, file_version_id, check_id, engine, engine_version,
               signature_version, outcome, reason_code, severity, confidence,
               evidence, scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
             ) VALUES (
               $1, $2, 'scanner.yara', 'yara-x', $3,
               $4, 'PASS', 'CLEAN', 'INFO', 'CONFIRMED',
               $5::jsonb, $6, $7, $8, $9
             )`,
            [
              job.id,
              job.fileVersionId,
              yaraResult.engineVersion,
              yaraResult.signatureVersion,
              JSON.stringify({
                status: 'CLEAN',
                matches: [],
                rawOutput: yaraResult.rawOutput,
              }),
              storageVersionId,
              Buffer.from(calculatedSha256, 'hex'),
              calculatedSize,
              yaraResult.durationMs,
            ],
          );

          this.logger.info('Scan job passed YARA-X scan (no rules matched)', {
            jobId: job.id,
            durationMs: yaraResult.durationMs,
          });
        } else if (yaraResult.status === 'MATCH') {
          this.logger.warn('YARA-X detected matching security rule(s)', {
            jobId: job.id,
            matchCount: yaraResult.matches.length,
            matches: yaraResult.matches.map((m) => m.identifier),
          });

          // Determine overall severity and confidence from the highest matching rule
          let overallSeverity: SeverityLevel = 'INFO';
          let overallConfidence: ConfidenceLevel = 'LOW';
          let primaryRuleIdentifier = yaraResult.matches[0]?.identifier ?? 'unknown';

          for (const m of yaraResult.matches) {
            if (SEVERITY_ORDER[m.meta.severity] > SEVERITY_ORDER[overallSeverity]) {
              overallSeverity = m.meta.severity;
              primaryRuleIdentifier = m.identifier;
            }
            if (CONFIDENCE_ORDER[m.meta.confidence] > CONFIDENCE_ORDER[overallConfidence]) {
              overallConfidence = m.meta.confidence;
            }
          }

          await this.db.query(
            `INSERT INTO scan_results (
               scan_job_id, file_version_id, check_id, engine, engine_version,
               signature_version, outcome, reason_code, severity, confidence,
               evidence, scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
             ) VALUES (
               $1, $2, 'scanner.yara', 'yara-x', $3,
               $4, 'FAIL', 'MALWARE_DETECTED', $5, $6,
               $7::jsonb, $8, $9, $10, $11
             )`,
            [
              job.id,
              job.fileVersionId,
              yaraResult.engineVersion,
              yaraResult.signatureVersion,
              overallSeverity,
              overallConfidence,
              JSON.stringify({
                status: 'MATCH',
                primaryRule: primaryRuleIdentifier,
                matchedRules: yaraResult.matches.map((m) => m.identifier),
                matches: yaraResult.matches,
                rawOutput: yaraResult.rawOutput,
              }),
              storageVersionId,
              Buffer.from(calculatedSha256, 'hex'),
              calculatedSize,
              yaraResult.durationMs,
            ],
          );
        } else {
          // YARA-X scanner ERROR: fail closed
          this.logger.error('YARA-X scan failed with error', {
            jobId: job.id,
            error: yaraResult.error,
          });

          await this.db.query(
            `INSERT INTO scan_results (
               scan_job_id, file_version_id, check_id, engine, engine_version,
               signature_version, outcome, reason_code, severity, confidence,
               evidence, scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
             ) VALUES (
               $1, $2, 'scanner.yara', 'yara-x', $3,
               $4, 'ERROR', 'SCANNER_ERROR', 'HIGH', 'CONFIRMED',
               $5::jsonb, $6, $7, $8, $9
             )`,
            [
              job.id,
              job.fileVersionId,
              yaraResult.engineVersion,
              yaraResult.signatureVersion,
              JSON.stringify({
                status: 'ERROR',
                error: yaraResult.error,
                rawOutput: yaraResult.rawOutput,
              }),
              storageVersionId,
              Buffer.from(calculatedSha256, 'hex'),
              calculatedSize,
              yaraResult.durationMs,
            ],
          );

          const scanError = new Error(yaraResult.error || 'YARA-X scanner error');
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
            yara: yaraResult,
            sha256: calculatedSha256,
            size: calculatedSize,
            error: scanError.message,
          };
        }
      }

      let origName = path.basename(objectKey).toLowerCase();
      let policyDoc: Record<string, unknown> | null = null;

      // Try resolving upload session from objectKey identifier (last UUID in path is upload session ID)
      const uuidMatches = objectKey.match(
        /[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi,
      );
      const sessionId = uuidMatches ? uuidMatches[uuidMatches.length - 1] : undefined;
      if (sessionId) {
        try {
          const sessionQuery = await this.db.query<{
            original_filename: string;
            policy_document: Record<string, unknown> | null;
          }>(
            `SELECT us.original_filename, sp.document AS policy_document
               FROM upload_sessions us
               LEFT JOIN security_policies sp ON sp.id = us.policy_id
               WHERE us.id = $1`,
            [sessionId],
          );
          if (sessionQuery.rows.length > 0) {
            if (sessionQuery.rows[0]!.original_filename) {
              origName = sessionQuery.rows[0]!.original_filename.toLowerCase();
            }
            policyDoc = sessionQuery.rows[0]!.policy_document;
          }
        } catch (dbErr) {
          this.logger.warn('Failed to query upload session / policy for archive check', {
            jobId: job.id,
            error: (dbErr as Error).message,
          });
        }
      }

      const isArchiveExt =
        origName.endsWith('.zip') ||
        origName.endsWith('.docx') ||
        origName.endsWith('.xlsx') ||
        origName.endsWith('.pptx') ||
        origName.endsWith('.jar') ||
        origName.endsWith('.odt') ||
        origName.endsWith('.ods') ||
        origName.endsWith('.odp');
      const isOoxml =
        origName.endsWith('.docx') || origName.endsWith('.xlsx') || origName.endsWith('.pptx');

      let archiveResult: ArchiveInspectionResult | undefined;

      // 9. If archive inspection is enabled, check if artifact is a ZIP or OOXML container
      if (this.enableArchive) {
        let isZipMagic = false;
        try {
          const headerBuf = Buffer.alloc(4);
          const fd = await fs.promises.open(localArtifactPath, 'r');
          await fd.read(headerBuf, 0, 4, 0);
          await fd.close();
          isZipMagic = headerBuf.equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
        } catch {
          // ignore stat/read failure here
        }

        if (isZipMagic || isArchiveExt) {
          this.logger.info('Invoking archive security inspection', {
            jobId: job.id,
            isZipMagic,
            isArchiveExt,
            isOoxml,
          });

          const archiveAllowed =
            this.archiveAllowed !== undefined
              ? this.archiveAllowed
              : policyDoc?.archiveAllowed !== undefined
                ? Boolean(policyDoc.archiveAllowed)
                : true;

          const budget = {
            ...(policyDoc?.archive || {}),
            ...(this.archiveBudget || {}),
          };

          archiveResult = await inspectArchive({
            filePath: localArtifactPath,
            budget,
            archiveAllowed,
            isOoxml,
          });

          const outcome =
            archiveResult.status === 'CLEAN'
              ? 'PASS'
              : archiveResult.status === 'REJECTED'
                ? 'FAIL'
                : 'ERROR';

          await this.db.query(
            `INSERT INTO scan_results (
               scan_job_id, file_version_id, check_id, engine, engine_version,
               outcome, reason_code, severity, confidence, evidence,
               scanned_storage_version_id, scanned_sha256, scanned_size, duration_ms
             ) VALUES (
               $1, $2, 'scanner.archive', 'yauzl', '3.4.0',
               $3, $4, $5, $6, $7::jsonb,
               $8, $9, $10, $11
             )`,
            [
              job.id,
              job.fileVersionId,
              outcome,
              archiveResult.reasonCode,
              archiveResult.severity,
              archiveResult.confidence,
              JSON.stringify({
                status: archiveResult.status,
                reasonCode: archiveResult.reasonCode,
                reason: archiveResult.reason,
                entryCount: archiveResult.entryCount,
                totalCompressedBytes: archiveResult.totalCompressedBytes,
                totalDecompressedBytes: archiveResult.totalDecompressedBytes,
                compressionRatio: archiveResult.compressionRatio,
                maxNestingDepth: archiveResult.maxNestingDepth,
                durationMs: archiveResult.durationMs,
                workerRssBytes: archiveResult.workerRssBytes,
                details: archiveResult.details,
              }),
              storageVersionId,
              Buffer.from(calculatedSha256, 'hex'),
              calculatedSize,
              archiveResult.durationMs,
            ],
          );

          if (archiveResult.status === 'ERROR') {
            this.logger.error('Archive inspection failed with error', {
              jobId: job.id,
              reason: archiveResult.reason,
            });

            const archiveError = new Error(archiveResult.reason || 'Archive inspection error');
            await failScanJob(this.db, job.id, {
              workerId: this.workerId,
              error: archiveError,
              retryable: true,
              now: this.now,
            });

            return {
              success: false,
              verified: true,
              clamav: clamavResult,
              yara: yaraResult,
              archive: archiveResult,
              sha256: calculatedSha256,
              size: calculatedSize,
              error: archiveError.message,
            };
          } else if (archiveResult.status === 'REJECTED') {
            this.logger.warn('Archive security inspection detected violation', {
              jobId: job.id,
              reasonCode: archiveResult.reasonCode,
              reason: archiveResult.reason,
            });
          } else {
            this.logger.info('Archive passed security inspection', {
              jobId: job.id,
              entryCount: archiveResult.entryCount,
              durationMs: archiveResult.durationMs,
            });
          }
        }
      }

      let pdfResult: PdfCheckResult | undefined;
      let ooxmlMacroResult: OoxmlMacroResult | undefined;
      let ooxmlRelationshipResult: OoxmlRelationshipResult | undefined;
      let imageTrailingResult: ImageTrailingResult | undefined;
      let embeddedSigResult: EmbeddedSignatureResult | undefined;
      let polyglotResult: PolyglotResult | undefined;

      // 10. If format checks are enabled, execute P17 format-specific checks
      if (this.enableFormatChecks) {
        let headerBuffer = Buffer.alloc(0);
        try {
          const fd = await fs.promises.open(localArtifactPath, 'r');
          const tmpBuf = Buffer.alloc(1024);
          const { bytesRead } = await fd.read(tmpBuf, 0, 1024, 0);
          await fd.close();
          headerBuffer = tmpBuf.subarray(0, bytesRead);
        } catch {
          // ignore
        }

        // A. PDF Active-Content check (scan-04)
        const isPdf = origName.endsWith('.pdf') || headerBuffer.includes(Buffer.from('%PDF-'));
        if (isPdf) {
          this.logger.info('Invoking PDF active-content inspection', { jobId: job.id });
          pdfResult = await inspectPdf({ filePath: localArtifactPath });
          await this.recordFinding({
            jobId: job.id,
            fileVersionId: job.fileVersionId,
            checkId: 'scanner.pdf',
            engine: pdfResult.engine,
            engineVersion: pdfResult.engineVersion,
            outcome: pdfResult.outcome,
            reasonCode: pdfResult.reasonCode,
            severity: pdfResult.severity,
            confidence: pdfResult.confidence,
            evidence: pdfResult.evidence,
            storageVersionId,
            sha256Hex: calculatedSha256,
            sizeBytes: calculatedSize,
            durationMs: pdfResult.durationMs,
          });
        }

        // B. OOXML Macro & Relationship checks (scan-05 & scan-06)
        if (
          isOoxml ||
          origName.endsWith('.docm') ||
          origName.endsWith('.xlsm') ||
          origName.endsWith('.pptm')
        ) {
          this.logger.info('Invoking OOXML security checks', { jobId: job.id });
          const ooxmlCheck = await inspectOoxml({ filePath: localArtifactPath });
          ooxmlMacroResult = ooxmlCheck.macro;
          ooxmlRelationshipResult = ooxmlCheck.relationships;

          await this.recordFinding({
            jobId: job.id,
            fileVersionId: job.fileVersionId,
            checkId: 'scanner.ooxml.macro',
            engine: ooxmlMacroResult.engine,
            engineVersion: ooxmlMacroResult.engineVersion,
            outcome: ooxmlMacroResult.outcome,
            reasonCode: ooxmlMacroResult.reasonCode,
            severity: ooxmlMacroResult.severity,
            confidence: ooxmlMacroResult.confidence,
            evidence: ooxmlMacroResult.evidence,
            storageVersionId,
            sha256Hex: calculatedSha256,
            sizeBytes: calculatedSize,
            durationMs: ooxmlMacroResult.durationMs,
          });

          await this.recordFinding({
            jobId: job.id,
            fileVersionId: job.fileVersionId,
            checkId: 'scanner.ooxml.relationship',
            engine: ooxmlRelationshipResult.engine,
            engineVersion: ooxmlRelationshipResult.engineVersion,
            outcome: ooxmlRelationshipResult.outcome,
            reasonCode: ooxmlRelationshipResult.reasonCode,
            severity: ooxmlRelationshipResult.severity,
            confidence: ooxmlRelationshipResult.confidence,
            evidence: ooxmlRelationshipResult.evidence,
            storageVersionId,
            sha256Hex: calculatedSha256,
            sizeBytes: calculatedSize,
            durationMs: ooxmlRelationshipResult.durationMs,
          });
        }

        // C. Image Trailing Data check
        const isImage =
          origName.endsWith('.png') ||
          origName.endsWith('.jpg') ||
          origName.endsWith('.jpeg') ||
          origName.endsWith('.gif') ||
          (headerBuffer.length >= 8 &&
            headerBuffer
              .subarray(0, 8)
              .equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) ||
          (headerBuffer.length >= 2 &&
            headerBuffer.subarray(0, 2).equals(Buffer.from([0xff, 0xd8]))) ||
          (headerBuffer.length >= 6 &&
            (headerBuffer.subarray(0, 6).toString('ascii').startsWith('GIF87a') ||
              headerBuffer.subarray(0, 6).toString('ascii').startsWith('GIF89a')));

        if (isImage) {
          this.logger.info('Invoking image trailing data inspection', { jobId: job.id });
          imageTrailingResult = await inspectImageTrailing({ filePath: localArtifactPath });
          if (imageTrailingResult.format) {
            await this.recordFinding({
              jobId: job.id,
              fileVersionId: job.fileVersionId,
              checkId: 'scanner.image.trailing',
              engine: imageTrailingResult.engine,
              engineVersion: imageTrailingResult.engineVersion,
              outcome: imageTrailingResult.outcome,
              reasonCode: imageTrailingResult.reasonCode,
              severity: imageTrailingResult.severity,
              confidence: imageTrailingResult.confidence,
              evidence: imageTrailingResult.evidence,
              storageVersionId,
              sha256Hex: calculatedSha256,
              sizeBytes: calculatedSize,
              durationMs: imageTrailingResult.durationMs,
            });
          }
        }

        // D. Embedded Executable Signature check
        this.logger.info('Invoking embedded signature inspection', { jobId: job.id });
        embeddedSigResult = await inspectEmbeddedSignatures({ filePath: localArtifactPath });
        await this.recordFinding({
          jobId: job.id,
          fileVersionId: job.fileVersionId,
          checkId: 'scanner.signature.embedded',
          engine: embeddedSigResult.engine,
          engineVersion: embeddedSigResult.engineVersion,
          outcome: embeddedSigResult.outcome,
          reasonCode: embeddedSigResult.reasonCode,
          severity: embeddedSigResult.severity,
          confidence: embeddedSigResult.confidence,
          evidence: embeddedSigResult.evidence,
          storageVersionId,
          sha256Hex: calculatedSha256,
          sizeBytes: calculatedSize,
          durationMs: embeddedSigResult.durationMs,
        });

        // E. Polyglot check (poly-01, poly-02, poly-03)
        this.logger.info('Invoking polyglot inspection', { jobId: job.id });
        polyglotResult = await inspectPolyglot({ filePath: localArtifactPath });
        await this.recordFinding({
          jobId: job.id,
          fileVersionId: job.fileVersionId,
          checkId: 'scanner.polyglot',
          engine: polyglotResult.engine,
          engineVersion: polyglotResult.engineVersion,
          outcome: polyglotResult.outcome,
          reasonCode: polyglotResult.reasonCode,
          severity: polyglotResult.severity,
          confidence: polyglotResult.confidence,
          evidence: polyglotResult.evidence,
          storageVersionId,
          sha256Hex: calculatedSha256,
          sizeBytes: calculatedSize,
          durationMs: polyglotResult.durationMs,
        });
      }

      // 11. All enabled scans completed without error! Transition job to SUCCEEDED
      await completeScanJob(this.db, job.id, {
        workerId: this.workerId,
        now: this.now,
      });

      this.logger.info('Scan job succeeded and verified', {
        jobId: job.id,
        durationMs,
        sha256: calculatedSha256,
        clamavStatus: clamavResult?.status,
        yaraStatus: yaraResult?.status,
        archiveStatus: archiveResult?.status,
      });

      return {
        success: true,
        verified: true,
        clamav: clamavResult,
        yara: yaraResult,
        archive: archiveResult,
        pdf: pdfResult,
        ooxmlMacro: ooxmlMacroResult,
        ooxmlRelationship: ooxmlRelationshipResult,
        imageTrailing: imageTrailingResult,
        embeddedSig: embeddedSigResult,
        polyglot: polyglotResult,
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
