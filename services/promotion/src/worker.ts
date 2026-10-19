/**
 * @sug/service-promotion/worker
 * Background worker executing the promotion decision loop, queue claiming, and promotion lifecycle.
 */

import crypto from 'node:crypto';
import {
  enqueueEligiblePromotionJobs,
  claimPromotionJob,
  type ClaimedPromotionJob,
} from '@sug/shared';
import { PromotionService } from './promoter.js';
import type { PromotionWorkerOptions, PromotionResult, PromotionLogger } from './types.js';

export class PromotionWorker {
  private readonly service: PromotionService;
  private readonly options: PromotionWorkerOptions;
  private readonly workerId: string;
  private readonly pollIntervalMs: number;
  private readonly logger: PromotionLogger | undefined;
  private isRunning: boolean = false;
  private loopTimer: NodeJS.Timeout | null = null;

  constructor(options: PromotionWorkerOptions) {
    this.options = options;
    this.workerId =
      options.workerId ?? `promoter-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    this.pollIntervalMs = options.pollIntervalMs ?? 1000;
    this.logger = options.logger;

    this.service = new PromotionService({
      ...options,
      workerId: this.workerId,
    });
  }

  /**
   * Executes a single promotion cycle:
   * 1. Automatically enqueues any un-promoted, un-superseded ALLOW decisions.
   * 2. Atomically claims the next eligible QUEUED promotion job.
   * 3. Executes promotion protocol via PromotionService.
   *
   * Returns true if a job was claimed and executed, false if queue was empty.
   */
  async runOnce(): Promise<{ worked: boolean; result?: PromotionResult | undefined }> {
    // 1. Enqueue newly eligible ALLOW decisions
    try {
      const enqueued = await enqueueEligiblePromotionJobs(this.options.db);
      if (enqueued > 0) {
        this.logger?.info(`Enqueued ${enqueued} eligible promotion jobs`);
      }
    } catch (err) {
      this.logger?.warn('Failed to enqueue eligible promotion jobs', {
        error: (err as Error).message,
      });
    }

    // 2. Claim next available job
    let job: ClaimedPromotionJob | null = null;
    try {
      job = await claimPromotionJob(this.options.db, {
        workerId: this.workerId,
        ...(this.options.leaseTimeoutMs !== undefined
          ? { leaseTimeoutMs: this.options.leaseTimeoutMs }
          : {}),
      });
    } catch (claimErr) {
      this.logger?.error('Error claiming promotion job', {
        error: (claimErr as Error).message,
      });
      return { worked: false };
    }

    if (!job) {
      return { worked: false };
    }

    this.logger?.info('Claimed promotion job', {
      jobId: job.id,
      decisionId: job.decisionId,
      fileId: job.fileId,
      storageVersionId: job.boundStorageVersionId,
    });

    // 3. Execute promotion
    try {
      const result = await this.service.promote(job);
      return { worked: true, result };
    } catch (err) {
      this.logger?.error('Unhandled exception during artifact promotion', {
        jobId: job.id,
        error: (err as Error).message,
      });
      return {
        worked: true,
        result: {
          success: false,
          outcome: 'FAILED',
          fileId: job.fileId,
          fileVersionId: job.fileVersionId,
          error: (err as Error).message,
        },
      };
    }
  }

  /**
   * Starts the continuous background polling loop.
   */
  start(): void {
    if (this.isRunning) return;
    this.isRunning = true;
    this.logger?.info('PromotionWorker started', { workerId: this.workerId });

    const poll = async () => {
      if (!this.isRunning) return;
      try {
        await this.runOnce();
      } catch (err) {
        this.logger?.error('Error in promotion loop iteration', {
          error: (err as Error).message,
        });
      } finally {
        if (this.isRunning) {
          this.loopTimer = setTimeout(poll, this.pollIntervalMs);
        }
      }
    };

    this.loopTimer = setTimeout(poll, 10);
  }

  /**
   * Gracefully stops the background polling loop.
   */
  stop(): void {
    this.isRunning = false;
    if (this.loopTimer) {
      clearTimeout(this.loopTimer);
      this.loopTimer = null;
    }
    this.logger?.info('PromotionWorker stopped', { workerId: this.workerId });
  }

  getWorkerId(): string {
    return this.workerId;
  }
}
