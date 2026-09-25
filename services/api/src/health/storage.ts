import { S3Client, HeadBucketCommand } from '@aws-sdk/client-s3';
import type { ReadinessStorage } from './types.js';

export interface S3ReadinessOptions {
  client?: S3Client | undefined;
  endpoint?: string | undefined;
  region?: string | undefined;
  bucket?: string | undefined;
  credentials?:
    | {
        accessKeyId: string;
        secretAccessKey?: string | undefined;
      }
    | undefined;
  timeoutMs?: number | undefined;
}

/**
 * Storage readiness check using a lightweight, non-mutating `HeadBucket` operation.
 * Bounded by strict timeout, ensures client cleanup, and prevents credential
 * or bucket configuration leakage on failure.
 */
export class S3ReadinessCheck implements ReadinessStorage {
  private readonly client: S3Client;
  private readonly ownsClient: boolean;
  private readonly bucket: string;
  private readonly timeoutMs: number;

  constructor(options: S3ReadinessOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 2000;
    this.bucket = options.bucket ?? 'sug-quarantine-local';

    if (options.client) {
      this.client = options.client;
      this.ownsClient = false;
    } else {
      this.client = new S3Client({
        ...(options.endpoint ? { endpoint: options.endpoint } : {}),
        region: options.region ?? 'us-east-1',
        forcePathStyle: true,
        credentials: {
          accessKeyId: options.credentials?.accessKeyId ?? 'test',
          secretAccessKey: options.credentials?.secretAccessKey ?? 'test',
        },
      });
      this.ownsClient = true;
    }
  }

  public async checkReachability(): Promise<void> {
    let timer: NodeJS.Timeout | undefined;

    try {
      const timeoutPromise = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error('Storage reachability check timed out'));
        }, this.timeoutMs);
      });

      const executeHeadBucket = async (): Promise<void> => {
        await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }));
      };

      await Promise.race([executeHeadBucket(), timeoutPromise]);
    } catch {
      // Re-throw generic error without leaking AWS error payload or credentials
      throw new Error('Storage reachability check failed');
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
  }

  public async close(): Promise<void> {
    if (this.ownsClient) {
      this.client.destroy();
    }
  }
}
