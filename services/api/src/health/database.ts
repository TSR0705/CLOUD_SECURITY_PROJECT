import pg from 'pg';
import type { ReadinessDatabase } from './types.js';

const { Pool } = pg;

export interface PostgresReadinessOptions {
  pool?: pg.Pool | undefined;
  connectionString?: string | undefined;
  timeoutMs?: number | undefined;
}

/**
 * PostgreSQL readiness check using a lightweight, non-mutating `SELECT 1` query.
 * Enforces strict query timeouts, guarantees connection release in finally,
 * and prevents credential or SQL syntax leakage on failure.
 */
export class PostgresReadinessCheck implements ReadinessDatabase {
  private readonly pool: pg.Pool;
  private readonly ownsPool: boolean;
  private readonly timeoutMs: number;

  constructor(options: PostgresReadinessOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 2000;
    if (options.pool) {
      this.pool = options.pool;
      this.ownsPool = false;
    } else {
      this.pool = new Pool({
        ...(options.connectionString ? { connectionString: options.connectionString } : {}),
        connectionTimeoutMillis: this.timeoutMs,
        max: 5,
        idleTimeoutMillis: 10000,
      });
      this.ownsPool = true;
    }
  }

  public async checkReachability(): Promise<void> {
    let client: pg.PoolClient | undefined;
    let timer: NodeJS.Timeout | undefined;

    try {
      const timeoutPromise = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error('PostgreSQL readiness check timed out'));
        }, this.timeoutMs);
      });

      const connectAndQuery = async (): Promise<void> => {
        client = await this.pool.connect();
        await client.query('SELECT 1');
      };

      await Promise.race([connectAndQuery(), timeoutPromise]);
    } catch {
      // Re-throw generic error without revealing connection details or stack traces
      throw new Error('PostgreSQL reachability check failed');
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
      if (client) {
        try {
          client.release();
        } catch {
          // Ignore release errors
        }
      }
    }
  }

  public async close(): Promise<void> {
    if (this.ownsPool) {
      await this.pool.end();
    }
  }
}
