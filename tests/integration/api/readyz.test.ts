import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createApp } from '../../../services/api/src/app.js';
import { loadConfig } from '@sug/shared/config';

describe('Integration — Fastify API Readiness & Live Infrastructure (Phase P5)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const secretsDir =
      process.env.SECRETS_DIR ??
      (fs.existsSync(path.resolve(process.cwd(), 'secrets'))
        ? path.resolve(process.cwd(), 'secrets')
        : '/run/secrets');

    const config = loadConfig({ secretsDir });
    app = await createApp({ config, logger: false });
    await app.ready();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it('GET /healthz returns 200 against live server', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/healthz',
    });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ status: 'ok' });
    expect(res.headers['x-request-id']).toBeDefined();
  });

  it('GET /readyz returns 200 verifying real PostgreSQL 18 and LocalStack S3 connectivity', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/readyz',
    });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ status: 'ready' });
    expect(res.headers['x-request-id']).toBeDefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('handles 50 repeated / concurrent readiness checks without leaking pool connections', async () => {
    const requests = Array.from({ length: 50 }, (_, i) =>
      app.inject({
        method: 'GET',
        url: '/readyz',
        headers: {
          'x-request-id': `perf-test-${i}`,
        },
      }),
    );

    const responses = await Promise.all(requests);

    for (let i = 0; i < responses.length; i++) {
      const res = responses[i];
      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body)).toEqual({ status: 'ready' });
      expect(res.headers['x-request-id']).toBe(`perf-test-${i}`);
    }
  });
});
