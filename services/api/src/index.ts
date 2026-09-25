/**
 * @sug/api
 * Edge API gateway Fastify service
 */

export const ApiPackageName = '@sug/api' as const;

export interface ApiInfo {
  name: typeof ApiPackageName;
  version: string;
}

export const ApiInfo: ApiInfo = {
  name: ApiPackageName,
  version: '0.1.0',
};

export * from './app.js';
export * from './server.js';
export * from './errors/problem.js';
export * from './health/types.js';
export * from './health/database.js';
export * from './health/storage.js';
export * from './routes/health.js';
