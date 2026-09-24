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
