/**
 * @sug/shared
 * Core shared types and contracts across the gateway
 */

export const SharedPackageName = '@sug/shared' as const;

export interface SharedInfo {
  name: typeof SharedPackageName;
  version: string;
}

export const SharedInfo: SharedInfo = {
  name: SharedPackageName,
  version: '0.1.0',
};

export type * from './db.js';
