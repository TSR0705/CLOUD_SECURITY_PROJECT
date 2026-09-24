/**
 * @sug/storage
 * Storage provider interfaces and adapters
 */

export const StoragePackageName = '@sug/storage' as const;

export interface StorageInfo {
  name: typeof StoragePackageName;
  version: string;
}

export const StorageInfo: StorageInfo = {
  name: StoragePackageName,
  version: '0.1.0',
};
