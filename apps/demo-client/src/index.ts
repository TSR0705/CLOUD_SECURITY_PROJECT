/**
 * @sug/demo-client
 * Demonstration and benchmarking upload client
 */

export const Demo_ClientPackageName = '@sug/demo-client' as const;

export interface Demo_ClientInfo {
  name: typeof Demo_ClientPackageName;
  version: string;
}

export const Demo_ClientInfo: Demo_ClientInfo = {
  name: Demo_ClientPackageName,
  version: '0.1.0',
};
