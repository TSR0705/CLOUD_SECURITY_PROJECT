/**
 * @sug/security-engine
 * File validation, type mapping, and archive inspection interfaces
 */

export const Security_EnginePackageName = '@sug/security-engine' as const;

export interface Security_EngineInfo {
  name: typeof Security_EnginePackageName;
  version: string;
}

export const Security_EngineInfo: Security_EngineInfo = {
  name: Security_EnginePackageName,
  version: '0.1.0',
};
