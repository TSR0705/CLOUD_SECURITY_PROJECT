/**
 * @sug/policy-engine
 * Policy evaluation schemas and precheck logic
 */

export const Policy_EnginePackageName = '@sug/policy-engine' as const;

export interface Policy_EngineInfo {
  name: typeof Policy_EnginePackageName;
  version: string;
}

export const Policy_EngineInfo: Policy_EngineInfo = {
  name: Policy_EnginePackageName,
  version: '0.1.0',
};
