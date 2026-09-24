/**
 * @sug/decision-engine
 * Deterministic decision engine contracts and rules
 */

export const Decision_EnginePackageName = '@sug/decision-engine' as const;

export interface Decision_EngineInfo {
  name: typeof Decision_EnginePackageName;
  version: string;
}

export const Decision_EngineInfo: Decision_EngineInfo = {
  name: Decision_EnginePackageName,
  version: '0.1.0',
};
