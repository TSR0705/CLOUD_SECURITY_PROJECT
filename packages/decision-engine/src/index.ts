/**
 * @sug/decision-engine
 * Deterministic decision engine contracts, rules R1–R7, and explainable record generator.
 */

export const DecisionEnginePackageName = '@sug/decision-engine' as const;

export interface DecisionEngineInfo {
  name: typeof DecisionEnginePackageName;
  version: string;
}

export const DecisionEngineInfo: DecisionEngineInfo = {
  name: DecisionEnginePackageName,
  version: '1.0.0',
};

export * from './types.js';
export * from './risk.js';
export * from './mapping.js';
export * from './engine.js';
export * from './review.js';
export * from './persistence.js';
