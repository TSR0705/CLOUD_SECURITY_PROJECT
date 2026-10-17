/**
 * @sug/policy-engine
 * Standalone, framework-independent policy evaluation engine for the Secure Upload Gateway.
 * Provides strict Zod schema validation, deterministic JSON canonicalization,
 * SHA-256 policy hashing, immutable presets, filename normalization, and precheck logic.
 */

export * from './schema.js';
export * from './canonical.js';
export * from './presets.js';
export * from './normalizer.js';
export * from './precheck.js';

export const POLICY_ENGINE_NAME = '@sug/policy-engine' as const;
export const POLICY_ENGINE_VERSION = '0.1.0' as const;
