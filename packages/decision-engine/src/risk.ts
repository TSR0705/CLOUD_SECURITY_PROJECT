/**
 * @sug/decision-engine/risk
 * Deterministic risk-score calculation for findings.
 */

import type { SeverityLevel, FindingInput } from './types.js';

export const SEVERITY_RISK_WEIGHTS: Readonly<Record<SeverityLevel, number>> = {
  CRITICAL: 100,
  HIGH: 75,
  MEDIUM: 25,
  LOW: 10,
  INFO: 0,
};

/**
 * Computes a deterministic integer risk score from 0 to 100 based on findings.
 *
 * Scoring rules:
 * - Findings with outcome 'PASS' or 'SKIPPED' contribute 0 points.
 * - Findings with outcome 'FAIL' or 'SUSPICIOUS' contribute their severity weight:
 *   - CRITICAL: 100
 *   - HIGH: 75
 *   - MEDIUM: 25
 *   - LOW: 10
 *   - INFO: 0
 * - Findings with outcome 'ERROR' contribute 100 points (fail-closed principle).
 * - Total score is clamped between 0 and 100.
 */
export function calculateRiskScore(findings: readonly FindingInput[]): number {
  if (!findings || findings.length === 0) {
    return 0;
  }

  let totalScore = 0;

  for (const finding of findings) {
    const outcome = finding.outcome;
    if (outcome === 'PASS' || outcome === 'SKIPPED') {
      continue;
    }

    if (outcome === 'ERROR') {
      const severity = finding.severity;
      const weight =
        !severity || (severity as string) === 'ERROR' || severity === 'CRITICAL'
          ? 100
          : (SEVERITY_RISK_WEIGHTS[severity] ?? 100);
      totalScore += weight;
      continue;
    }

    if (outcome === 'FAIL' || outcome === 'SUSPICIOUS' || (outcome as string) === 'WARN') {
      const severity = finding.severity ?? 'INFO';
      const weight = SEVERITY_RISK_WEIGHTS[severity] ?? 0;
      totalScore += weight;
    }
  }

  return Math.min(100, Math.max(0, totalScore));
}
