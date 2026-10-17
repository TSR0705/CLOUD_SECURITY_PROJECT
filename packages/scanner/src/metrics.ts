import { Gauge, Registry, register as defaultRegistry } from '@prometheus-io/client';
import type { ClamAvScanner } from './clamav.js';

export interface ClamAvMetricsOptions {
  scanner?: ClamAvScanner | undefined;
  registry?: Registry | undefined;
  name?: string | undefined;
  help?: string | undefined;
}

export const DEFAULT_CLAMAV_SIGNATURE_AGE_METRIC_NAME = 'clamav_signature_age_seconds';

/**
 * Creates and registers a Prometheus Gauge for ClamAV signature database age in seconds.
 *
 * Semantic behavior:
 * - Metric Name: `clamav_signature_age_seconds`
 * - Type: Gauge
 * - Value: current_time - ClamAV signature database publication/update timestamp (in seconds).
 * - When signature info cannot be retrieved (clamd down or unparseable), sets value to NaN
 *   (never silently reports 0 or fake timestamp).
 * - Automatic collection: when Prometheus metrics collection is triggered, invokes scanner.getSignatureAge().
 */
export function createClamAvSignatureAgeGauge(
  scanner?: ClamAvScanner,
  options: ClamAvMetricsOptions = {},
): Gauge {
  const reg = options.registry ?? defaultRegistry;
  const metricName = options.name ?? DEFAULT_CLAMAV_SIGNATURE_AGE_METRIC_NAME;
  const metricHelp = options.help ?? 'Age of ClamAV virus signature database in seconds';

  return new Gauge({
    name: metricName,
    help: metricHelp,
    registers: [reg],
    async collect() {
      if (!scanner) return;
      try {
        const info = await scanner.getSignatureAge();
        if (info.available && info.ageSeconds !== null && !isNaN(info.ageSeconds)) {
          this.set(info.ageSeconds);
        } else {
          this.set(NaN);
        }
      } catch {
        this.set(NaN);
      }
    },
  });
}
