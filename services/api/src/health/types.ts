/**
 * Health check interfaces and status payloads.
 */

export interface ReadinessDatabase {
  checkReachability(): Promise<void>;
  close?(): Promise<void>;
}

export interface ReadinessStorage {
  checkReachability(): Promise<void>;
  close?(): Promise<void>;
}

export interface HealthResponse {
  status: 'ok';
}

export interface ReadinessResponse {
  status: 'ready' | 'not_ready';
}
