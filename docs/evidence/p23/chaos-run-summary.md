# Phase P23 Deliverable: Chaos & Resilience Harness Execution Summary

This report documents the live execution results of the top-level chaos test harness `chaos.ts` (invoked via `pnpm chaos`).

- **Test Date**: 2026-10-20
- **Runner**: Node.js v24.14.0 (Windows x64)
- **Database**: PostgreSQL 16 (Live Docker container `sug-postgres`)
- **Storage**: LocalStack S3 (`sug-quarantine-local`, `sug-clean-local`)
- **Total Execution Time**: 7.68 seconds

---

## Scenario Execution Summary

| Scenario ID & Name                                      | Simulated Fault / Attack                                                                                                                                  | Measured Duration | Invariant Violations | Status   |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | -------------------- | -------- |
| **Scenario 1**: Scanner Crash & Reaper Recovery         | Hard worker termination during active lease; lease timeout simulated; orphan reaper sweeps back to QUEUED; healthy worker claims and completes            | 212 ms            | 0                    | **PASS** |
| **Scenario 2**: Database Transaction Interruption       | Simulated fatal crash / connection drop mid-session creation; transactional rollback fail-closed                                                          | 122 ms            | 0                    | **PASS** |
| **Scenario 3**: Truncated Stream Client Abort           | Ingest stream aborted by client after 20 bytes (mismatching 150-byte Content-Length header); HTTP 400 problem details returned; zero clean storage writes | 152 ms            | 0                    | **PASS** |
| **Scenario 4**: Concurrent Claim Race (`SKIP LOCKED`)   | 20 scanner workers compete simultaneously to claim a single queued job via `FOR UPDATE SKIP LOCKED`; exactly 1 worker claims, 19 return null              | 204 ms            | 0                    | **PASS** |
| **Scenario 5**: High-Concurrency Multi-Tenant Ingestion | 1,000 concurrent file uploads across Tenant A and Tenant B under 50-worker parallel load                                                                  | 5,982 ms          | 0                    | **PASS** |

---

## High-Concurrency Multi-Tenant Benchmark (Scenario 5)

### Measured Metrics

- **Total Operations**: 1,000 file uploads
  - Tenant A Uploads: 500
  - Tenant B Uploads: 500
- **Concurrent In-Flight Workers**: 50
- **Successful Ingestions**: 1,000 (100.0% success rate)
- **Failed Ingestions**: 0 (0.0% failure rate)
- **Elapsed Benchmark Duration**: 5,982 ms (5.98 seconds)
- **Ingestion Throughput**: **167.2 uploads/sec**
- **Latency Distribution**:
  - **Min Latency**: 215.1 ms
  - **p50 (Median)**: **283.2 ms**
  - **p95**: **428.5 ms**
  - **p99**: **549.8 ms**
  - **Max Latency**: 612.4 ms

### Multi-Tenant Boundary Isolation Under Load

- 20 sample files (10 from Tenant A, 10 from Tenant B) tested for cross-tenant unauthorized metadata access and download extraction.
- **Cross-Tenant Authorization Rejections**: 40 / 40 (100.0% rejected with HTTP 403 Forbidden / 404 Not Found).
- **Data Leaks**: 0.

---

## Post-Chaos Database Invariant Verification

Immediately following all 5 fault-injection scenarios and the 1,000-request concurrency surge, `invariants.sql` was executed across the database.

- **Total Checks Evaluated**: 16
- **Total Invariant Violations**: **0**
- **Final Verdict**: **[GATE APPROVED] ALL 16 INVARIANTS SATISFIED**
