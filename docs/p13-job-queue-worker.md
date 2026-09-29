# Phase P13 — PostgreSQL Job Queue and Scanner Worker Architecture: Evidence & Implementation Report

## 1. Executive Summary

Phase P13 establishes the asynchronous execution and job processing infrastructure for the Secure Upload Gateway (SUG). It implements a robust, PostgreSQL-backed reliable job queue with atomic locking, crash recovery, deterministic exponential backoff, and a secure skeleton scanner worker daemon that enforces cryptographic identity verification before dispatching artifacts to analysis engines in later phases.

### Core Architecture Highlights

1. **PostgreSQL-Backed Concurrency & Atomic Locking**:
   - Implements `claimScanJob` leveraging PostgreSQL's `FOR UPDATE SKIP LOCKED` inside a Common Table Expression (CTE).
   - Guarantees zero duplicate job claims across concurrent worker processes without external queue brokers (Redis/RabbitMQ).
2. **Crash-Resilient Lease Reaping**:
   - Implements `reapExpiredJobs` to detect and safely recover abandoned jobs from terminated or crashed workers.
   - Respects maximum retry bounds, re-queuing retryable jobs or dead-lettering exhausted jobs to `DEAD`.
3. **Deterministic Exponential Backoff**:
   - Computes retry intervals deterministically: $T_{\text{backoff}} = \min(B \cdot 2^{a-1}, T_{\text{max}})$, preventing thundering herds while guaranteeing reproducible schedule sequencing.
4. **Exact-Version Storage Retrieval & Scan-Time Verification**:
   - The scanner retrieves the exact VersionId bound to the uploaded file version, preventing a subsequent overwrite of the same object key from silently redirecting the scan to a newer object version.
   - _Research boundary_: P13 establishes exact-version retrieval and scan-time artifact identity verification. It does not by itself constitute the final promotion-side TOCTOU defense; later promotion logic performs the required re-fetch, re-hash, size, and version verification before trusted-storage promotion.
5. **Real-Time Streaming Integrity Verification**:
   - Objects are streamed into isolated per-job temporary directories (`$TMPFS_DIR/<job-id>/`).
   - Content digest and byte size are computed continuously during the read pass and validated against the authoritative ingest metadata using `timingSafeSha256Equal`.
   - Fails closed on any mismatch, recording an immutable audit finding and marking the job `DEAD`.
6. **Strict Monorepo Quality Gates**:
   - 100% clean test suite: 40 test files, 530 passing tests (20 dedicated P13 tests covering concurrency, locking, dead-lettering, and identity verification).
   - TypeScript build (`tsc -b`), linting (`eslint .`), formatting (`prettier`), OpenAPI validation (`openapi:check`), and secret scanning (`gitleaks`) all pass with zero errors.

---

## 2. Canonical Scope & Strict Phase Boundaries

In accordance with the project build plan, Phase P13 strictly establishes the job queue and worker execution infrastructure. It intentionally omits all subsequent scanning engines and downstream processing:

### Included in P13 Scope:

- **PostgreSQL Queue Abstraction (`packages/shared/src/jobs.ts`)**:
  - `claimScanJob`: Atomic claim via `FOR UPDATE SKIP LOCKED` returning claimed job and artifact identity.
  - `completeScanJob`: Terminal transition of `RUNNING` jobs to `SUCCEEDED`.
  - `failScanJob`: Transition to `QUEUED` (with exponential backoff) or `DEAD` (on terminal failure or max attempts).
  - `reapExpiredJobs`: Background sweep recovering expired worker leases with batch-locking and skip-locked concurrency.
  - `generateWorkerId`: Hostname-, PID-, and entropy-based unique worker identification.
  - `calculateBackoff`: Deterministic exponential backoff calculation.
- **Scanner Worker Daemon (`services/scanner/src/worker.ts` & `services/scanner/src/index.ts`)**:
  - `ScannerWorker` class supporting `start()`, `stop()`, and `runOnce()`.
  - Role separation executing with `sug_scanner` credentials.
  - Integration with `StorageProvider.getByVersion(...)`.
  - Per-job isolated temporary working directory with guaranteed cleanup in `finally`.
  - Real-time streaming hash and size computation.
  - Cryptographic identity verification against `file_versions.sha256_ingest` and `file_versions.size_bytes`.
  - Canonical placeholder finding persistence in `scan_results` recording `scanned_storage_version_id`, `scanned_sha256`, and `scanned_size`.
  - Fail-closed handling for missing versions, invalid VersionIds, and identity mismatches.
- **Unit and Integration Test Suites**:
  - `tests/unit/shared/jobs.test.ts`: Deterministic backoff math and worker ID generation.
  - `tests/integration/scanner/p13-concurrency.test.ts`: High-concurrency job contention (50 jobs / 4 workers, 2-worker races, reaper recovery timing within 5 minutes, retry bounds).
  - `tests/integration/scanner/p13-worker-identity.test.ts`: End-to-end LocalStack S3 retrieval, exact versioning across overwrites, tamper detection, and graceful shutdown.

### Explicitly Excluded (Strict P14+ Boundary):

- **NO ClamAV Integration**: Deferred to Phase P14.
- **NO EICAR Detection**: Deferred to Phase P14.
- **NO YARA-X Engine**: Deferred to Phase P15.
- **NO Archive Inspection / Zip-Bomb Defense**: Deferred to Phase P16.
- **NO Content Disarm & Reconstruction (CDR) / PDF / OOXML Checks**: Deferred to Phase P17.
- **NO Deterministic Decision Engine**: Deferred to Phase P18.
- **NO AES-256-GCM Encryption**: Deferred to Phase P19.
- **NO Exact Artifact Promotion**: Deferred to Phase P20.
- **NO Audit / Audit Trail**: Deferred to Phase P21.
- **NO Privilege Separation**: Deferred to Phase P22.
- **NO Local MVP**: Deferred to Phase P23.
- **NO AWS Account Hygiene**: Deferred to Phase P24.
- **NO AWS Storage / IAM**: Deferred to Phase P25.
- **NO GCP Workload Identity Federation**: Deferred to Phase P26.
- **NO GCS Replication**: Deferred to Phase P27.
- **NO Cross-Cloud Audit / Recovery**: Deferred to Phase P28.
- **NO IAM Negative Testing**: Deferred to Phase P29.
- **NO Metrics**: Deferred to Phase P30.
- **NO Dashboard Authentication**: Deferred to Phase P31.
- **NO TOCTOU Experiment**: Deferred to Phase P32.
- **NO Dashboard Files / Scans / Decisions**: Deferred to Phase P33.
- **NO Dashboard Review / Policies / Integrity / Audit / Access**: Deferred to Phase P34.
- **NO Security Corpus**: Deferred to Phase P35.
- **NO Performance Testing**: Deferred to Phase P36.
- **NO Hardening**: Deferred to Phase P37.
- **NO Research Evaluation**: Deferred to Phase P38.
- **NO Documentation / Demonstration / Paper**: Deferred to Phase P39.

---

## 3. Database Architecture & Schema Verification

The database schema created in Phase P3 (`migrations/005_scan_and_decision.sql` and `migrations/009_roles_grants.sql`) was designed anticipating the exact queue mechanics required by P13. Zero new migrations were needed.

### Table: `scan_jobs`

| Column            | Type          | Constraints / Defaults                  | Purpose in P13                                                             |
| ----------------- | ------------- | --------------------------------------- | -------------------------------------------------------------------------- |
| `id`              | `uuid`        | `PRIMARY KEY DEFAULT uuidv7()`          | Unique job identifier                                                      |
| `file_version_id` | `uuid`        | `NOT NULL REFERENCES file_versions(id)` | Target file version being scanned                                          |
| `status`          | `job_status`  | `NOT NULL DEFAULT 'QUEUED'`             | Queue lifecycle state (`QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `DEAD`) |
| `attempts`        | `integer`     | `NOT NULL DEFAULT 0`                    | Current execution counter, incremented atomically upon claim               |
| `max_attempts`    | `integer`     | `NOT NULL DEFAULT 3`                    | Maximum allowed attempts before permanent death                            |
| `run_after`       | `timestamptz` | `NOT NULL DEFAULT now()`                | Scheduled execution timestamp (backoff target)                             |
| `locked_by`       | `text`        | `NULL`                                  | Active worker ID holding the lease                                         |
| `locked_at`       | `timestamptz` | `NULL`                                  | Timestamp when the lease was claimed                                       |
| `last_error`      | `text`        | `NULL`                                  | Error details from the most recent failed execution                        |
| `created_at`      | `timestamptz` | `NOT NULL DEFAULT now()`                | Job submission timestamp                                                   |
| `finished_at`     | `timestamptz` | `NULL`                                  | Terminal completion timestamp (`SUCCEEDED` or `DEAD`)                      |

### Table: `scan_results`

| Column                       | Type              | Constraints / Defaults                  | Purpose in P13                                            |
| ---------------------------- | ----------------- | --------------------------------------- | --------------------------------------------------------- |
| `id`                         | `uuid`            | `PRIMARY KEY DEFAULT uuidv7()`          | Result record identifier                                  |
| `scan_job_id`                | `uuid`            | `NOT NULL REFERENCES scan_jobs(id)`     | Associated scan job                                       |
| `file_version_id`            | `uuid`            | `NOT NULL REFERENCES file_versions(id)` | Target artifact version                                   |
| `check_id`                   | `text`            | `NOT NULL`                              | Unique check identifier (`scanner.skeleton`)              |
| `engine`                     | `text`            | `NOT NULL`                              | Engine identifier (`scanner.skeleton`)                    |
| `outcome`                    | `finding_outcome` | `NOT NULL`                              | Evaluation outcome (`PASS`, `FAIL`, `WARN`, `ERROR`)      |
| `scanned_storage_version_id` | `text`            | `NOT NULL`                              | Authoritative VersionId fetched and scanned by the worker |
| `scanned_sha256`             | `bytea`           | `CHECK (octet_length = 32)`             | Server-computed SHA-256 digest of scanned bytes           |
| `scanned_size`               | `bigint`          | `NOT NULL`                              | Exact byte length of scanned payload                      |

### Role Privileges & Least Privilege: `sug_scanner`

Phase P3 strictly configured `sug_scanner` to enforce the principle of least privilege:

- `GRANT SELECT ON file_versions, upload_sessions, security_policies TO sug_scanner;`
- `GRANT SELECT, UPDATE ON scan_jobs TO sug_scanner;`
- `GRANT INSERT ON scan_results TO sug_scanner;`

Because `sug_scanner` has write-only (`INSERT`) permissions on `scan_results` and `scan_results` is protected by the `forbid_mutation` append-only trigger, P13 workers insert canonical findings using clean `INSERT INTO scan_results (...)` without `ON CONFLICT` clauses (which would require read access), upholding immutable audit security.

---

## 4. Atomic Queue Mechanics & Concurrency Guarantees

### Atomic Job Claiming via CTE & `FOR UPDATE SKIP LOCKED`

To eliminate race conditions, duplicate claims, and the need for external locking services (e.g. Redlock), `claimScanJob` executes a single atomic PostgreSQL query:

```sql
WITH next_job AS (
  SELECT sj.id, sj.file_version_id
  FROM scan_jobs sj
  WHERE sj.status = 'QUEUED'
    AND sj.run_after <= $1
  ORDER BY sj.run_after ASC, sj.created_at ASC
  LIMIT 1
  FOR UPDATE SKIP LOCKED
)
UPDATE scan_jobs
SET status = 'RUNNING',
    locked_by = $2,
    locked_at = $1,
    attempts = scan_jobs.attempts + 1
FROM next_job, file_versions fv
WHERE scan_jobs.id = next_job.id
  AND fv.id = next_job.file_version_id
RETURNING
  scan_jobs.id,
  scan_jobs.file_version_id,
  scan_jobs.status,
  scan_jobs.attempts,
  scan_jobs.max_attempts,
  scan_jobs.run_after,
  scan_jobs.locked_by,
  scan_jobs.locked_at,
  fv.bucket,
  fv.object_key,
  fv.storage_version_id,
  fv.size_bytes,
  fv.sha256_ingest;
```

### Concurrency Invariants Proven:

1. **Mutual Exclusion**: When multiple workers query the database concurrently, `FOR UPDATE SKIP LOCKED` locks the candidate row instantly. Concurrent workers skip locked rows and claim subsequent jobs without waiting or blocking.
2. **Zero Duplicate Claims**: Under test `P13-01`, 50 jobs submitted to the queue and contested by 4 parallel workers resulted in exactly 50 claims, with $\text{duplicates} = 0$.
3. **Single Winner in Contention**: Under test `P13-02`, two workers racing for a single job produce exactly one winner holding the claim and one worker receiving `null`.

---

## 5. Exponential Backoff & Lifecycle Management

### Deterministic Exponential Backoff Formula

When a scan fails due to a transient error (such as a temporary network blip or storage timeout), the job is re-queued with exponential backoff calculated as:

$$T_{\text{backoff}} = \min(B \cdot 2^{a - 1}, T_{\text{max}})$$

Where:

- $B$ is the base backoff (default: 5,000 ms).
- $a$ is the attempt count (1, 2, 3, ...).
- $T_{\text{max}}$ is the maximum backoff ceiling (default: 300,000 ms / 5 minutes).

| Attempt ($a$)     | Formula Calculation | Scheduled Delay                         |
| ----------------- | ------------------- | --------------------------------------- |
| Attempt 1 Failure | $5000 \cdot 2^0$    | 5,000 ms (5s)                           |
| Attempt 2 Failure | $5000 \cdot 2^1$    | 10,000 ms (10s)                         |
| Attempt 3 Failure | $5000 \cdot 2^2$    | 20,000 ms (20s)                         |
| Attempt 4 Failure | $5000 \cdot 2^3$    | 40,000 ms (40s)                         |
| Attempt 5 Failure | $5000 \cdot 2^4$    | 80,000 ms (80s)                         |
| Attempt 6 Failure | $5000 \cdot 2^5$    | 160,000 ms (160s)                       |
| Attempt 7 Failure | $5000 \cdot 2^6$    | 300,000 ms (capped at $T_{\text{max}}$) |

### Terminal Transitions & Dead-Lettering

A job transitions to terminal `DEAD` status under any of the following conditions:

1. `attempts >= max_attempts`: All retry attempts have been exhausted.
2. `retryable: false`: The error is non-retryable (e.g., cryptographic identity mismatch, corrupted file, non-existent storage version).

When marked `DEAD`, `scan_jobs.finished_at` is set, `locked_by` and `locked_at` are cleared to `NULL`, and the error is recorded in `last_error`. Test `P13-06` and `P13-10` verify that `DEAD` jobs can never be re-claimed by workers.

---

## 6. Orphan Reaper & Crash Recovery

If a worker process crashes, loses power, or is killed via `SIGKILL` while holding a job lease, the job remains in `RUNNING` status indefinitely unless actively recovered.

### `reapExpiredJobs` Mechanics

The reaper runs periodically or on schedule:

1. Identifies jobs in `status = 'RUNNING'` where `locked_at < (now - leaseTimeoutMs)`.
2. Locks candidate rows using `SELECT ... FOR UPDATE SKIP LOCKED LIMIT batchSize`.
3. For each expired job:
   - If `attempts >= max_attempts`: marks job as `DEAD`, sets `finished_at = now()`, and records `Lease expired; attempts exhausted`.
   - If `attempts < max_attempts`: resets `status = 'QUEUED'`, clears `locked_by = NULL`, sets `run_after = now() + backoff`, and logs `Lease expired; recovered by reaper`.

---

## 7. Killed Worker Recovery Evidence

The canonical P13 DoD requires that a killed worker's job is detected and re-queued by the reaper within 5 minutes ($300,000\text{ ms}$ / 300 seconds).

### Configuration Distinction: Production vs. Test

#### Production / Default Configuration

- **Worker Lease Duration**: `240,000 ms` (240 seconds / 4 minutes).
- **Maximum Reaper Detection Interval**: `30,000 ms` (30 seconds).
- **Worst-Case Recovery Bound**:
  $$\text{Worst-Case Recovery Bound} = \text{lease duration} + \text{maximum reaper detection interval} = 240\text{s} + 30\text{s} = \mathbf{270\text{ seconds}} \le 300\text{ seconds}$$
- **Safety Margin**: A 30-second deterministic buffer guarantees that even in the absolute worst-case timing alignment (where a worker crashes 1 millisecond after a reaper sweep begins), the subsequent sweep detects and re-queues the job at second 270, strictly honoring the canonical 5-minute ($300\text{s}$) SLA.

#### Test Suite Configuration (`tests/integration/scanner/p13-concurrency.test.ts` — `P13-07 & P13-08`)

- **Fast Deterministic Test Lease**: `200 ms`.
- **Immediate Reaper Execution**: Triggered following lease expiration ($T > 200\text{ ms}$).
- **Measured Requeue Latency**: `258 ms`.
- **Measured Recovery Latency**: `262 ms`.
- _Note_: The test suite uses accelerated millisecond leases ($200\text{ ms}$) to verify the state transitions and timer arithmetic without pausing CI for minutes; the production system uses the 240s lease + 30s reaper interval to guarantee the 270s $\le$ 300s bound.

### Measured Recovery Timeline (Test Execution)

| Event / Marker           | Description                                                     | Timestamp (ISO 8601 UTC)   | Elapsed / Latency |
| ------------------------ | --------------------------------------------------------------- | -------------------------- | ----------------: |
| $T_1$: Worker Claimed    | Worker A claims queued job via `claimScanJob`                   | `2026-09-29T15:56:31.856Z` |              0 ms |
| $T_2$: Worker Terminated | Worker A crashes/dies abruptly (simulated `SIGKILL`)            | `2026-09-29T15:56:31.858Z` |             +2 ms |
| $T_3$: Lease Expired     | Lease duration ($200\text{ ms}$) elapses; job becomes candidate | `2026-09-29T15:56:32.056Z` |           +200 ms |
| $T_4$: Reaper Requeued   | `reapExpiredJobs` detects expired lease and resets to `QUEUED`  | `2026-09-29T15:56:32.116Z` |        **258 ms** |
| $T_5$: Worker B Claimed  | Secondary Worker B successfully claims recovered job            | `2026-09-29T15:56:32.120Z` |        **262 ms** |

### Canonical Bound Verification

| Metric                           |     Actual Measured |                 Canonical Threshold |  Result  |
| -------------------------------- | ------------------: | ----------------------------------: | :------: |
| Requeue Latency ($T_4 - T_2$)    |          **258 ms** | $\le 300,000\text{ ms}$ (5 minutes) | **PASS** |
| Reclaim Latency ($T_5 - T_2$)    |          **262 ms** | $\le 300,000\text{ ms}$ (5 minutes) | **PASS** |
| Premature Reap Check ($T < T_3$) |       0 jobs reaped |                       0 jobs reaped | **PASS** |
| Attempt Counter Increment        |                   2 |               $\text{attempts} + 1$ | **PASS** |
| Re-claimability by Normal Worker | Claimed by Worker B |                   Must be claimable | **PASS** |

---

## 8. Cryptographic Identity Verification & Storage Retrieval

The scanner worker establishes an airtight verification loop before passing artifacts to future scanner engines:

```
[Quarantine Storage]
       |
       |  storageProvider.getByVersion({ bucket, key, versionId })
       v
[Streaming Pipeline] ---> Streaming SHA-256 Digest & Size Computation
       |
       +---------------> Staged to Isolated tmpfs ($TMPFS_DIR/<job-id>/artifact.bin)
       |
       v
[Cryptographic Verification]
       |
       |-- 1. timingSafeSha256Equal(scannedSha256, sha256Ingest)
       |-- 2. scannedSize === sizeBytes
       |-- 3. getResult.versionId === storageVersionId
       |
       +--> PASS: Write canonical finding to scan_results -> completeScanJob()
       |
       +--> FAIL: Write IDENTITY_MISMATCH to scan_results -> failScanJob(DEAD)
       |
[Finally Block] Always rm -rf $TMPFS_DIR/<job-id>/
```

### Storage Overwrite Protection & TOCTOU Boundary (Test `P13-ID-02`)

The scanner retrieves the exact VersionId bound to the uploaded file version, preventing a subsequent overwrite of the same object key from silently redirecting the scan to a newer object version.

Test `P13-ID-02` verifies this invariant: when object key `quarantine/.../versioned-file.bin` is overwritten in S3 with a second payload ($V_2$), the scan job bound to $V_1$ fetches only $V_1$, cryptographically validates its SHA-256 and size against the $V_1$ ingest record, and records $V_1$'s finding.

**Research Boundary Clarification**:
P13 establishes exact-version retrieval and scan-time artifact identity verification. It does not by itself constitute the final promotion-side TOCTOU defense; later promotion logic performs the required re-fetch, re-hash, size, and version verification before trusted-storage promotion.

### Tamper Detection & Fail-Closed Behavior (Test `P13-ID-03`, `P13-ID-04`)

- When an artifact's bytes in quarantine do not match the ingest record (`sha256_ingest`), the worker aborts analysis immediately.
- It writes an immutable finding to `scan_results`:
  - `outcome: 'FAIL'`
  - `reason_code: 'IDENTITY_MISMATCH'`
  - `severity: 'CRITICAL'`
  - `confidence: 'CONFIRMED'`
- It marks the job `DEAD` with non-retryable failure.
- Zero allow or clean findings are generated.

---

## 9. Test Execution Matrix & Evidence

All 20 dedicated P13 tests across 3 suites pass with 100% reliability:

### Concurrency & Lifecycle Suite (`tests/integration/scanner/p13-concurrency.test.ts`)

| Test ID           | Description                                                                                               | Result   |
| ----------------- | --------------------------------------------------------------------------------------------------------- | -------- |
| `P13-01`          | 50 jobs claimed concurrently by 4 workers -> 50 unique claims, 0 duplicates                               | **PASS** |
| `P13-02`          | Two workers racing for one job -> exactly one winner, one null                                            | **PASS** |
| `P13-03`          | Worker claims job -> status is RUNNING with locked_by and locked_at                                       | **PASS** |
| `P13-04`          | completeScanJob transitions job to terminal SUCCEEDED state                                               | **PASS** |
| `P13-05`          | failScanJob with retryable=true re-queues job with backoff                                                | **PASS** |
| `P13-06`          | Exhausting max_attempts transitions job to DEAD                                                           | **PASS** |
| `P13-07 & P13-08` | Killed worker orphaned job is recovered by reaper within 5-minute canonical bound and claimed by worker B | **PASS** |
| `P13-09`          | Already completed job (SUCCEEDED) cannot be claimed                                                       | **PASS** |
| `P13-10`          | DEAD job cannot be claimed by normal workers                                                              | **PASS** |

### Worker Identity & Execution Suite (`tests/integration/scanner/p13-worker-identity.test.ts`)

| Test ID     | Description                                                                          | Result   |
| ----------- | ------------------------------------------------------------------------------------ | -------- |
| `P13-ID-01` | Worker claims job, verifies cryptographic identity, writes finding, and cleans tmpfs | **PASS** |
| `P13-ID-02` | Overwrite on same key in S3 does not affect exact VersionId retrieval                | **PASS** |
| `P13-ID-03` | Cryptographic identity mismatch records FAIL finding and marks job DEAD              | **PASS** |
| `P13-ID-04` | Artifact size mismatch fails closed and transitions job to DEAD                      | **PASS** |
| `P13-ID-05` | Non-existent VersionId in storage fails closed without producing clean finding       | **PASS** |
| `P13-ID-06` | Worker background loop starts, processes, and stops gracefully                       | **PASS** |

### Unit Tests Suite (`tests/unit/shared/jobs.test.ts`)

| Test ID       | Description                                                                 | Result   |
| ------------- | --------------------------------------------------------------------------- | -------- |
| `P13-UNIT-01` | generateWorkerId returns valid worker ID containing host and random entropy | **PASS** |
| `P13-UNIT-02` | calculateBackoff returns exponential values for attempts 1 through 5        | **PASS** |
| `P13-UNIT-03` | calculateBackoff caps at maxBackoffMs ceiling                               | **PASS** |
| `P13-UNIT-04` | calculateBackoff handles zero or negative attempts gracefully               | **PASS** |
| `P13-UNIT-05` | calculateBackoff handles custom base and max values                         | **PASS** |

---

## 10. Required Final Evidence Table

| Requirement              | Evidence                                                                       |  Result  |
| ------------------------ | ------------------------------------------------------------------------------ | :------: |
| `claim()`                | `packages/shared/src/jobs.ts` (`claimScanJob`)                                 | **PASS** |
| `FOR UPDATE SKIP LOCKED` | `packages/shared/src/jobs.ts` CTE claim query                                  | **PASS** |
| Atomic claim             | `tests/integration/scanner/p13-concurrency.test.ts` (`P13-01`, `P13-02`)       | **PASS** |
| 50 jobs / 4 workers      | 50 unique claims across 4 concurrent workers (`P13-01`)                        | **PASS** |
| Zero duplicate claims    | `expect(claims.length).toBe(50)` with unique IDs (`P13-01`)                    | **PASS** |
| Retry/backoff            | `tests/unit/shared/jobs.test.ts` & `p13-concurrency.test.ts` (`P13-05`)        | **PASS** |
| Reaper                   | `packages/shared/src/jobs.ts` (`reapExpiredJobs`)                              | **PASS** |
| Worker crash recovery    | `tests/integration/scanner/p13-concurrency.test.ts` (`P13-07 & P13-08`)        | **PASS** |
| Actual requeue latency   | **258 ms** measured latency ($T_4 - T_2$)                                      | **PASS** |
| Requeue <= 5 minutes     | $258\text{ ms} < 300,000\text{ ms}$ (measured comparison)                      | **PASS** |
| max_attempts             | Job marked `DEAD` after attempt counter reaches limit (`P13-06`)               | **PASS** |
| DEAD                     | Status transitions and timestamp recorded (`P13-06`)                           | **PASS** |
| DEAD cannot be claimed   | `claimScanJob` returns `null` for `DEAD` jobs (`P13-10`)                       | **PASS** |
| Exact VersionId          | `services/scanner/src/worker.ts` & `p13-worker-identity.test.ts` (`P13-ID-02`) | **PASS** |
| SHA-256 verification     | Real-time hash comparison via `timingSafeSha256Equal` (`P13-ID-01`)            | **PASS** |
| Size verification        | Stream byte count comparison (`P13-ID-01`, `P13-ID-04`)                        | **PASS** |
| Placeholder finding      | Canonical finding in `scan_results` with `scanned_*` fields (`P13-ID-01`)      | **PASS** |
| tmpfs                    | Directory `$TMPFS_DIR/<job-id>/` isolation                                     | **PASS** |
| Cleanup                  | Temporary directory deleted in `finally` block (`P13-ID-01`)                   | **PASS** |
| Least privilege          | `sug_scanner` role grants verified in `009_roles_grants.sql`                   | **PASS** |
| P0–P12 regression        | 40 test files, 530 tests passed with 0 failures                                | **PASS** |
| Build                    | `pnpm build` (`tsc -b`) exits 0                                                | **PASS** |
| Typecheck                | `pnpm typecheck` (`tsc -b`) exits 0                                            | **PASS** |
| Lint                     | `pnpm lint` (`eslint .`) reports 0 errors, 0 warnings                          | **PASS** |
| Format                   | `pnpm format:check` reports clean formatting                                   | **PASS** |
| OpenAPI                  | `pnpm openapi:check` verified synchronized                                     | **PASS** |
| Gitleaks                 | 0 leaks found across git history and filesystem                                | **PASS** |
| P14+ contamination       | `git diff 2857095..HEAD` verified zero P14+ scope contamination                | **NONE** |

---

## 11. Final Verdict

**FULL PASS — READY FOR P14**

All canonical requirements for Phase P13 are satisfied and empirically validated:

- **Production Configuration Recovery Bound**:
  - Lease duration = `240s`
  - Maximum reaper detection interval = `30s`
  - Worst-case recovery bound: $\text{lease} + \text{interval} = 240\text{s} + 30\text{s} = \mathbf{270\text{ seconds}} \le 300\text{ seconds}$ (5 minutes)
- **Accelerated Test Suite Verification**:
  - Test lease = `200 ms`
  - Immediate reaper sweep
  - Measured requeue latency = `258 ms`
  - Measured recovery latency = `262 ms`
- All 20 P13 tests and 510 legacy regression tests pass (530/530 total).
- Phase numbering strictly follows the canonical P14–P39 roadmap.
- VersionId security claims reflect technically precise boundaries.
- Working tree is clean and ready for Phase P14.
