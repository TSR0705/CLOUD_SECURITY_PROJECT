# ADR 0002: PostgreSQL Job Queue with `SKIP LOCKED`

## Status
APPROVED (DEC-001)

## Context
The security gateway pipeline requires asynchronous job orchestration across pipeline stages:
1. `scan_jobs`: Triggered upon quarantine upload completion to schedule virus, YARA, archive, and format checks.
2. `promotion_jobs`: Triggered upon deterministic `ALLOW` decision to orchestrate exact-version re-verification, envelope encryption, and clean bucket writing.
3. `replication_jobs`: Triggered upon clean bucket write to orchestrate cross-cloud GCS synchronization.

Common approaches in microservice architectures introduce external message brokers such as Redis (with BullMQ), Apache Kafka, or AWS SQS. Introducing an external broker increases operational complexity, requires securing an additional network protocol and credential set, risks losing queue events unless multi-phase commits are used, and separates the execution state from the audit evidence stored in relational tables.

## Decision
We implement the asynchronous job queue directly inside PostgreSQL using native queries with `SELECT ... FOR UPDATE SKIP LOCKED`:
- The queue tables (`scan_jobs`, `promotion_jobs`, `replication_jobs`) are native PostgreSQL tables sharing the relational database with file metadata.
- Workers atomically claim jobs by locking available rows (`status = 'PENDING'`) while skipping rows already claimed by concurrent workers (`SKIP LOCKED`).
- A background reaper process monitors `CLAIMED` jobs with heartbeat timeouts, returning abandoned or crashed worker tasks to `PENDING` with exponential backoff and a hard retry ceiling (`max_attempts`), moving permanently failed tasks to `DEAD`.
- No Redis, BullMQ, Kafka, RabbitMQ, SQS, or external library (e.g., `pg-boss`) will be used for the MVP.

## Alternatives Considered
- **Redis + BullMQ**: Provides high throughput and in-memory speed, but introduces a second state store, lacks atomic transactions spanning both file metadata and queue state, and creates dual data backup requirements.
- **AWS SQS**: Native AWS service, but breaks local development parity without LocalStack SQS emulation, incurs cloud network overhead, and complicates local transactional consistency.
- **pg-boss**: Node.js library for PostgreSQL job queues; rejected to avoid unnecessary third-party dependencies, ensure explicit transaction management, and preserve exact schema visibility for database migrations.

## Security Impact
- Atomic transactions: A file record and its associated `scan_job` are inserted in the exact same transaction that records the ingest audit event. A rollback of the file upload leaves zero orphaned queue records.
- Single trust boundary: Securing PostgreSQL via network isolation, TLS, and role-based permissions simultaneously secures the queue.
- Auditability: Job dispatch, state transitions, attempts, and error details remain visible in relational tables with foreign keys to `file_versions`.

## Cost Impact
Zero additional infrastructure costs. Eliminates costs associated with managed Redis instances, SQS API requests, or Kafka cluster provisioning.

## Research Impact
Simplifies chaos engineering testing (evaluating Hypothesis H2). Injecting worker crashes, database restarts, and job duplicates is cleanly testable within the single relational store.

## Consequences
- Throughput is bounded by PostgreSQL connection pooling and transaction overhead. The gateway's target workload is tens to hundreds of files per minute, well within PostgreSQL's performance envelope.
- Workers must maintain a heartbeat or adhere to job timeouts to ensure crashed jobs are reclaimed by the reaper.

## Evidence & Source References
- PostgreSQL Official Documentation: `SELECT ... FOR UPDATE` row-level locks and `SKIP LOCKED`.
- Build Plan: Section 1.2 (DEC-001), Section 2.2 (P13 contract).
