# ADR 0005: PostgreSQL Version Selection (PostgreSQL 18 vs 16)

## Status
PROVISIONAL / RECOMMENDED (DEC-005, OPEN-1)

## Context
The project requires a robust relational database with support for:
- Asynchronous job queue processing via `SELECT ... FOR UPDATE SKIP LOCKED`.
- Native cryptographic primitives (`pgcrypto` digest functions) for audit chain hashing.
- Append-only constraints and row-level security triggers (`forbid_mutation`).
- Time-sortable primary key identifiers to maintain strictly ordered audit trails and job queues.

The original project specification referenced PostgreSQL 16. The Build Plan recommends PostgreSQL 18 (`postgres:18-alpine`).

## Decision
We select **PostgreSQL 18** (`postgres:18-alpine`) as the recommended and default database version for the following technical reasons:
1. **Native `uuidv7()` Support**: PostgreSQL 18 introduces native generation of UUIDv7 identifiers (`uuidv7()`). UUIDv7 embeds a millisecond-precision Unix timestamp in the most significant bits, providing naturally time-ordered, index-friendly primary keys without external extensions or sequential integer ID leak risks.
2. **Extended Support Lifecycle**: PostgreSQL 18 is supported through November 2030 (compared to November 2028 for PG 16).
3. **Queue and Lock Optimizations**: PostgreSQL 18 includes engine-level optimizations for concurrent row-level locking (`SKIP LOCKED`), reducing lock contention on high-throughput job queue workloads.
4. **Syntax Compatibility**: All required SQL primitives (identity columns, advisory locks, `citext`, `pgcrypto`, trigger procedures) operate identically.

### OPEN-1 Alignment
This decision is marked **OPEN-1** in the decision register. The default is PostgreSQL 18. If a project stakeholder mandates reverting to PostgreSQL 16, the only required adaptation is replacing native `uuidv7()` calls with an application-level UUIDv7 generator or `gen_random_uuid()` from `pgcrypto`.

## Alternatives Considered
- **PostgreSQL 16**: Supported until late 2028. Lacks native `uuidv7()`, requiring application-level UUIDv7 generation or reliance on UUIDv4 (random) which causes B-tree index fragmentation on high-write audit tables.
- **PostgreSQL 17**: Evolutionary release; superseded by PG 18 without providing unique advantages.

## Security Impact
Native `uuidv7()` provides unguessable yet strictly monotonic keys, preventing enumeration attacks while maintaining deterministic chronological ordering in audit queries.

## Cost Impact
Zero cost variance. Docker image footprints and resource utilization between PG 16 and PG 18 are virtually identical.

## Research Impact
Enhances audit chain consistency proofs and eliminates clock skew issues between application containers generating timestamps and database record insertion.

## Consequences
- Requires using official `postgres:18-alpine` Docker image.
- Database migration scripts in Phase 3 will utilize `uuidv7()` as default column expressions.

## Evidence & Source References
- PostgreSQL 18 Release Notes (UUIDv7 implementation, row lock optimizations).
- Build Plan: Section 1.2 (DEC-005), Section 1.3 (OPEN-1).
