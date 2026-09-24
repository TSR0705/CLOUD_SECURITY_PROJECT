# P3 Database Schema, Migrations, and Security Invariants Report

## Executive Summary

Phase P3 establishes the PostgreSQL 18 persistence foundation and security invariants for the Secure Upload Gateway (SUG) architecture. The implementation codifies 16 relational tables across 9 deterministic SQL migrations managed by `node-pg-migrate 9.0.0`, enforces database-level immutability across 6 audit/evidence tables, introduces a cryptographically linked SHA-256 audit hash-chain serialized via transaction-level advisory locks, provisions 6 least-privilege database roles with column-level security and Row-Level Security (RLS), and generates strict TypeScript types via `kysely-codegen`.

All 30 required database verification tests (DB-01 through DB-30), alongside storage assumption tests and workspace checks (44 tests in total), execute cleanly and pass without errors.

---

## Environment & Toolchain

| Component             | Version / Specification                   | Notes                                                  |
| :-------------------- | :---------------------------------------- | :----------------------------------------------------- |
| **Database Engine**   | PostgreSQL 18.6 (Alpine Linux)            | Containerized via Docker Desktop (`sug-postgres`)      |
| **Migration Runner**  | `node-pg-migrate` 9.0.0                   | Pure SQL migrations (`migrations/*.sql`)               |
| **PostgreSQL Driver** | `pg` 8.23.0 (`@types/pg` 8.23.1)          | Node.js native PostgreSQL client pool                  |
| **Typed Query Layer** | `kysely` 0.29.6 & `kysely-codegen` 0.20.0 | Generates `packages/shared/src/db.ts` from live schema |
| **Runtime**           | Node.js 24.14.0 LTS, pnpm 12.5.1          | Monorepo root workspace                                |
| **Test Runner**       | Vitest 5.0.1                              | Automated integration testing                          |

---

## 1. Schema Architecture & The 16 Tables

The schema is partitioned into four logical subsystems across 16 tables within PostgreSQL 18:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PostgreSQL 18 Database ("sug")                       │
├────────────────────────┬───────────────────────┬───────────────────────┤
│ Identity & Policy      │ Ingestion & Objects   │ Scanning & Decision   │
├────────────────────────┼───────────────────────┼───────────────────────┤
│ • users                │ • upload_sessions     │ • scan_jobs           │
│ • applications         │ • files               │ • scan_results*       │
│ • api_keys             │ • file_versions*      │ • security_decisions* │
│ • security_policies*   │ • cloud_objects       │                       │
│ • refresh_tokens       │                       │                       │
├────────────────────────┴───────────────────────┴───────────────────────┤
│               Lifecycle, Replication & Audit Subsystem                 │
├────────────────────────────────────────────────────────────────────────┤
│ • promotion_jobs                                                       │
│ • replication_jobs                                                     │
│ • audit_events* (SHA-256 hash-chain, append-only)                      │
│ • audit_checkpoints* (signed ledger checkpoints)                       │
└────────────────────────────────────────────────────────────────────────┘
  * Denotes an immutable table protected by the forbid_mutation() trigger.
```

### Table Inventory

|  #  | Table Name           | Purpose                                                        | Immutability Status         |
| :-: | :------------------- | :------------------------------------------------------------- | :-------------------------- |
|  1  | `users`              | Administrative and operator identities, argon2id hashes, roles | Mutable                     |
|  2  | `applications`       | Ingesting tenant applications / API consumers                  | Mutable                     |
|  3  | `api_keys`           | Tenant API key metadata and HMAC credentials                   | Mutable (revocation)        |
|  4  | `security_policies`  | Versioned file security policies with canonical SHA-256        | **Immutable**               |
|  5  | `refresh_tokens`     | Hashed session refresh tokens with expiration                  | Mutable (rotation)          |
|  6  | `upload_sessions`    | Presigned upload session grants, expiration, state             | Mutable (lifecycle)         |
|  7  | `files`              | High-level logical file records tied to applications           | Mutable (status)            |
|  8  | `file_versions`      | Physical quarantined object upload instances with ingest SHA   | **Immutable**               |
|  9  | `cloud_objects`      | Clean/replica/quarantine storage objects across S3/GCS         | Mutable (metadata)          |
| 10  | `scan_jobs`          | Queue state for asynchronous multi-engine scanning             | Mutable (queue/retry)       |
| 11  | `scan_results`       | Engine-specific scanning findings, signatures, evidence        | **Immutable**               |
| 12  | `security_decisions` | Canonical security evaluation binding artifact to policy       | **Immutable**               |
| 13  | `promotion_jobs`     | Queue state for promoting quarantined files to clean zone      | Mutable (queue/retry)       |
| 14  | `replication_jobs`   | Queue state for cross-cloud replication (AWS ↔ GCP)            | Mutable (queue/retry)       |
| 15  | `audit_events`       | Tamper-evident SHA-256 hash-chained security event log         | **Immutable (Append-Only)** |
| 16  | `audit_checkpoints`  | Signed periodic ledger summaries for cross-cloud durability    | **Immutable**               |

---

## 2. Migration Sequence

Migrations are executed via `scripts/migrate.mjs` using `node-pg-migrate` inside single transactions:

1. **`001_types.sql`**: Custom ENUM types (`user_role`, `session_status`, `file_status`, `job_status`, `decision_type`, `finding_outcome`, `severity_level`, `confidence_level`, `cloud_provider`, `storage_zone`).
2. **`002_extensions_and_functions.sql`**: Installs `pgcrypto`, `citext`, and creates `forbid_mutation()` trigger function.
3. **`003_identity_policy.sql`**: Creates `users`, `applications`, `api_keys`, `security_policies`, `refresh_tokens`.
4. **`004_upload_files.sql`**: Creates `upload_sessions`, `files`, `file_versions`, `cloud_objects` (with `CHECK (storage_version_id <> '' AND storage_version_id <> 'null')`).
5. **`005_scan_and_decision.sql`**: Creates `scan_jobs`, `scan_results`, `security_decisions`.
6. **`006_promotion_replication.sql`**: Creates `promotion_jobs` (`UNIQUE(decision_id)`), `replication_jobs`.
7. **`007_audit.sql`**: Creates `audit_events` (`seq bigint GENERATED ALWAYS AS IDENTITY`), `audit_checkpoints`, and the `audit_append()` `SECURITY DEFINER` function with `pg_advisory_xact_lock(7426001)`.
8. **`008_indexes_constraints_triggers.sql`**: Attaches `forbid_mutation` triggers across all 6 immutable evidence tables; enables Row-Level Security on `cloud_objects`.
9. **`009_roles_grants.sql`**: Creates the 6 database roles, revokes `PUBLIC` schema access, applies least-privilege table/column grants, and configures RLS policies on `cloud_objects`.

---

## 3. Security Invariants & Protections

### Native UUIDv7 Identifiers

PostgreSQL 18 natively provides `uuidv7()`. All table primary keys default to `uuidv7()`:

- Provides high 48-bit Unix timestamp millisecond ordering.
- Yields 74 bits of cryptographically secure pseudo-random entropy.
- Ensures natural B-tree indexing locality without page thrashing.

### Immutability via `forbid_mutation()`

The trigger function `forbid_mutation()` is attached as `BEFORE UPDATE OR DELETE OR TRUNCATE ... FOR EACH STATEMENT` on:

- `audit_events`
- `audit_checkpoints`
- `scan_results`
- `security_decisions`
- `file_versions`
- `security_policies`

Any attempted `UPDATE`, `DELETE`, or `TRUNCATE` against these tables is rejected by the PostgreSQL engine with an explicit exception (`<table_name> is append-only / immutable`).

### Non-Empty Storage Version IDs

In `file_versions` and `cloud_objects`:

```sql
CHECK (storage_version_id <> '' AND storage_version_id <> 'null')
```

Ensures that unversioned storage uploads or accidental string conversions of null are rejected before insertion.

### Promotion TOCTOU Prevention

In `promotion_jobs`:

```sql
decision_id uuid NOT NULL UNIQUE REFERENCES security_decisions(id)
```

Guarantees that a security decision cannot be re-queued or promoted multiple times.

---

## 4. Cryptographic Audit Hash Chain

The `audit_events` table forms a sequential cryptographic blockchain inside PostgreSQL:

- Each event row possesses an auto-incrementing identity sequence (`seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY`).
- Events are appended strictly through the stored function `audit_append(...)`:
  - Runs as `SECURITY DEFINER` with fixed `search_path = public, pg_temp`.
  - Serializes concurrent appenders using `PERFORM pg_advisory_xact_lock(7426001)`.
  - Reads the current tail event's `event_hash`. If no events exist, roots the chain at 32 zero bytes (`\x00...00`).
  - Computes `event_hash = digest(v_prev || convert_to(payload, 'UTF8'), 'sha256')`.
  - Inserts the new record linking `prev_hash` to the predecessor's `event_hash`.

### Concurrency & Tamper Resistance

- **High Concurrency**: Tested under 1,000 concurrent asynchronous append calls. The advisory transaction lock eliminates race conditions and ensures a strictly contiguous sequence and unbroken cryptographic chain.
- **Verification Module**: `@sug/audit` (`verifyAuditChain`) traverses audit events and validates:
  1. Monotonic sequence ordering (`seq[i] > seq[i-1]`).
  2. Root event links to 32 bytes of zero.
  3. Every event's `prev_hash` matches its predecessor's `event_hash`.
  4. In-memory bit flips or out-of-band database modifications are immediately detected, identifying the exact corrupted sequence number.

---

## 5. Role Privilege Matrix & Row-Level Security

All default privileges on schema `public` are revoked from `PUBLIC`. Six specific roles exist:

| Role             | Allowed Operations                                                                                                                    | Denied Operations / Invariants                                                                           |
| :--------------- | :------------------------------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------- |
| `sug_admin`      | Full schema and table administration, migrations                                                                                      | Used solely by migration scripts and administrative tooling                                              |
| `sug_api`        | Ingests upload sessions, files, file versions, scan jobs; executes `audit_append`                                                     | **Denied** `security_decisions`, `scan_results`, `promotion_jobs`, `replication_jobs`                    |
| `sug_scanner`    | Reads quarantine objects, claims `scan_jobs`, writes `scan_results`; executes `audit_append`                                          | **Denied** `security_decisions`, `promotion_jobs`, `replication_jobs`                                    |
| `sug_promoter`   | Evaluates scan findings, writes `security_decisions`, claims `promotion_jobs`, inserts clean `cloud_objects`; executes `audit_append` | Cannot alter historical decisions; constrained to promotion workflow                                     |
| `sug_replicator` | Reads `replication_jobs` and `cloud_objects`, inserts replica `cloud_objects`; executes `audit_append`                                | **Denied** `security_decisions`, `scan_results`; restricted by RLS on `cloud_objects`                    |
| `sug_auditor`    | Read-only inspection across ledger, jobs, and non-sensitive columns                                                                   | **Denied** all writes; **Denied** `users.password_hash`, `api_keys.key_hmac`, and `refresh_tokens` table |

### Row-Level Security on `cloud_objects`

`cloud_objects` enforces RLS:

- `cloud_objects_admin_policy`: `sug_admin`, `sug_api`, `sug_promoter`, `sug_auditor` have full access.
- `cloud_objects_replicator_select_policy`: `sug_replicator` can select all cloud objects.
- `cloud_objects_replicator_insert_policy`: `sug_replicator` can **only** insert rows where `WITH CHECK (zone = 'replica')`. Attempts to insert clean or quarantine objects are rejected by the database.

---

## 6. Verification Test Matrix (DB-01 to DB-30)

| Test ID   | Test Category        | Description                                                                                                |  Result  |
| :-------- | :------------------- | :--------------------------------------------------------------------------------------------------------- | :------: |
| **DB-01** | Migration Execution  | Migration succeeds from empty database and records `pgmigrations`                                          | **PASS** |
| **DB-02** | Schema Integrity     | All 16 required tables exist in `public` schema                                                            | **PASS** |
| **DB-03** | Engine Prerequisites | Required extensions (`pgcrypto`, `citext`), functions, and enums exist                                     | **PASS** |
| **DB-04** | Identifier Format    | UUIDv7 primary keys generate RFC-valid UUIDv7 values with current timestamp                                | **PASS** |
| **DB-05** | Storage Invariant    | Empty string `storage_version_id = ''` is rejected by check constraint                                     | **PASS** |
| **DB-06** | Storage Invariant    | Literal `'null'` `storage_version_id` is rejected by check constraint                                      | **PASS** |
| **DB-07** | Storage Invariant    | Valid non-empty `storage_version_id` insertion succeeds                                                    | **PASS** |
| **DB-08** | Audit Chain          | Genesis audit event links to 32-byte zero previous hash                                                    | **PASS** |
| **DB-09** | Audit Chain          | Subsequent audit event links directly to predecessor's `event_hash`                                        | **PASS** |
| **DB-10** | Audit Concurrency    | 1,000 concurrent `audit_append` invocations generate an unbroken, monotonic chain                          | **PASS** |
| **DB-11** | Immutability         | `UPDATE` on `audit_events` rejected by `forbid_mutation` trigger                                           | **PASS** |
| **DB-12** | Immutability         | `DELETE` on `audit_events` rejected by `forbid_mutation` trigger                                           | **PASS** |
| **DB-13** | Immutability         | `UPDATE` on `scan_results` rejected by `forbid_mutation` trigger                                           | **PASS** |
| **DB-14** | Immutability         | `DELETE` on `scan_results` rejected by `forbid_mutation` trigger                                           | **PASS** |
| **DB-15** | Immutability         | `UPDATE` on `security_decisions` rejected by `forbid_mutation` trigger                                     | **PASS** |
| **DB-16** | Immutability         | `DELETE` on `security_decisions` rejected by `forbid_mutation` trigger                                     | **PASS** |
| **DB-17** | Immutability         | `UPDATE` on `file_versions` rejected by `forbid_mutation` trigger                                          | **PASS** |
| **DB-18** | Immutability         | `DELETE` on `file_versions` rejected by `forbid_mutation` trigger                                          | **PASS** |
| **DB-19** | Immutability         | `UPDATE` on `security_policies` rejected by `forbid_mutation` trigger                                      | **PASS** |
| **DB-20** | Immutability         | `DELETE` on `security_policies` rejected by `forbid_mutation` trigger                                      | **PASS** |
| **DB-21** | Immutability         | `UPDATE` on `audit_checkpoints` rejected by `forbid_mutation` trigger                                      | **PASS** |
| **DB-22** | Immutability         | `DELETE` on `audit_checkpoints` rejected by `forbid_mutation` trigger                                      | **PASS** |
| **DB-23** | Least Privilege      | `sug_api` cannot write to `security_decisions`                                                             | **PASS** |
| **DB-24** | Least Privilege      | `sug_scanner` cannot write to `security_decisions`                                                         | **PASS** |
| **DB-25** | Least Privilege      | `sug_scanner` cannot write to `promotion_jobs`                                                             | **PASS** |
| **DB-26** | Least Privilege      | `sug_replicator` cannot write to `security_decisions`                                                      | **PASS** |
| **DB-27** | Least Privilege      | `sug_replicator` cannot write to `scan_results`                                                            | **PASS** |
| **DB-28** | Least Privilege      | `sug_auditor` writes rejected; sensitive columns (`password_hash`, `key_hmac`) and `refresh_tokens` denied | **PASS** |
| **DB-29** | Integrity Invariant  | `promotion_jobs` rejects duplicate `decision_id`                                                           | **PASS** |
| **DB-30** | Reproducibility      | Migrations can be applied, rolled back completely, and re-applied cleanly                                  | **PASS** |

In addition:

- **RLS Verification**: `sug_replicator` permitted to insert into `zone = 'replica'` but blocked by RLS on `zone = 'clean'`; `sug_promoter` permitted on `zone = 'clean'`.
- **Tamper Verification**: `@sug/audit` detects in-memory bit corruption, genesis hash deviation, and database-level out-of-band updates at the exact corrupted sequence number.
