# ADR 0004: Service Privilege Separation and Least-Privilege IAM Boundaries

## Status
APPROVED (DEC-003)

## Context
A primary failure mode in cloud storage gateways is privilege collapse: running services with monolithic database credentials and administrative cloud storage roles. If the scanner or API service is compromised (e.g., via an unparsed exploit in an image library or malicious document parser), an attacker with broad cloud permissions can bypass quarantine, write directly to clean storage, overwrite existing production artifacts, or alter database audit records to conceal their presence.

Strict least privilege must be maintained across both the relational database and the cloud object storage layers.

## Decision
We enforce strict privilege separation at both the database and storage layers:

### 1. Database Role Segregation (PostgreSQL)
Six distinct database roles are created with minimal necessary grants:
- **`sug_api`**:
  - Grants: `INSERT`, `SELECT`, `UPDATE` on `upload_sessions`, `files`, `file_versions`, `scan_jobs`, `api_keys`, `users`.
  - Append-only grant: `INSERT` ONLY on `audit_events` (via `audit_append()` trigger function).
  - Explicit DENY: No access to write `security_decisions`, `promotion_jobs`, or `cloud_objects`.
- **`sug_scanner`**:
  - Grants: `SELECT`, `UPDATE` on `scan_jobs`; `INSERT`, `SELECT` on `scan_results`.
  - Explicit DENY: Cannot write to `security_decisions`, `cloud_objects`, or clean storage.
- **`sug_decision`**:
  - Grants: `SELECT` on `scan_results`, `file_versions`, `security_policies`; `INSERT` on `security_decisions`, `promotion_jobs`.
- **`sug_promotion`**:
  - Grants: `SELECT` on `security_decisions`, `file_versions`; `INSERT`, `UPDATE` on `promotion_jobs`, `cloud_objects`.
  - Append-only grant: `INSERT` on `audit_events`.
- **`sug_replication`**:
  - Grants: `SELECT` on `cloud_objects`; `SELECT`, `UPDATE` on `replication_jobs`.
- **`sug_dashboard` / `sug_auditor`**:
  - Grants: `SELECT` ONLY on views and non-sensitive tables. No `INSERT`, `UPDATE`, or `DELETE` grants.

### 2. Cloud Storage and IAM Role Separation
- **`UPLOAD_ROLE` (API)**:
  - Allowed: `s3:PutObject` with condition requiring `s3:if-none-match` strictly on the `sug-quarantine-*` bucket under prefix `incoming/*`.
  - Denied: `s3:GetObject` on clean storage, `s3:PutObject` on clean storage, `s3:DeleteObject*` on all buckets.
- **`SCANNER_ROLE` (Scanner)**:
  - Allowed: `s3:GetObject`, `s3:GetObjectVersion` on `sug-quarantine-*`.
  - Denied: All `PutObject` actions on all buckets; all actions on `sug-clean-*`.
- **`PROMOTION_ROLE` (Promoter)**:
  - Allowed: `s3:GetObjectVersion` on `sug-quarantine-*`; `s3:PutObject` with condition requiring `s3:if-none-match` on `sug-clean-*`; KMS decrypt/encrypt with specific KEK alias.
  - Denied: Deletions on clean storage; cannot write quarantine storage.
- **`REPLICATION_ROLE` (Replicator)**:
  - Allowed: `s3:GetObjectVersion` on `sug-clean-*`; GCS `storage.objects.create` via Workload Identity Federation with `ifGenerationMatch: 0`.
  - Denied: Read access to GCS replica; cannot delete or overwrite.

### 3. Container Network Isolation
- Docker Compose defines segmented networks: `edge`, `data`, `store`, and `scan`.
- The `scanner` service runs on an internal network with no external internet egress (`internal: true`), read-only root filesystem, dropped capabilities (`cap_drop: ALL`), and `no-new-privileges: true`.

## Alternatives Considered
- **Single Master Database User (`postgres`)**: Rejected as it eliminates the defense-in-depth boundary protecting the audit log and clean storage.
- **Single Cloud IAM User/Role**: Rejected because scanner memory corruption would allow direct writes to clean buckets.

## Security Impact
Guarantees that a compromise in Z1 (API) or Z4 (Scanner) cannot result in unauthorized promotion or modification of clean storage. Enforces Non-Negotiable Invariants 1 and 2.

## Cost Impact
Zero additional cost. PostgreSQL roles and IAM policies are configuration-level primitives with no per-role billing.

## Research Impact
Directly operationalizes Hypothesis H4 (privilege-separated IAM limits blast radius), evaluated via the 40-action cloud blast-radius test matrix in Phase 29.

## Consequences
- Each service must authenticate using its own dedicated database credentials and IAM role.
- LocalStack Community does not enforce IAM policies locally (DEC-003); real IAM policy enforcement must be verified on AWS in Phase 25/29.

## Evidence & Source References
- Build Plan: Section 1.1 (Invariants), Section 1.2 (DEC-003), Section 2.2 (P22, P25, P29 contracts).
- Literature Survey: Section 3.4 (Cloud Trust Boundaries), Springer 2024 DR-TBAC Paper.
- NIST SP 800-53 (AC-6 Least Privilege).
