# ADR 0001: Architecture, Eight Trust Zones, and Pipeline Topology

## Status
APPROVED

## Context
Traditional file upload architectures in cloud environments frequently violate the principle of complete mediation. In direct-to-cloud upload topologies (e.g., using S3 presigned URLs), files are placed directly into addressable application storage buckets prior to inspection. Even in mediated topologies, application backends often operate with monolithic credentials allowing read/write access to both incoming uploads and production artifacts. If security inspection is delayed or performed asynchronously without cryptographic binding, a race condition exists (Time-of-Check-to-Time-of-Use, CWE-367) where an attacker can overwrite a validated object prior to consumption.

To enforce Zero Trust and prevent uninspected or malicious content from entering trusted domains, a quarantine-first, privilege-separated pipeline is required.

## Decision
We freeze the architecture into eight isolated Trust Zones (Z1–Z8) governed by strict boundaries and four distinct Node.js services sharing a single PostgreSQL 18 instance:

1. **Z1 (Untrusted Client / External Application)**: Untrusted external actors uploading files via API keys or ephemeral upload tokens.
2. **Z2 (Ingest & API Gateway — `services/api`)**: Fastify 5 service exposed to clients. Holds credentials ONLY to write to quarantine storage under an immutable key pattern (`incoming/<app_id>/<upload_id>`) with `If-None-Match: *` and insert rows into PostgreSQL `files`, `file_versions`, and `scan_jobs`. Holds NO credentials to write to clean storage or insert `security_decisions`.
3. **Z3 (Quarantine Storage)**: Isolated S3-compatible bucket (`sug-quarantine-*`) with object versioning enabled. Denies overwrites via bucket policy (`s3:if-none-match`). Objects lifecycle-expire automatically in 7 days.
4. **Z4 (Security Scanner — `services/scanner`)**: Background worker service running in a network-isolated container (no public egress). Claims jobs from PostgreSQL via `FOR UPDATE SKIP LOCKED`. Reads specific object versions (`GetObject` by `VersionId`) from quarantine. Interfaces with `clamd` (INSTREAM protocol) and `yr` (YARA-X CLI). Persists findings to `scan_results`. Holds NO clean storage credentials and CANNOT write `security_decisions`.
5. **Z5 (Promotion Service — `services/promotion`)**: Independent background worker. The SOLE identity authorized to write clean storage (`sug-clean-*`). Evaluates deterministic decision records, re-fetches the exact bound artifact by `(bucket, key, version_id)` from quarantine, re-verifies SHA-256 and byte length, encrypts payload into `SUG1` envelope format using AES-256-GCM, writes ciphertext to clean storage with `If-None-Match: *`, and inserts `cloud_objects` in the same database transaction.
6. **Z6 (Trusted Clean Storage)**: S3-compatible bucket (`sug-clean-*`) holding ciphertext objects. Only accessible by `services/promotion` (write) and download endpoints under strict verification.
7. **Z7 (Cross-Cloud Replica Storage)**: Google Cloud Storage bucket (`sug-replica-*`) in a secondary cloud. Receives ciphertext replicas via `services/replication` using Workload Identity Federation (WIF) with `ifGenerationMatch: 0` (write-once precondition).
8. **Z8 (Read-Only Dashboard & Evidence — `apps/dashboard`)**: Next.js 16 application for security analysts and auditors. Operates strictly via Fastify API using JWT/RBAC. Holds NO database connection and NO cloud storage credentials.

### Non-Negotiable Invariants
1. **Unilateral Promotion**: Nothing reaches clean storage except through `services/promotion` following an un-superseded `ALLOW` decision and exact `(storage_version_id, sha256, file_size)` re-verification.
2. **Privilege Ceiling**: `services/api` and `services/scanner` cannot write clean storage or create `security_decisions`.
3. **Transactional Audit Chain**: Every state transition of a file generates one hash-chained `audit_events` row in the same PostgreSQL transaction.
4. **Fail-Closed Default**: Every scanner timeout, detector disagreement, format ambiguity, or system exception maps to `ERROR`, `QUARANTINE`, or `BLOCK`—never `ALLOW`.
5. **Ciphertext Invariant**: Clean and replica storage contain ONLY the `SUG1` AES-256-GCM encrypted format. Key Encryption Key (KEK) access is strictly limited to promotion and authorized download execution paths.

## Alternatives Considered
- **Direct-to-S3 Presigned Uploads**: Rejected due to absence of streaming backpressure, inability to enforce strict body limits before storage consumption, and broad attack surface on presigned URL reuse.
- **Monolithic Ingest-Scan-Promote Worker**: Rejected because compromise of scanner parsing logic (e.g., memory corruption in complex parsers) would yield clean bucket write credentials.
- **Serverless (AWS Lambda) Pipeline**: Rejected for local development parity and higher latency/cost overhead under steady-state scanning workloads.

## Security Impact
Enforces complete mediation, least privilege, and non-bypassability across ingestion, inspection, and promotion. Compromise of the API or scanner cannot result in unauthorized objects landing in clean storage.

## Cost Impact
Local development uses Docker Compose with zero cloud spend. Cloud deployment in Track 4 utilizes AWS S3 standard tier and GCP GCS Standard tier with tight budget alarms ($5 and $0.01 thresholds) and no compute/NAT gateways.

## Research Impact
Validates Hypothesis H2 (quarantine-first prevents unscanned promotion) and H4 (privilege separation limits blast radius). Provides the formal 8-zone model evaluated in the academic research paper.

## Consequences
- Every stage requires distinct IAM roles / application credentials.
- Local emulation must accurately model separate credentials per service.
- State progression must be tracked transactionally in PostgreSQL.

## Evidence & Source References
- Build Plan: Part 1.1 (Frozen Architecture), Section 2.2 (P0 contract).
- Literature Survey: Section 3.4 (Cloud Trust Boundaries), Section 8 (Proposed Architecture).
- Standards: NIST SP 800-207 (Zero Trust Architecture), MITRE CWE-434, CWE-367.
