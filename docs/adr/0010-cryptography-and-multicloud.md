# ADR 0010: Cryptographic Envelope, Anti-TOCTOU Promotion, and Multi-Cloud Replication

## Status
APPROVED (DEC-012, DEC-013, DEC-014, DEC-015, DEC-017)

## Context
Deploying files to cloud storage introduces two major vulnerabilities:
1. **Time-of-Check to Time-of-Use (TOCTOU) Races (CWE-367)**: Between when a file is scanned in quarantine and when it is copied to clean storage, an attacker could overwrite the file at that key with malicious content. If promotion relies on object keys rather than immutable version IDs, the clean bucket will receive unscanned malicious content.
2. **Data Exposure at Rest**: Storing plaintext files in cloud storage relies entirely on provider-level encryption (SSE-S3), which does not protect against IAM over-granting, compromised administrative credentials, or multi-tenant leakage.
3. **Cross-Cloud Credential Risk**: Replicating data from AWS to Google Cloud Storage (GCS) traditionally involves static, long-lived GCP service account JSON private keys stored in the AWS environment. Leaked service account keys are a leading cause of multi-cloud data breaches.

## Decision
We enforce a secure cryptographic envelope, exact-artifact promotion binding, and credential-less multi-cloud replication:

### 1. `SUG1` Envelope Encryption (AES-256-GCM)
- Every clean file is encrypted at the application level into the **`SUG1` binary envelope format**:
  - `Magic`: 4 bytes ASCII (`SUG1`).
  - `Version`: 1 byte (`0x01`).
  - `IV / Nonce`: 12 bytes cryptographically secure random bytes (unique per file; tested for non-collision across 10,000 runs).
  - `Wrapped DEK Length`: 2 bytes big-endian unsigned integer.
  - `Wrapped DEK`: Per-file 256-bit Data Encryption Key (DEK) encrypted with the master Key Encryption Key (KEK) using AES-256-KeyWrap (RFC 3394).
  - `Auth Tag`: 16 bytes GCM authentication tag.
  - `AAD (Additional Authenticated Data)`: Cryptographically binds file metadata (`app_id`, `file_id`, `storage_version_id`, `sha256_plaintext`).
  - `Ciphertext`: Streamed payload encrypted with AES-256-GCM.
- **Verify-Before-Release Decryption**: Download streams authenticate the GCM tag (`decipher.final()`) before releasing plaintext bytes. Any tampering or truncated payload results in immediate stream destruction and HTTP 500 error.
- **Key Management**: Master KEK is provided via Docker Secret locally and AWS SSM Parameter Store (`SecureString`, `value_wo`) in cloud deployment.

### 2. Exact-Artifact Promotion Protocol (TOCTOU Immunity)
- Promotion is executed **strictly** by `services/promotion`:
  1. Claims an un-superseded `ALLOW` decision from PostgreSQL.
  2. Queries quarantine storage strictly by **`bound_storage_version_id`** (never by object key alone).
  3. Streams the object through a hash tee, re-computing SHA-256 and byte length.
  4. If the re-computed hash diverges from `decision.bound_sha256` or length differs from `decision.bound_size`, the promotion is **IMMEDIATELY ABORTED**, `BLOCK / HASH_MISMATCH` is audited, and an alert is triggered.
  5. The verified bytes are encrypted into `SUG1` ciphertext.
  6. The ciphertext is written to clean storage (`sug-clean-*`) using `s3:PutObject` with condition `If-None-Match: *` (preventing overwrite of existing promoted files).
  7. In the same database transaction, `cloud_objects` is inserted and an `audit_events` entry is recorded.

### 3. Multi-Cloud Replication via Workload Identity Federation (WIF)
- Replicates ciphertext to Google Cloud Storage (`sug-replica-*`) in a secondary cloud region.
- **Zero Static Service Account Keys**:
  - AWS replication worker authenticates to GCP using **Workload Identity Federation (AIP-4117)**.
  - Google's auth library exchanges AWS STS temporary session credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) for short-lived Google OAuth tokens via a configured Workload Identity Pool Provider.
  - The federated identity is granted only `roles/storage.objectCreator` on the replica bucket.
- **Write-Once Replica**:
  - GCS uploads enforce `preconditionOpts: { ifGenerationMatch: 0 }`, ensuring objects cannot overwrite existing generations.
  - The replica contains ONLY `SUG1` ciphertext. GCS and GCP IAM hold NO access to the KEK, ensuring complete confidentiality even in the event of total GCP project compromise.

### 4. Hash-Chained Audit Logging & Checkpoints
- State transitions are recorded in `audit_events` with fields `(seq, prev_hash, event_hash, event_type, payload)`.
- Hash chain formula: `event_hash = SHA256(seq || prev_hash || event_type || payload)`.
- PostgreSQL trigger `forbid_mutation()` raises an exception on any attempt to `UPDATE` or `DELETE` audit rows.
- Periodic Ed25519-signed audit checkpoints are exported to an S3 Object Lock bucket and GCS bucket every 10 minutes.

## Alternatives Considered
- **Direct S3 CopyObject**: Rejected because S3 `CopyObject` bypasses re-verification, does not allow streaming application-level encryption, and fails when conditional `If-None-Match` bucket policies are enforced (DEC-016).
- **GCP Service Account JSON Key**: Rejected due to high risk of secret exfiltration and security audit violation.
- **Blockchain for Audit Log**: Rejected per Literature Survey Section 3.5; relational append-only triggers combined with cryptographic hash-chaining and S3 Object Lock provide mathematically equivalent tamper evidence without blockchain latency and infrastructure overhead.

## Security Impact
Guarantees Non-Negotiable Invariants 1, 3, and 5. Eliminates TOCTOU race windows entirely, ensures cryptographic confidentiality across cloud providers, and creates a tamper-evident audit record.

## Cost Impact
Envelope encryption runs in-process with minimal CPU overhead. Replication uses standard S3 egress and GCS ingress. SSM Parameter Store with AWS-managed keys avoids per-key KMS hourly charges.

## Research Impact
Directly operationalizes Hypothesis H3 (version-binding prevents promotion of modified artifacts) and powers the TOCTOU empirical race experiment in Phase 32.

## Consequences
- Clean bucket and replica bucket contain binary `SUG1` files, requiring gateway mediation for retrieval.
- GCP infrastructure setup requires configuring Workload Identity Federation in Terraform.

## Evidence & Source References
- NIST SP 800-38D (Recommendation for Block Cipher Modes of Operation: GCM).
- RFC 3394 (Advanced Encryption Standard Key Wrap Algorithm).
- Google Cloud AIP-4117 (Workload Identity Federation with AWS).
- Build Plan: Part 1.1, Part 1.2 (DEC-012, DEC-013, DEC-014, DEC-015, DEC-016), Part 2.2 (P19, P20, P21, P26, P27, P28 contracts).
