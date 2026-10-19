# Phase P21 Architectural & Security Resolution Document

**Target Phase:** Phase P21 — Hash-Chained Audit System & Checkpoints  
**Branch:** `phase/21-audit-chain`  
**Status:** All Security Gates Passed (100/100 tests passing)

---

## 1. Resolution of Issue A: Cryptographic Verification of Existing S3 Checkpoints

### Vulnerability Identified

Previously, when `storage.putIfAbsent` failed with an `AlreadyExists` or conflict error during checkpoint creation, the reconciliation logic relied merely on `storage.head({ bucket, key })` to obtain `versionId`. This was unsafe: an adversary or conflicting process could plant an arbitrary, malformed, or hostile object at that key, and the system would blindly adopt it without verifying its payload or signature.

### Remediation Implemented

1. `CheckpointStorageAdapter` and `createAuditCheckpoint` were upgraded to enforce mandatory retrieval of the exact S3 version (`storage.getByVersion({ bucket, key, versionId })`).
2. The raw object bytes are streamed, parsed into the canonical `AuditCheckpoint` JSON schema (`sug.audit_checkpoint/v1`), and strictly validated.
3. Cryptographic Ed25519 signature verification is executed using the trusted public key (`verifyCheckpointSignature(existingCp, publicKeyPem)`). If the signature is invalid or signed by an unauthorized key, the process immediately aborts fail-closed.
4. The verified checkpoint's `lastSeq` and `chainHash` are asserted against the intended database sequence and event hash.
5. If the database already had a checkpoint recorded for `lastSeq`, the S3 object is retrieved by `s3_version_id` and verified to match the DB record in `checkpointId`, `lastSeq`, and `chainHash`.
6. Negative adversarial tests were added verifying that invalid signatures, malformed JSON, mismatched `lastSeq`, or mismatched `chainHash` trigger fail-closed abortion with zero false success reporting.

---

## 2. Resolution of Issue B: Canonical Action-Code Taxonomy (`audit.checkpoint_created`)

### Discrepancy Identified

The checkpoint creation routine previously logged `checkpoint.created` instead of aligning with the canonical taxonomy (`audit.checkpoint_created`).

### Remediation Implemented

1. `packages/audit/src/checkpoint.ts` now records `'audit.checkpoint_created'` via PostgreSQL's `audit_append()`.
2. All unit tests (`tests/unit/audit/checkpoint.test.ts`, `tests/unit/api/audit.test.ts`) and integration tests (`tests/integration/audit/p21-audit.test.ts`) assert and filter by `audit.checkpoint_created`.
3. Event details payload records `checkpoint_id`, `last_seq`, `chain_hash`, and `s3_version_id`.

---

## 3. Resolution of Issue C: Adversarial Coverage Beyond Chain Links

### Gaps Identified

The test suite needed explicit adversarial verification beyond simple bitflip link tampering:

- Payload mutation with unchanged hash
- Forged history rewriting (recomputing downstream hashes)
- Interior row deletion and reordering
- Corrupted genesis root
- Conflicting/tampered S3 checkpoint object
- Empty audit ledger handling
- External anchoring verification
- Stale or missing checkpoint deletion detection

### Remediation Implemented

In `tests/integration/audit/p21-audit.test.ts`:

- **Scenario A (Bitflip):** Event hash bitflip detected at immediate successor sequence (`CHAIN_BROKEN`).
- **Scenario B (Payload Mutation):** Modifying JSON details without changing `event_hash` detected by byte-for-byte SHA-256 recomputation (`HASH_MISMATCH`).
- **Scenario C (Interior Deletion):** Deleting an interior row detected at successor sequence (`CHAIN_BROKEN`).
- **Scenario D (Corrupted Genesis):** Altering sequence 1 `prev_hash` away from 32 zero-bytes detected immediately (`GENESIS_VIOLATION`).
- **Scenario E (Row Permutation / Swapping):** Swapping adjacent event hashes violates sequence linkage (`CHAIN_BROKEN`).
- **Scenario F (Forged History Rewriting):** Superuser modifies an earlier event and recomputes all downstream hashes so internal DB links match. External Ed25519 checkpoint detects the divergence and flags `CHECKPOINT_PREFIX_MISMATCH`.
- **Scenario G (S3 Checkpoint Tampering):** Forged S3 checkpoint rejected during orphan reconciliation.
- **Scenario H (Stale / Missing Checkpoint Detection):** Deleting a checkpoint record from `audit_checkpoints` is detected by comparing against immutable `audit.checkpoint_created` ledger entries, returning `CHECKPOINT_STALE_OR_MISSING`.
- **Scenario I (S3 Checkpoint Storage Tampering / Mismatch):** Tampering with the physical S3 checkpoint object is detected during verification, returning `CHECKPOINT_STORAGE_MISMATCH`.
- **Fail-Closed Empty Chain:** Verifier rejects empty event collections by default (`EMPTY_CHAIN`).

---

## 4. Resolution of Issue D: Signed-Prefix vs Current-Head Semantics

### Ambiguity Identified

Clear distinction was required between the signed prefix (anchored by an external Ed25519 checkpoint) and ongoing continuation events up to the current ledger head.

### Remediation Implemented

1. **Signed Prefix Verification:**
   Calling `GET /audit/verify?to_seq=<checkpointLastSeq>` verifies only the immutable signed prefix. The verifier confirms that `headHash` matches the signed checkpoint's `chainHash`.
2. **Current Head Verification:**
   Calling `GET /audit/verify` verifies the full audit ledger up to current head. In addition to validating the full chain, the response inspects the latest checkpoint bounded by `last_seq <= headSeq`:
   - Validates Ed25519 signature (`signatureValid: true`).
   - Verifies the event in `audit_events` at `checkpoint.lastSeq` matches `checkpoint.chainHash` (`prefixMatched: true`).
   - Verifies physical S3 checkpoint object presence and identity.
   - Reports `subsequentEventsCount`, showing exactly how many events have arrived since the checkpoint.
   - If the database events diverged from the checkpoint hash, the verification fails closed with `CHECKPOINT_PREFIX_MISMATCH`.

---

## 5. Resolution of Issue E: Database Least Privilege for Checkpoint Writing

### Problem Identified

Previously, `sug_api` possessed direct `INSERT` permissions on `audit_checkpoints`, allowing a compromised API service session to write unvalidated checkpoint records directly into the table.

### Remediation Implemented

1. **Direct `INSERT` Revocation:**
   In `migrations/013_p21_audit_grants.sql`:
   ```sql
   GRANT SELECT ON audit_events TO sug_api;
   GRANT SELECT ON audit_checkpoints TO sug_api;
   REVOKE INSERT ON audit_checkpoints FROM sug_api;
   ```
2. **Narrowly-Scoped `SECURITY DEFINER` Checkpoint Function:**
   Checkpoint creation is routed exclusively through `audit_checkpoint_create()`:
   ```sql
   CREATE OR REPLACE FUNCTION audit_checkpoint_create(
       p_id uuid,
       p_last_seq bigint,
       p_chain_hash bytea,
       p_signature bytea,
       p_s3_version_id text,
       p_created_at timestamptz DEFAULT now()
   ) RETURNS uuid
   LANGUAGE plpgsql
   SECURITY DEFINER
   SET search_path = public, pg_temp
   ```
3. **In-Database Validations Under Advisory Lock:**
   The function acquires transaction advisory lock `7426002` and enforces:
   - Valid UUID, non-null `last_seq >= 1`.
   - Exactly 32 bytes for `chain_hash`.
   - Exactly 64 bytes for `signature`.
   - Non-empty `s3_version_id`.
   - Sequence existence in `audit_events` (`p_last_seq` must exist, else `foreign_key_violation`).
   - Byte-for-byte match: `p_chain_hash` must strictly equal `event_hash` at `p_last_seq` (`data_corrupted`).
   - Monotonic sequence progression: `p_last_seq >= MAX(c.last_seq)` for genuine checkpoints.
   - Idempotency via `ON CONFLICT (last_seq) DO NOTHING`.
4. **Verification via Integration Tests:**
   In `tests/integration/db/roles.test.ts`:
   - `P21-LP: sug_api cannot directly INSERT into audit_checkpoints`: Confirms direct insert fails with SQL error `42501 permission denied for table audit_checkpoints`.
   - `P21-LP: audit_checkpoint_create rejects nonexistent seq and mismatched chain_hash`: Confirms the function rejects nonexistent sequences and mismatched event hashes.

---

## 6. Resolution of Issue F: External Checkpoint Trust & Retention Model

### Independent Public Key Trust Root

- Checkpoint verification keys are loaded strictly from the container/secret filesystem (e.g. `secrets/checkpoint_public_key.pem` or `/run/secrets/checkpoint_public_key.pem`).
- The public key is **never stored in or loaded from database tables**. A database compromise cannot substitute or manipulate the verification trust root.

### External Object Storage Retention & Immutability

- Checkpoint payloads are written to S3 before database recording using strict `putIfAbsent` preconditions.
- In production, the audit bucket is configured with S3 Object Lock in Compliance Mode, prohibiting deletion or modification of checkpoint JSON files even by cloud root accounts throughout the retention lifecycle.
- Versioning is strictly enabled, and each checkpoint record in PostgreSQL stores the immutable `s3_version_id`.

### Stale / Missing Checkpoint Detection (Anti-Rollback)

- When any checkpoint is created, `audit_append()` records an immutable `audit.checkpoint_created` action in `audit_events`.
- During `GET /audit/verify`, the verifier queries `audit_events` for the latest `audit.checkpoint_created` event within the verified sequence slice.
- If a checkpoint creation event exists in the audit ledger, but `audit_checkpoints` is empty or holds an older checkpoint (`last_seq < maxAuditedSeq`), the verifier fails closed with `CHECKPOINT_STALE_OR_MISSING`.
- If `storageProvider` is available, the verifier also retrieves the checkpoint directly from S3 using `s3_version_id` and verifies payload identity. If missing or altered, it returns `CHECKPOINT_STORAGE_MISSING` or `CHECKPOINT_STORAGE_MISMATCH`.
