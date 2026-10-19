# Phase P21 Architectural & Security Resolution Document

**Target Phase:** Phase P21 — Hash-Chained Audit System & Checkpoints  
**Branch:** `phase/21-audit-chain`  
**Status:** All Security Gates Passed (85/85 tests passing)

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

### Remediation Implemented

In `tests/integration/audit/p21-audit.test.ts`:

- **Scenario A (Bitflip):** Event hash bitflip detected at immediate successor sequence (`CHAIN_BROKEN`).
- **Scenario B (Payload Mutation):** Modifying JSON details without changing `event_hash` detected by byte-for-byte SHA-256 recomputation (`HASH_MISMATCH`).
- **Scenario C (Interior Deletion):** Deleting an interior row detected at successor sequence (`CHAIN_BROKEN`).
- **Scenario D (Corrupted Genesis):** Altering sequence 1 `prev_hash` away from 32 zero-bytes detected immediately (`GENESIS_VIOLATION`).
- **Scenario E (Row Permutation / Swapping):** Swapping adjacent event hashes violates sequence linkage (`CHAIN_BROKEN`).
- **Scenario F (Forged History Rewriting):** Superuser modifies an earlier event and recomputes all downstream hashes so internal DB links match. External Ed25519 checkpoint detects the divergence and flags `CHECKPOINT_PREFIX_MISMATCH`.
- **Scenario G (S3 Checkpoint Tampering):** Forged S3 checkpoint rejected during orphan reconciliation.
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
   - Reports `subsequentEventsCount`, showing exactly how many events have arrived since the checkpoint.
   - If the database events diverged from the checkpoint hash, the verification fails closed with `CHECKPOINT_PREFIX_MISMATCH`.

---

## 5. Resolution of Issue E: Database Least Privilege for Checkpoint Writing

### Architecture Review & Privilege Separation

1. **Role Grants:**
   In `migrations/013_p21_audit_grants.sql`, `sug_api` is granted:
   ```sql
   GRANT SELECT ON audit_events TO sug_api;
   GRANT SELECT, INSERT ON audit_checkpoints TO sug_api;
   ```
   `sug_api` does NOT possess `UPDATE`, `DELETE`, or `TRUNCATE` privileges on `audit_checkpoints` or `audit_events`.
2. **Immutable Mutation Triggers:**
   In `migrations/008_indexes_constraints_triggers.sql`, `audit_checkpoints` is protected by `audit_checkpoints_immutable`:
   ```sql
   CREATE TRIGGER audit_checkpoints_immutable
       BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_checkpoints
       FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
   ```
   Even if a database role possessed `UPDATE` or `DELETE` grants, any statement mutating existing checkpoint rows is aborted by the database engine.
3. **Application Layer Guarding:**
   The `POST /audit/checkpoints` endpoint is restricted strictly to authenticated users with role `admin` or `auditor`. API keys and `analyst` users are rejected with `403 Forbidden`.
