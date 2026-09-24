# Attack Taxonomy: T1–T8 Verdict-Binding Threats in Cloud Object Storage

This taxonomy formalizes the eight critical threat classes (T1–T8) that target promotion pipelines in cloud object storage systems. These threats exploit the asynchronous, decoupled nature of cloud event pipelines, storage eventual consistency, and Time-of-Check-to-Time-of-Use (TOCTOU) race windows.

---

## T1 — Overwrite After Scan

### 1. Attack Description
An attacker uploads a benign file to quarantine storage under a specific key. The scanner inspects the file and reports it clean. The decision engine emits an `ALLOW` decision. Before the promotion service copies the file to clean storage, the attacker uploads a malicious file to the exact same quarantine key, overwriting the object. If the promotion service reads by key alone, the malicious payload is promoted to clean storage.

### 2. Preconditions
- Attacker has upload permissions to the quarantine bucket.
- Promotion service reads objects using `(bucket, key)` without specifying an immutable `VersionId` or verifying content hash.

### 3. Attacker Capability
Ability to issue concurrent `PutObject` requests to quarantine storage.

### 4. Affected Component
`services/promotion`, quarantine storage (`sug-quarantine-*`), clean storage (`sug-clean-*`).

### 5. Attack Sequence
1. Attacker calls `PUT /upload/:id` with benign file `invoice.pdf` (Version V1).
2. Scanner reads V1 and records clean findings.
3. Decision engine creates `security_decisions` row for `invoice.pdf` (`status = 'ALLOW'`).
4. Attacker issues a second `PUT` replacing `invoice.pdf` with malware (Version V2).
5. Promoter fetches `invoice.pdf` by key without version ID $\to$ receives V2 (malware).
6. Promoter encrypts V2 and deposits it into trusted clean storage.

### 6. Security Consequence
High: Unscanned, malicious executable/payload placed in trusted production storage.

### 7. Prevention Layer
- **Version-Binding**: Ingest records `storage_version_id` (V1). Decision records explicitly bind to `(bucket, key, bound_storage_version_id, bound_sha256)`.
- Promoter requests `GetObject(Key, VersionId=V1)`; never reads unversioned key.
- S3 Bucket Policy: `DenyOverwrite` (`s3:if-none-match` condition).

### 8. Detection Layer
- Invariant SQL check `int-01` detects orphaned or divergent version IDs.
- Promotion re-hash compares fetched bytes against `bound_sha256` $\to$ raises `HASH_MISMATCH`.

### 9. Research Experiment Mapping
Phase 32 TOCTOU Harness (Experiment H3: Baseline Promoter P0 [Key-Only] vs Bound Promoter).

---

## T2 — Overwrite During Scan

### 1. Attack Description
The attacker uploads a benign file. While the scanner worker is actively reading and scanning the stream, the attacker overwrites the file in quarantine storage. A naive pipeline might evaluate the first part of the scan on benign bytes and a second part on malicious bytes, or complete the scan and emit an `ALLOW` that applies to the newly created object.

### 2. Preconditions
Object storage allows concurrent writes to the same key; scanner does not pin the version ID during the retrieval process.

### 3. Attacker Capability
High-frequency automated upload tooling racing against scanner execution.

### 4. Affected Component
`services/scanner`, `sug-quarantine-*`.

### 5. Attack Sequence
1. Attacker uploads benign file $F_A$ (Version V1).
2. `scan_job` dispatched with `storage_version_id = V1`.
3. Attacker immediately uploads malicious file $F_B$ (Version V2) under same key.
4. Scanner worker claims `scan_job`. If scanner fetches without `VersionId`, it scans $F_B$, but might attribute results to session $F_A$, or vice versa.

### 6. Security Consequence
High: Inconsistent scan results; potential to clear a malicious version or produce corrupted findings.

### 7. Prevention Layer
- `scan_jobs` table explicitly contains `storage_version_id`.
- Scanner worker *always* passes `VersionId` to S3 `GetObject`. S3 guarantees read isolation for immutable versions.

### 8. Detection Layer
- Scanner compares ingest hash from `file_versions` with the byte stream hash computed during scanning. If mismatched, raises `RESULT_IDENTITY_MISMATCH`.

### 9. Research Experiment Mapping
Phase 32 TOCTOU Harness (Window $W_1$: Ingest-to-Scan race).

---

## T3 — Stale or Duplicated Event

### 1. Attack Description
A network glitch, worker crash, or message replay causes a previously processed `scan_job` or `promotion_job` to execute a second time after the file state or policy has been modified.

### 2. Preconditions
At-least-once message delivery or worker retry without idempotent state checking.

### 3. Attacker Capability
Network-level retransmission or inducing worker failure mid-execution.

### 4. Affected Component
PostgreSQL job queue, `services/scanner`, `services/promotion`.

### 5. Attack Sequence
1. File uploaded, scanned, and placed in `QUARANTINE` status.
2. A stale duplicate job or replayed event arrives at the worker queue.
3. Worker re-executes without verifying if the file state has transitioned, potentially clobbering updated review decisions.

### 6. Security Consequence
Medium: Inconsistent state transitions, duplicated audit events, or race conditions during status updates.

### 7. Prevention Layer
- Idempotency guards in PostgreSQL: state machines enforce valid transitions (`PENDING` $\to$ `CLAIMED` $\to$ `COMPLETED`).
- Conditional writes (`UPDATE ... WHERE status = 'PENDING'`).
- `cloud_objects` enforces unique constraint on `(file_id)`. Clean bucket `PutObject` enforces `If-None-Match: *`.

### 8. Detection Layer
- PostgreSQL duplicate key violation (23505) logged and handled gracefully.
- Audit event log tracks sequence numbers (`seq`).

### 9. Research Experiment Mapping
Phase 23 Chaos Suite (Chaos test: duplicated jobs injection).

---

## T4 — Delete and Recreate

### 1. Attack Description
The attacker uploads benign file $A$ under key $K$. The file passes scan and is approved. Before promotion, the attacker issues a `DeleteObject` on key $K$ and immediately creates a new object with malicious payload under key $K$. In S3, deleting an object in a versioned bucket inserts a Delete Marker; a subsequent write creates a brand new Version V3. If promoter queries by key without version, it fetches V3.

### 2. Preconditions
Quarantine bucket permits `s3:DeleteObject`; promoter queries by key without checking version ID or delete markers.

### 3. Attacker Capability
Client holds write/delete permissions on the quarantine bucket.

### 4. Affected Component
`sug-quarantine-*`, `services/promotion`.

### 5. Attack Sequence
1. Attacker uploads file (Version V1). Decision = `ALLOW`.
2. Attacker deletes key $K$ (creates Delete Marker V2).
3. Attacker uploads malware to key $K$ (creates Version V3).
4. Promoter fetches key $K$ $\to$ receives V3.

### 6. Security Consequence
High: Bypass of security screening via delete marker manipulation.

### 7. Prevention Layer
- IAM policy on `sug-quarantine-*` explicitly DENIES `s3:DeleteObject` and `s3:DeleteObjectVersion` to all application identities (`UPLOAD_ROLE`, `SCANNER_ROLE`, `PROMOTION_ROLE`). Objects can only expire via S3 Lifecycle rule (7-day TTL).
- Promoter requests explicit `bound_storage_version_id = V1`.

### 8. Detection Layer
- S3 CloudTrail logs flag any unauthorized `DeleteObject` attempts (`AccessDenied`).
- If promoter requested V1, S3 returns the exact original bytes of V1 (even with delete marker present at head).

### 9. Research Experiment Mapping
Phase 29 IAM Negative Testing (`iam-04`: deletion denied).

---

## T5 — Result Substitution

### 1. Attack Description
An attacker compromises a worker or exploits a race condition to associate scan results from a benign file with the scan record of a malicious file.

### 2. Preconditions
Scan results are indexed by mutable identifiers (e.g., filename or client upload ID) rather than cryptographic artifact hash.

### 3. Attacker Capability
Database injection or manipulating parameters in internal job messages.

### 4. Affected Component
`services/scanner`, `scan_results` table, `packages/decision-engine`.

### 5. Attack Sequence
1. Benign file $A$ scanned $\to$ clean results.
2. Malicious file $B$ scanned $\to$ malicious findings.
3. Attacker alters `file_version_id` on findings row to point to file $B$.
4. Decision engine evaluates benign findings for file $B$ and emits `ALLOW`.

### 6. Security Consequence
Critical: Malicious artifact receives legitimate `ALLOW` decision.

### 7. Prevention Layer
- Database constraints: `scan_results` contains `scanned_sha256` and foreign key to `file_versions`.
- **Decision Engine Rule R1**: Before evaluating findings, the decision engine strictly asserts `finding.scanned_sha256 == file_version.sha256`. If mismatched, immediately issues `BLOCK / RESULT_IDENTITY_MISMATCH`.

### 8. Detection Layer
- Decision engine invariant property test (10,000 randomized cases in P18).
- Audit log records full tuple in `security_decisions`.

### 9. Research Experiment Mapping
Phase 18 Decision Engine property tests.

---

## T6 — Content Differs Despite Same Version

### 1. Attack Description
A corrupted or malicious S3 emulator or compromised storage engine returns altered content when requested by a specific `VersionId`. (Or an attacker exploits a hash collision / storage corruption bug).

### 2. Preconditions
Storage backend corruption, collision attack, or emulator divergence where `VersionId` does not guarantee bit-level immutability.

### 3. Attacker Capability
Compromise of the storage provider or deep storage engine bug.

### 4. Affected Component
Storage provider, `services/promotion`.

### 5. Attack Sequence
1. File uploaded with SHA-256 hash $H_1$, Version $V_1$.
2. Decision engine emits `ALLOW` for $(V_1, H_1)$.
3. Promoter calls `GetObject(Key, VersionId=V1)`.
4. Storage returns bytes with hash $H_2 \neq H_1$.

### 6. Security Consequence
High: Corruption of clean storage or promotion of tampered data.

### 7. Prevention Layer
- **Mandatory Re-Hash**: `services/promotion` streams bytes through an in-memory SHA-256 tee before encryption.
- Strict assertion: `computed_sha256 == bound_sha256`. If unequal, promotion is immediately halted.

### 8. Detection Layer
- Metric `sug_hash_mismatch_total` incremented.
- Audit event `PROMOTION_HASH_MISMATCH` emitted with `CRITICAL` severity.

### 9. Research Experiment Mapping
Phase 20 bound promotion unit test (`toctou-02: hash mismatch triggers abort`).

---

## T7 — Replay of an Old ALLOW Decision

### 1. Attack Description
An administrative reviewer or analyst initially approved a file under an older security policy. Later, the security policy is updated to be stricter (e.g., blocking macros in OOXML), or new threat intelligence flags the file, superseding the original decision with a `BLOCK`. An attacker attempts to trigger promotion by replaying the older `ALLOW` decision record.

### 2. Preconditions
Promotion service queries any historical `ALLOW` record without verifying whether it has been superseded by a newer decision.

### 3. Attacker Capability
Triggering promotion worker retries or replaying database IDs.

### 4. Affected Component
`security_decisions` table, `services/promotion`.

### 5. Attack Sequence
1. Decision $D_1$ emitted: `ALLOW`.
2. Admin reviews file and inserts Decision $D_2$: `BLOCK` (superseding $D_1$).
3. Promotion job for $D_1$ executes $\to$ naive promoter checks $D_1$.verdict == `ALLOW` and promotes.

### 6. Security Consequence
High: Promotion of a blocked/quarantined file in direct violation of active policy.

### 7. Prevention Layer
- **Non-Supersession Query**: `services/promotion` verifies:
  `SELECT id FROM security_decisions WHERE file_version_id = :vid AND superseded_at IS NULL AND verdict = 'ALLOW'`.
- When a new decision is inserted for a file version, any previous active decision is atomically marked `superseded_at = NOW()` in the same transaction.

### 8. Detection Layer
- Audit log captures `DECISION_SUPERSEDED` and `PROMOTION_SKIPPED_SUPERSEDED`.

### 9. Research Experiment Mapping
Phase 20 integration tests (`toctou-04: superseded decision prevents promotion`).

---

## T8 — Race Inside Promotion

### 1. Attack Description
Two promotion workers concurrently claim promotion jobs for the same file, or an attacker attempts to promote two different versions of a file to the same destination clean key simultaneously.

### 2. Preconditions
Distributed workers operating without atomic clean storage write locks or database concurrency control.

### 3. Attacker Capability
Inducing high concurrency or network race conditions during promotion.

### 4. Affected Component
`services/promotion`, `sug-clean-*`.

### 5. Attack Sequence
1. Worker 1 claims promotion for Version 1.
2. Worker 2 claims promotion for Version 2 (or a retry of Version 1).
3. Both workers stream ciphertext to clean key `objects/<app_id>/<file_id>`.
4. Without conditional writes, the second write silently overwrites the first, potentially corrupting cloud object tracking.

### 6. Security Consequence
Medium-High: Overwritten production artifacts, inconsistent database metadata, corrupted ciphertext.

### 7. Prevention Layer
- S3 Conditional Write: `PutObject` on clean storage ALWAYS specifies `If-None-Match: *`. S3 rejects the second write with HTTP 412 Precondition Failed.
- Database unique constraint on `cloud_objects(file_id)` ensures only one clean object record exists per logical file.
- S3 Bucket Policy: `DenyOverwrite` explicit rule.

### 8. Detection Layer
- Promoter logs HTTP 412 as `AlreadyExists` and marks duplicate job `COMPLETED` without overwriting data.

### 9. Research Experiment Mapping
Phase 23 Concurrency & Chaos Suite (1,000 concurrent promotions).
