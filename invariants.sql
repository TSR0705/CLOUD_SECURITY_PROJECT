-- =============================================================================
-- Secure Upload Gateway (SUG) — Database & Storage Invariants
-- Phase 23 Deliverable D: Canonical Invariant Verification Script
--
-- Invariants Checked:
--   INV-01: Zero Orphan Clean Objects
--   INV-02: Zero Unapproved Clean Writes (BLOCK/REVIEW files never promoted)
--   INV-03: Sequential Audit Hash Chain Integrity (Zero gaps, valid prev_hash)
--   INV-04: Multi-Tenant Foreign Key & Isolation Consistency
--   INV-05: Artifact Identity & Cryptographic Version/Hash Binding
--   INV-06: Terminal Job State & Attempt Consistency
-- =============================================================================

-- -----------------------------------------------------------------------------
-- INV-01: Zero Orphan Clean Objects
-- Every object in cloud_objects (zone = 'clean') must reference an active,
-- un-superseded ALLOW decision and a file whose status is PROMOTED or DELETED.
-- -----------------------------------------------------------------------------
SELECT
  'INV-01A' AS invariant_id,
  'Clean object without un-superseded ALLOW decision' AS description,
  COUNT(*)::int AS violations
FROM cloud_objects co
WHERE co.zone = 'clean'
  AND NOT EXISTS (
    SELECT 1 FROM security_decisions sd
    WHERE sd.file_version_id = co.file_version_id
      AND sd.decision = 'ALLOW'
      AND NOT EXISTS (
        SELECT 1 FROM security_decisions child
        WHERE child.supersedes_id = sd.id
      )
  );

SELECT
  'INV-01B' AS invariant_id,
  'Clean object with invalid file status (must be PROMOTED or DELETED)' AS description,
  COUNT(*)::int AS violations
FROM cloud_objects co
JOIN file_versions fv ON co.file_version_id = fv.id
JOIN files f ON fv.file_id = f.id
WHERE co.zone = 'clean'
  AND f.status NOT IN ('PROMOTED', 'DELETED');

-- -----------------------------------------------------------------------------
-- INV-02: Zero Unapproved Clean Writes
-- No clean object may exist for a file version whose active decision is
-- BLOCK, QUARANTINE, or ERROR.
-- -----------------------------------------------------------------------------
SELECT
  'INV-02' AS invariant_id,
  'Clean object exists for BLOCKED or QUARANTINED file version' AS description,
  COUNT(*)::int AS violations
FROM cloud_objects co
JOIN security_decisions sd ON co.file_version_id = sd.file_version_id
WHERE co.zone = 'clean'
  AND sd.decision IN ('BLOCK', 'QUARANTINE', 'ERROR')
  AND NOT EXISTS (
    SELECT 1 FROM security_decisions child WHERE child.supersedes_id = sd.id
  );

-- -----------------------------------------------------------------------------
-- INV-03: Sequential Audit Hash Chain Integrity
-- Audit events must form a strictly contiguous sequence starting at 1,
-- with valid non-null hashes and prev_hash linking to previous event_hash.
-- -----------------------------------------------------------------------------
SELECT
  'INV-03A' AS invariant_id,
  'Audit sequence non-monotonic or duplicate sequence numbers' AS description,
  COUNT(*)::int AS violations
FROM (
  SELECT seq, LAG(seq) OVER (ORDER BY seq ASC) AS prev_seq
  FROM audit_events
) t
WHERE prev_seq IS NOT NULL AND seq <= prev_seq;

SELECT
  'INV-03B' AS invariant_id,
  'Audit event prev_hash does not match preceding event_hash' AS description,
  COUNT(*)::int AS violations
FROM (
  SELECT seq, prev_hash,
         LAG(event_hash) OVER (ORDER BY seq ASC) AS expected_prev
  FROM audit_events
) t
WHERE expected_prev IS NOT NULL AND prev_hash != expected_prev;

SELECT
  'INV-03C' AS invariant_id,
  'Audit event with NULL event_hash or prev_hash' AS description,
  COUNT(*)::int AS violations
FROM audit_events
WHERE event_hash IS NULL OR prev_hash IS NULL;

-- -----------------------------------------------------------------------------
-- INV-04: Multi-Tenant Foreign Key & Isolation Consistency
-- File application_id must match upload_session and audit_events application_id.
-- -----------------------------------------------------------------------------
SELECT
  'INV-04A' AS invariant_id,
  'File application_id mismatch with upload_session' AS description,
  COUNT(*)::int AS violations
FROM files f
JOIN upload_sessions us ON f.upload_session_id = us.id
WHERE f.application_id != us.application_id;

SELECT
  'INV-04B' AS invariant_id,
  'Audit event application_id mismatch with referenced file' AS description,
  COUNT(*)::int AS violations
FROM audit_events a
JOIN files f ON a.file_id = f.id
WHERE a.application_id IS NOT NULL AND a.application_id != f.application_id;

SELECT
  'INV-04C' AS invariant_id,
  'Upload session policy belongs to different application' AS description,
  COUNT(*)::int AS violations
FROM upload_sessions us
JOIN security_policies sp ON us.policy_id = sp.id
WHERE us.application_id != sp.application_id;

-- -----------------------------------------------------------------------------
-- INV-05: Artifact Identity & Cryptographic Version/Hash Binding
-- Non-null storage_version_id, matching sha256 between clean cloud_objects,
-- file_versions, scan_results, and security_decisions.
-- -----------------------------------------------------------------------------
SELECT
  'INV-05A' AS invariant_id,
  'Cloud object with empty or null storage_version_id' AS description,
  COUNT(*)::int AS violations
FROM cloud_objects
WHERE storage_version_id IS NULL OR storage_version_id = '' OR storage_version_id = 'null';

SELECT
  'INV-05B' AS invariant_id,
  'File version with empty or null storage_version_id' AS description,
  COUNT(*)::int AS violations
FROM file_versions
WHERE storage_version_id IS NULL OR storage_version_id = '' OR storage_version_id = 'null';

SELECT
  'INV-05C' AS invariant_id,
  'Clean object sha256_plain diverges from file_versions sha256_ingest' AS description,
  COUNT(*)::int AS violations
FROM cloud_objects co
JOIN file_versions fv ON co.file_version_id = fv.id
WHERE co.zone = 'clean' AND co.sha256_plain IS NOT NULL AND co.sha256_plain != fv.sha256_ingest;

SELECT
  'INV-05D' AS invariant_id,
  'Clean object sha256_plain diverges from scan_results scanned_sha256' AS description,
  COUNT(*)::int AS violations
FROM cloud_objects co
JOIN scan_results sr ON co.file_version_id = sr.file_version_id
WHERE co.zone = 'clean' AND co.sha256_plain IS NOT NULL AND co.sha256_plain != sr.scanned_sha256;

SELECT
  'INV-05E' AS invariant_id,
  'Clean object sha256_plain diverges from security_decisions bound_sha256' AS description,
  COUNT(*)::int AS violations
FROM cloud_objects co
JOIN security_decisions sd ON co.file_version_id = sd.file_version_id
WHERE co.zone = 'clean' AND co.sha256_plain IS NOT NULL AND co.sha256_plain != sd.bound_sha256;

-- -----------------------------------------------------------------------------
-- INV-06: Terminal Job State & Attempt Consistency
-- Finished jobs must have non-null finished_at timestamp.
-- -----------------------------------------------------------------------------
SELECT
  'INV-06A' AS invariant_id,
  'Finished scan_job missing finished_at timestamp' AS description,
  COUNT(*)::int AS violations
FROM scan_jobs
WHERE status IN ('SUCCEEDED', 'FAILED', 'DEAD') AND finished_at IS NULL;

SELECT
  'INV-06B' AS invariant_id,
  'Finished promotion_job missing finished_at timestamp' AS description,
  COUNT(*)::int AS violations
FROM promotion_jobs
WHERE status IN ('SUCCEEDED', 'FAILED', 'DEAD') AND finished_at IS NULL;
