# Phase P23 Deliverable: End-to-End Lifecycle Suite Results

This document records the end-to-end verification of the three canonical file lifecycle paths defined in the Secure Upload Gateway Build Plan.

Suite Source: `tests/integration/lifecycle.test.ts`
Execution Status: PASS (3 of 3 paths passed)
Duration: ~1.2s

---

## Path 1: Upload -> Promoted (Clean Path)

### Workflow Description

A tenant uploads a clean document conforming to the active security policy. The file undergoes multi-engine scanning, policy evaluation, automatic promotion to clean storage, and authorized download verification.

### Detailed Step Execution Log

1. **Upload Session Initiation**:
   - Caller: Tenant A
   - Method: `SugClient.uploadFile(...)` (initiates `POST /api/v1/upload-sessions` then `PUT /api/v1/upload/:id`)
   - Payload: Valid PDF document (`%PDF-1.7 Clean document for Path 1 verification`)
   - Outcome: `uploadSessionId` generated, HMAC token signed, file queued.
2. **Scanner Execution**:
   - Worker claims scan job via PostgreSQL `FOR UPDATE SKIP LOCKED`.
   - Multi-engine analysis:
     - Format validator: PDF structure valid (`PASS`)
     - ClamAV daemon: No viral signatures detected (`PASS`)
     - YARA-X rules: No malicious heuristic rules triggered (`PASS`)
   - Outcome: `scan_jobs.status = 'SUCCEEDED'`, scan findings recorded in `scan_results`.
3. **Policy Evaluation**:
   - Decision Engine evaluates scan findings against Tenant A's active security policy.
   - Result: `security_decisions.decision = 'ALLOW'`.
4. **Clean Storage Promotion**:
   - Promotion worker claims promotion job.
   - Quarantine envelope is decrypted using AES-256-GCM.
   - Exact plaintext SHA-256 is verified against `sha256_ingest`.
   - Payload is re-encrypted into the clean bucket with KEK wrapping.
   - File record updated: `files.status = 'PROMOTED'`.
5. **Authorized Download Verification**:
   - Tenant A issues `GET /api/v1/files/:id/download`.
   - HTTP 200 OK returned with streaming binary octet-stream.
   - Security headers verified:
     - `X-Content-Type-Options: nosniff`
     - `Content-Security-Policy: sandbox; default-src 'none'`
     - `Content-Disposition: attachment; filename="..."`
   - Downloaded byte content matches original uploaded payload bit-for-bit.
6. **Cross-Tenant Attack Verification**:
   - Tenant B attempts `GET /api/v1/files/:id` -> HTTP 403 Forbidden.
   - Tenant B attempts `GET /api/v1/files/:id/download` -> HTTP 403 Forbidden.
   - Tenant B attempts `DELETE /api/v1/files/:id` -> HTTP 403 Forbidden.
7. **Database Invariants**:
   - Evaluated `invariants.sql`: 16 checks passed, 0 violations.

---

## Path 2: Upload -> Blocked (Zero Clean Writes)

### Workflow Description

A tenant uploads a file containing known malware (EICAR standard anti-virus test signature). The file is immediately detected, quarantined, and assigned an irrevocable `BLOCK` decision. Clean storage remains completely untouched.

### Detailed Step Execution Log

1. **Upload Ingestion**:
   - Payload: Standard EICAR string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
   - Ingest succeeds into isolated quarantine storage.
2. **Scanner Detection**:
   - ClamAV scan returns viral signature: `Eicar-Test-Signature`.
   - Overall scan outcome: `FAIL`.
   - Scanner sets `scan_jobs.status = 'SUCCEEDED'` with failure finding recorded.
3. **Decision Engine Gate**:
   - Decision Engine processes `FAIL` outcome.
   - Emits immutable `BLOCK` decision.
   - File status updated: `files.status = 'BLOCKED'`.
4. **Promotion Suppression & Clean Storage Verification**:
   - Clean S3 storage inspected: 0 objects exist for this file.
   - Promotion job table inspected: 0 promotion jobs queued.
5. **Tenant Access Denial**:
   - Tenant A attempts `GET /api/v1/files/:id/download` -> HTTP 400 Bad Request (`File Not Available`).
6. **Database Invariants**:
   - Evaluated `invariants.sql`: Invariant `INV-02` strictly holds (0 clean objects exist for BLOCKED file).

---

## Path 3: Upload -> Review -> Allow (Human Review Override)

### Workflow Description

A file triggers a policy condition requiring human security review (e.g., suspicious extension, active macro, or ambiguous heuristic). The file enters `IN_REVIEW` status, blocking downloads until an authorized human analyst reviews findings and grants an explicit signed override.

### Detailed Step Execution Log

1. **Upload & Review Trigger**:
   - File uploaded with extension / MIME requiring manual review.
   - Scan completes with review condition.
   - Decision Engine emits `decision = 'QUARANTINE'`.
   - File status updated: `files.status = 'IN_REVIEW'`.
2. **Premature Download Block**:
   - Tenant A attempts `GET /api/v1/files/:id/download` -> HTTP 400 Bad Request.
   - Tenant cannot download unpromoted file in review state.
3. **Analyst Review & Override**:
   - Authorized Security Analyst caller authenticates with signed analyst JWT.
   - Submits `POST /api/v1/security-decisions/:id/review`:
     ```json
     {
       "action": "ALLOW",
       "reason": "Authorized benign enterprise template verified by SecOps"
     }
     ```
   - New `ALLOW` security decision recorded with `override_by = analyst_id`.
   - Immutable audit event `decision.reviewed` appended to tamper-evident hash chain.
4. **Promotion & Download**:
   - Promotion worker claims job, verifies analyst decision, promotes to clean bucket.
   - File status updated: `files.status = 'PROMOTED'`.
   - Tenant A now successfully downloads decrypted payload.
5. **Database Invariants**:
   - Evaluated `invariants.sql`: 16 checks passed, 0 violations.
