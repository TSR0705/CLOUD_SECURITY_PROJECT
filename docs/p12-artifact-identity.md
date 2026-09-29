# Phase P12 — SHA-256 Artifact Identity: Final Hardening & Evidence Report

## 1. Executive Summary

Phase P12 establishes the cryptographic artifact identity layer of the Secure Upload Gateway (SUG). It defines and enforces an immutable, 5-tuple identity contract:

$$\text{ArtifactIdentity} = (\text{bucket}, \text{objectKey}, \text{versionId}, \text{sha256}, \text{sizeBytes})$$

This contract establishes the exact artifact identity required for later TOCTOU-resistant verification and object-replacement detection. P12 does not itself enforce the final promotion-time TOCTOU defense; that enforcement is implemented in the later promotion phase.

### Core Research Boundary

> **P12 establishes identity. Later phases enforce identity binding.**
>
> In Phase P12, the gateway binds the physical quarantine object in cloud storage to its exact, server-calculated SHA-256 digest and payload length, persisting it to `file_versions.sha256_ingest` and exposing it through the upload API. Subsequent phases (P13+ scanner workers, decision engine, and promotion workers) are responsible for verifying that the objects they read and promote continue to match this authoritative identity.

All required quality gates, security invariants, and test suites are 100% passing:

- Monorepo compilation: `pnpm build` (`tsc -b`) cleanly passes.
- Typecheck: `pnpm typecheck` (`tsc -b`) cleanly passes.
- Linting: `pnpm lint` (`eslint .`) reports 0 errors and 0 warnings.
- Formatting: `pnpm format:check` reports clean formatting across all files.
- OpenAPI schema: `pnpm openapi:check` verified up to date with `docs/openapi.json`.
- Test suite: 37 test files, 510/510 tests passing (27 unit tests, 2 integration tests, 0 regressions).
- Secret scanning: Gitleaks scan passed with 0 leaks detected across both git commits and uncommitted filesystem (`--no-git`).

---

## 2. Canonical Scope & Strict Phase Boundaries

### Included in P12 Scope:

1. **Canonical `ArtifactIdentity` definition** in `packages/shared/src/artifact-identity.ts` binding storage location (`bucket`, `objectKey`), storage versioning (`versionId`), content integrity (`sha256`), and size (`sizeBytes`).
2. **Strict Identity Validation** (`validateArtifactIdentity`, `isArtifactIdentity`): Enforces non-empty strings, strict non-null/non-latest version identifier, lowercase 64-character hexadecimal regex (`^[0-9a-f]{64}$`), and non-negative integer size in bytes.
3. **Timing-Safe Digest Comparison** (`timingSafeSha256Equal`): Constant-time byte-level comparison using Node's `crypto.timingSafeEqual` with input sanitation, defensive buffer allocation, and zero-exception failure modes on mismatched lengths or malformed digests.
4. **Structured Mismatch Classification** (`compareArtifactIdentities`): Deterministic comparison across all 5 identity fields returning discrete mismatch categories (`bucket`, `object_key`, `version_id`, `sha256`, `size_bytes`).
5. **Streaming Ingest Binding**: Reuses P10's real-time `CountingHashStream` digest and transactional persistence in `file_versions.sha256_ingest` with no redundant hashing passes.
6. **API Status Exposure**: Enriches `GET /upload/:id/status` (and `GET /api/v1/upload/:id/status`) to query `file_versions` joined via `files.current_version_id` and return the authoritative server-persisted `ArtifactIdentity`.
7. **OpenAPI Schema Synchronization**: Updates `docs/openapi.json` to formally declare the `identity` property on upload status and ingestion responses.

### Explicitly Excluded (Strict Phase Boundary Defense):

- **NO P13+ Scanner Workers**: No worker queue consumers, job dispatchers, or worker processes.
- **NO ClamAV or YARA-X Engines**: Deferred to worker scanning phases.
- **NO Archive Extraction or Zip-Bomb Inspections**: Deferred to archive processing phases.
- **NO Decision Engine Logic**: No policy evaluations against findings or verdict generation.
- **NO Clean Storage / Promotion / Replication**: No moving files out of quarantine, encryption with clean keys, or cross-cloud replication.

---

## 3. Database Schema Verification: `scanned_*` and `bound_*` Fields

A core architectural question for P12 is whether the database schema required new migrations to support `scanned_*` identity fields:

### Determination: `scanned_*` fields ALREADY EXISTED prior to P12 (Option A)

The database schema defined in Phase P3 (`migrations/004_upload_files.sql` and `migrations/005_scan_and_decision.sql`) already fully modeled all required identity and verification fields:

1. **`migrations/004_upload_files.sql` — Ingest Identity:**
   Table `file_versions`:
   - `bucket text NOT NULL`
   - `object_key text NOT NULL`
   - `storage_version_id text NOT NULL`
   - `size_bytes bigint NOT NULL`
   - `sha256_ingest bytea NOT NULL CHECK (octet_length(sha256_ingest) = 32)`
     _Role in P12:_ Used by `StreamingUploadService` to transactionally persist the calculated digest and S3 `versionId`, and read by `getUploadStatus` to construct the authoritative `ArtifactIdentity`.

2. **`migrations/005_scan_and_decision.sql` (Lines 33–35) — Scanned Identity:**
   Table `scan_results`:
   - `scanned_storage_version_id text NOT NULL`
   - `scanned_sha256 bytea NOT NULL CHECK (octet_length(scanned_sha256) = 32)`
   - `scanned_size bigint NOT NULL`
     _Role in Architecture:_ Pre-provisioned in Phase P3 for Phase P13+ scanner workers to record the exact storage version and digest of the artifact they fetched from quarantine.

3. **`migrations/005_scan_and_decision.sql` (Lines 57–61) — Decision Bound Identity:**
   Table `security_decisions`:
   - `bound_bucket text NOT NULL`
   - `bound_key text NOT NULL`
   - `bound_storage_version_id text NOT NULL`
   - `bound_sha256 bytea NOT NULL CHECK (octet_length(bound_sha256) = 32)`
   - `bound_size bigint NOT NULL`
     _Role in Architecture:_ Pre-provisioned in Phase P3 for the decision engine to bind its verdict to the exact artifact identity before promotion.

**Conclusion:** No new database migrations were required or created in Phase P12. The existing Phase P3 schema satisfies all canonical identity storage requirements.

---

## 4. Cryptographic Invariants & Identity Specification

### 4.1 The 5-Tuple Identity Contract

An `ArtifactIdentity` is strictly frozen and represents an unalterable artifact version:

```typescript
export interface ArtifactIdentity {
  readonly bucket: string;
  readonly objectKey: string;
  readonly versionId: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}
```

Field constraints:

- `bucket`: Non-empty string identifying the quarantine storage bucket (e.g. `sug-quarantine-local`).
- `objectKey`: Non-empty string identifying the object key (e.g. `incoming/<appId>/<sessionId>`).
- `versionId`: Storage provider object version ID returned on atomic write. Must NOT be empty, `'null'`, or `'latest'`.
- `sha256`: Exactly 64 lowercase hexadecimal characters matching `^[0-9a-f]{64}$`.
- `sizeBytes`: Non-negative integer representing the exact payload byte count.

### 4.2 SHA-256 Representation & Input Normalization Review

- **Canonical Persisted Representation:**
  `ArtifactIdentity.sha256` is strictly and unconditionally a 64-character lowercase hexadecimal string (`^[0-9a-f]{64}$`).
- **Input Normalization API:**
  Helper functions (`isValidSha256`, `normalizeSha256`, `toCanonicalSha256`) exist solely as caller conveniences during ingestion or comparison:
  - Strips optional `0x` or `\x` hex prefixes.
  - Converts uppercase hex to lowercase.
  - Converts raw 32-byte binary buffers (`Buffer` or `Uint8Array`) to canonical hex.
  - Rejects digests that do not evaluate to exactly 32 bytes (64 hex characters).
    Inside `createArtifactIdentity`, `toCanonicalSha256` is invoked immediately and validated against `CANONICAL_SHA256_HEX_REGEX = /^[0-9a-f]{64}$/`. The resulting `ArtifactIdentity` object is frozen (`Object.freeze()`).

### 4.3 Timing-Safe Equality & Comparison

`timingSafeSha256Equal(hashA, hashB)`:

- Sanitizes and validates both inputs against `CANONICAL_SHA256_HEX_REGEX`.
- Allocates fixed 32-byte buffers from both hashes.
- Invokes `crypto.timingSafeEqual(bufA, bufB)` in constant time.
- If either input is missing, malformed, non-hex, or of differing length, returns `false` safely without throwing exceptions or leaking execution time.

---

## 5. Comparison Mismatch Coverage Verification

The comparator `compareArtifactIdentities(a, b)` evaluates all 5 dimensions and returns structured `IdentityMismatchClass` entries:

```typescript
export type IdentityMismatchClass =
  'bucket' | 'object_key' | 'version_id' | 'sha256' | 'size_bytes';
```

Verification of all mismatch classes in `tests/unit/shared/artifact-identity.test.ts`:

| Comparison Mismatch Class | Unit Test ID                    | Scenario                                                        | Result                                                                       |
| :------------------------ | :------------------------------ | :-------------------------------------------------------------- | :--------------------------------------------------------------------------- |
| **`bucket`**              | `T-ID-05`                       | Candidate has differing bucket name                             | `mismatches: ['bucket']`                                                     |
| **`object_key`**          | `T-ID-06`                       | Candidate has differing object key                              | `mismatches: ['object_key']`                                                 |
| **`version_id`**          | `T-ID-02`, `T-ID-08`            | Candidate has differing version ID, or empty/null/'latest'      | `mismatches: ['version_id']`                                                 |
| **`sha256`**              | `T-ID-03`, `T-ID-07`, `T-ID-09` | Candidate has differing hash, malformed hash, or truncated hash | `mismatches: ['sha256']`                                                     |
| **`size_bytes`**          | `T-ID-04`                       | Candidate has differing payload size                            | `mismatches: ['size_bytes']`                                                 |
| **Multiple simultaneous** | `T-ID-10`, null checks          | All fields differ or candidate is null/undefined                | `mismatches: ['bucket', 'object_key', 'version_id', 'sha256', 'size_bytes']` |

---

## 6. Architecture & Implementation

### 6.1 Ingest Binding in `StreamingUploadService`

During `handleStreamingUpload()`:

1. Raw request body is piped through `CountingHashStream`.
2. Storage provider performs `putIfAbsent` into quarantine storage, returning storage `versionId`.
3. Ingest SHA-256 and byte length are verified against client headers (if declared).
4. The 32-byte binary hash is transactionally written to `file_versions.sha256_ingest` along with `storage_version_id`.
5. An authoritative `ArtifactIdentity` is instantiated via `createArtifactIdentity` and returned with the `202 Accepted` response.

### 6.2 Authoritative Status Query in `getUploadStatus`

When polling `GET /upload/:id/status`:

1. The session is verified against tenant isolation constraints (`upload_sessions.application_id = $2`).
2. When `session.status === 'UPLOADED'`, `files` is joined with `file_versions` on `current_version_id`.
3. The server constructs the `ArtifactIdentity` from database persistence (`bucket`, `object_key`, `storage_version_id`, `sha256_ingest`, `size_bytes`).
4. The response returns `{ sessionId, status, fileId, fileStatus, identity, createdAt, completedAt }`.
5. For pre-upload sessions (`CREATED`), `identity` is explicitly `null`.

---

## 7. Security & Threat Mitigation Analysis

| Threat / Attack Vector                            | Role in P12 & Subsequent Phases                                                                                                                                                                                               |
| :------------------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Object Replacement / S3 Overwrite (TOCTOU)**    | P12 establishes the immutable 5-tuple `ArtifactIdentity` (including explicit `versionId`). Later phases (P13+ scanner workers and promotion service) perform the TOCTOU check by re-verifying this identity before promotion. |
| **Hash Timing Attacks**                           | `timingSafeSha256Equal` normalizes input digests into fixed 32-byte buffers and delegates to `crypto.timingSafeEqual`.                                                                                                        |
| **Buffer Length Injection in Timing Equal**       | Node's `crypto.timingSafeEqual` throws if lengths differ. Our implementation guards lengths prior to invocation, returning `false` safely without leaking execution time or throwing uncaught exceptions.                     |
| **Digest Masquerade / Client-Declared Tampering** | Server rejects uploads if `declaredSha256` does not match the real-time calculated stream digest. The server-computed digest in `file_versions.sha256_ingest` is the single source of truth.                                  |
| **In-Memory Tampering Across Stages**             | `ArtifactIdentity` instances are frozen with `Object.freeze()` upon creation.                                                                                                                                                 |
| **Cross-Tenant Status Disclosure**                | Status queries strictly filter by `application_id`, ensuring tenant isolation.                                                                                                                                                |

---

## 8. Test Suite & Verification Matrix

### 8.1 Unit Test Matrix (`tests/unit/shared/artifact-identity.test.ts`)

| Test ID   | Scenario                                     | Expected Outcome                                       | Status |
| :-------- | :------------------------------------------- | :----------------------------------------------------- | :----- |
| `T-ID-01` | Same key, same version, same hash, same size | `equal: true`, `mismatches: []`                        | PASS   |
| `T-ID-02` | Same key, different version                  | `equal: false`, `mismatches: ['version_id']`           | PASS   |
| `T-ID-03` | Same version, different hash                 | `equal: false`, `mismatches: ['sha256']`               | PASS   |
| `T-ID-04` | Same hash, different size                    | `equal: false`, `mismatches: ['size_bytes']`           | PASS   |
| `T-ID-05` | Different bucket                             | `equal: false`, `mismatches: ['bucket']`               | PASS   |
| `T-ID-06` | Different object key                         | `equal: false`, `mismatches: ['object_key']`           | PASS   |
| `T-ID-07` | Malformed SHA-256 in candidate               | `equal: false`, includes `'sha256'`                    | PASS   |
| `T-ID-08` | Empty / null / latest VersionId              | `equal: false`, includes `'version_id'`                | PASS   |
| `T-ID-09` | Different hash lengths                       | `equal: false`, safe mismatch without throwing         | PASS   |
| `T-ID-10` | Multiple fields differ                       | `equal: false`, all relevant mismatch classes returned | PASS   |
| `T-ID-11` | Factory immutability                         | `Object.isFrozen(identity) === true`                   | PASS   |
| `T-ID-12` | Timing safe equality edge cases              | Nulls, non-hex, uppercase, 0x, \x handled safely       | PASS   |

### 8.2 Integration Test Matrix (`tests/integration/api/p12-artifact-identity.test.ts`)

| Test Scenario                               | Verification Points                                                                                                                                                                                                        | Status |
| :------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----- |
| **End-to-End Streaming & Identity Binding** | Upload streamed payload -> Validate 202 response includes `identity` -> Verify DB record in `file_versions` -> Verify `GET /upload/:id/status` returns identical identity -> `compareArtifactIdentities` reports equality. | PASS   |
| **Client Checksum Mismatch Rejection**      | Declared SHA-256 mismatch triggers HTTP 400 `CHECKSUM_MISMATCH`, session marked `FAILED`, status returns `identity: null`.                                                                                                 | PASS   |
| **Pre-Upload Session Status**               | Newly created session returns HTTP 200 with status `CREATED` and `identity: null`.                                                                                                                                         | PASS   |
| **Multi-Credential Authentication**         | Both Upload JWT and Application API Key can query status and retrieve authoritative `ArtifactIdentity`.                                                                                                                    | PASS   |

---

## 9. Quality Gates Summary

```bash
# Monorepo build
pnpm build
-> PASS (tsc -b exited 0)

# Monorepo typecheck
pnpm typecheck
-> PASS (tsc -b exited 0)

# Linting
pnpm lint
-> PASS (eslint . exited 0)

# Code formatting
pnpm format:check
-> PASS (prettier --check . exited 0)

# OpenAPI specification sync
pnpm openapi:check
-> PASS (docs/openapi.json is up to date)

# Test execution
pnpm test
-> PASS (37 test files, 510/510 tests passed)

# Secret scanning (git history)
docker run --rm -v "${PWD}:/path" zricethezav/gitleaks:latest detect --source="/path" -v
-> PASS (0 leaks found)

# Secret scanning (uncommitted filesystem)
docker run --rm -v "${PWD}:/path" zricethezav/gitleaks:latest detect --source="/path" --no-git -v
-> PASS (0 leaks found)
```

---

## 10. Conclusion & Final Verdict

Phase P12 is fully hardened, verified, and sealed.

- The 5-tuple `ArtifactIdentity` contract is established and immutable.
- Ingest identity is persisted in PostgreSQL and exposed via API status endpoints.
- All comparison mismatch classes are tested and verified.
- The research boundary is explicit: **P12 establishes identity; later phases enforce identity binding.**
- Zero pull-forward scope into Phase P13.

**Verdict: FULL PASS — READY FOR PHASE P13.**
