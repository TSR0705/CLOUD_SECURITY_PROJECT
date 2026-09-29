# Phase P12 — SHA-256 Artifact Identity: Final Implementation & Verification Report

## 1. Executive Summary

Phase P12 establishes the cryptographic artifact identity layer of the Secure Upload Gateway (SUG). It defines and enforces an immutable, 5-tuple identity contract:
$$\text{ArtifactIdentity} = (\text{bucket}, \text{objectKey}, \text{versionId}, \text{sha256}, \text{sizeBytes})$$

This contract binds the physical quarantine object in cloud storage to its exact, server-calculated SHA-256 digest and payload length, completely eliminating Time-of-Check to Time-of-Use (TOCTOU) and object-replacement attack surfaces for all subsequent scanning, decision-making, and promotion phases.

All required quality gates, security invariants, and test suites are 100% passing:

- Monorepo compilation: `pnpm build` (`tsc -b`) cleanly passes.
- Linting: `pnpm lint` (`eslint .`) reports 0 errors and 0 warnings.
- Formatting: `pnpm format:check` reports clean formatting across all files.
- OpenAPI schema: `pnpm openapi:check` verified up to date with `docs/openapi.json`.
- Test suite: 37 test files, 510/510 tests passing (27 new unit tests, 2 new integration tests, 0 regressions).
- Secret scanning: Gitleaks scan passed with 0 leaks detected.

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

## 3. Cryptographic Invariants & Identity Specification

### 3.1 The 5-Tuple Identity Contract

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

### 3.2 Immutability Guarantee

All instances constructed via `createArtifactIdentity()` are frozen with `Object.freeze()` to prevent mutation across asynchronous pipeline boundaries.

---

## 4. Architecture & Implementation

### 4.1 `packages/shared/src/artifact-identity.ts`

Provides core primitives:

- `isValidSha256(raw: unknown): boolean`: Resiliently checks whether a string is a valid 64-hex SHA-256 (supporting optional `0x` or `\x` hex prefixes).
- `normalizeSha256(raw: string): string`: Normalizes hex strings to canonical 64-character lowercase format or throws `ArtifactIdentityError`.
- `toCanonicalSha256(raw: string | Buffer | Uint8Array): string`: Unifies string digests and raw 32-byte buffers into canonical 64-character lowercase hex.
- `createArtifactIdentity(input: CreateArtifactIdentityInput): ArtifactIdentity`: Factory function validating all invariants and freezing the resulting object.
- `validateArtifactIdentity(input: unknown): IdentityValidationResult`: Comprehensive schema validator collecting all discrete violation reasons.
- `timingSafeSha256Equal(hashA?: string | null, hashB?: string | null): boolean`: Constant-time comparison using `crypto.timingSafeEqual`.
- `compareArtifactIdentities(a, b): IdentityComparisonResult`: Full 5-way comparator collecting all mismatch classes: `['bucket', 'object_key', 'version_id', 'sha256', 'size_bytes']`.

### 4.2 Ingest Binding in `StreamingUploadService`

During `handleStreamingUpload()`:

1. Raw request body is piped through `CountingHashStream`.
2. Storage provider performs `putIfAbsent` into quarantine storage, returning storage `versionId`.
3. Ingest SHA-256 and byte length are verified against client headers (if declared).
4. The 32-byte binary hash is transactionally written to `file_versions.sha256_ingest` along with `storage_version_id`.
5. An authoritative `ArtifactIdentity` is instantiated and returned with the 202 accepted response.

### 4.3 Authoritative Status Query in `getUploadStatus`

When polling `GET /upload/:id/status`:

1. The session is verified against tenant isolation constraints (`upload_sessions.application_id = $2`).
2. When `session.status === 'UPLOADED'`, `files` is joined with `file_versions` on `current_version_id`.
3. The server constructs the `ArtifactIdentity` from database persistence (`bucket`, `object_key`, `storage_version_id`, `sha256_ingest`, `size_bytes`).
4. The response returns `{ sessionId, status, fileId, fileStatus, identity, createdAt, completedAt }`.
5. For pre-upload sessions (`CREATED`), `identity` is explicitly `null`.

---

## 5. Security & Threat Mitigation Analysis

| Threat / Attack Vector                            | Mitigation in P12                                                                                                                                                                                         |
| :------------------------------------------------ | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Object Replacement / S3 Overwrite (TOCTOU)**    | Version pinning: All operations bind the specific `versionId` returned at write time. Unversioned access (`'latest'`) is explicitly forbidden by `validateArtifactIdentity`.                              |
| **Hash Timing Attacks**                           | `timingSafeSha256Equal` normalizes input digests into fixed 32-byte buffers and delegates to `crypto.timingSafeEqual`.                                                                                    |
| **Buffer Length Injection in Timing Equal**       | Node's `crypto.timingSafeEqual` throws if lengths differ. Our implementation guards lengths prior to invocation, returning `false` safely without leaking execution time or throwing uncaught exceptions. |
| **Digest Masquerade / Client-Declared Tampering** | Server rejects uploads if `declaredSha256` does not match the real-time calculated stream digest. The server-computed digest in `file_versions.sha256_ingest` is the single source of truth.              |
| **In-Memory Tampering Across Stages**             | `ArtifactIdentity` instances are frozen with `Object.freeze()` upon creation.                                                                                                                             |
| **Cross-Tenant Status Disclosure**                | Status queries strictly filter by `application_id`, ensuring tenant isolation.                                                                                                                            |

---

## 6. Test Suite & Verification Matrix

### 6.1 Unit Test Matrix (`tests/unit/shared/artifact-identity.test.ts`)

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

### 6.2 Integration Test Matrix (`tests/integration/api/p12-artifact-identity.test.ts`)

| Test Scenario                               | Verification Points                                                                                                                                                                                                        | Status |
| :------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----- |
| **End-to-End Streaming & Identity Binding** | Upload streamed payload -> Validate 202 response includes `identity` -> Verify DB record in `file_versions` -> Verify `GET /upload/:id/status` returns identical identity -> `compareArtifactIdentities` reports equality. | PASS   |
| **Client Checksum Mismatch Rejection**      | Declared SHA-256 mismatch triggers HTTP 400 `CHECKSUM_MISMATCH`, session marked `FAILED`, status returns `identity: null`.                                                                                                 | PASS   |
| **Pre-Upload Session Status**               | Newly created session returns HTTP 200 with status `CREATED` and `identity: null`.                                                                                                                                         | PASS   |
| **Multi-Credential Authentication**         | Both Upload JWT and Application API Key can query status and retrieve authoritative `ArtifactIdentity`.                                                                                                                    | PASS   |

---

## 7. Quality Gates Summary

```bash
# Monorepo build
pnpm build -> PASS (tsc -b exited 0)

# Linting
pnpm lint -> PASS (eslint . exited 0)

# Code formatting
pnpm format:check -> PASS (prettier --check . exited 0)

# OpenAPI specification sync
pnpm openapi:check -> PASS (openapi.json up to date)

# Test execution
pnpm test -> PASS (37 test files, 510/510 tests passing)

# Secret scanning
docker run --rm -v "${PWD}:/path" zricethezav/gitleaks:latest detect --source="/path" -v
-> PASS (0 leaks found)
```

---

## 8. Conclusion & Sign-Off

Phase P12 is fully implemented, verified, and sealed. The cryptographic binding between storage objects and digest metadata is established, with full regression coverage and zero pull-forward scope into future phases. The codebase is ready for Phase P13.
