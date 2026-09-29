# Phase P10 — Streaming Upload & Resource Limits

## 1. Executive Summary

Phase P10 implements raw HTTP request-body streaming into quarantine storage for the Secure Upload Gateway (SUG). It establishes zero-buffering stream pipelines, real-time byte counting and SHA-256 computation, strict resource limits (`effectiveLimit`), fast stream idle timeouts, atomic single-claim concurrency controls, and transactional database persistence.

Key achievements:

1. **PUT `/upload/:id` & `/api/v1/upload/:id`**: Accepts raw request streams authenticated via short-lived EdDSA upload tokens issued in P8.
2. **Zero-Buffering Raw Streaming**: Request bytes stream directly to quarantine storage via `CountingHashStream` with zero disk/temporary buffering and flat RSS memory profile. Multipart uploads are rejected with HTTP 415.
3. **Strict Effective Limit Enforcement (`val-10`)**: Stream size is strictly bounded by `effectiveLimit = min(policy.maxFileSize, declaredSize)`. Any stream exceeding this limit or declaring an excessive `Content-Length` is rejected immediately with HTTP 413 Payload Too Large.
4. **Fast Abort & Stream Idle Timeout**: Abort signals propagate instantly to the S3 provider on limit breach or after 30 seconds of inactivity without socket hang-up or resource leaks.
5. **Atomic Upload-Session Claim & Concurrency (`authz-05`)**: Uses atomic optimistic database locking (`UPDATE upload_sessions SET is_claimed = true, status = 'UPLOADING' WHERE id = $1 AND is_claimed = false AND status = 'CREATED'`) ensuring that concurrent token reuse attempts result in exactly one successful claim and exactly one quarantine object; all competing requests are rejected with HTTP 409 Conflict.
6. **Immutable VersionId Binding & DB Transaction**: Transactionally persists:
   - `files` row (`status: 'QUARANTINED'`)
   - `file_versions` row capturing the exact `storage_version_id` returned by P9 `StorageProvider.putIfAbsent`
   - `scan_jobs` row (`status: 'QUEUED'`)
   - Updates `upload_sessions` status to `UPLOADED`
   - Appends tamper-evident audit log event via PostgreSQL `audit_append()`
7. **HTTP 202 Acceptance**: Returns HTTP 202 Accepted with `fileId`, `fileVersionId`, `scanJobId`, `status`, `versionId`, `size`, and `sha256`.
8. **GET `/upload/:id/status`**: Allows clients to poll upload and quarantine status.

---

## 2. Architecture & Streaming Pipeline

```
                                  Client Request
                                        │
                                        ▼ (Raw HTTP Body Stream)
                            ┌───────────────────────┐
                            │ Fastify Route Handler │
                            │     PUT /upload/:id   │
                            └───────────┬───────────┘
                                        │
                                        ▼
                            ┌───────────────────────┐
                            │  StreamingUploadSvc   │
                            │  (Atomic DB Claim)    │
                            └───────────┬───────────┘
                                        │
                                        ▼
                            ┌───────────────────────┐
                            │  CountingHashStream   │
                            │  - Real-time SHA-256  │
                            │  - Byte Counter       │
                            │  - 30s Idle Timer     │
                            │  - Limit Abort Signal │
                            └───────────┬───────────┘
                                        │
                                        ▼ (Streaming S3 PutObject)
                            ┌───────────────────────┐
                            │   StorageProvider     │
                            │   (S3 / LocalStack)   │
                            └───────────┬───────────┘
                                        │
                                        ▼ (VersionId Captured)
                            ┌───────────────────────┐
                            │ PostgreSQL Transaction│
                            │ - files               │
                            │ - file_versions       │
                            │ - scan_jobs           │
                            │ - upload_sessions     │
                            │ - audit_append()      │
                            └───────────────────────┘
```

---

## 3. Verification & Definition of Done (DoD)

| Check ID        | Requirement                                  |  Result  | Evidence                                                                                                                                   |
| :-------------- | :------------------------------------------- | :------: | :----------------------------------------------------------------------------------------------------------------------------------------- |
| **val-10**      | Oversized Stream & Flat RSS Memory           | **PASS** | Streams exceeding `effectiveLimit` or declared `Content-Length` are aborted with HTTP 413; memory stays flat.                              |
| **authz-05**    | Single-Claim Token Concurrency Guarantee     | **PASS** | 10 concurrent PUT attempts with identical token result in exactly 1 HTTP 202 winner and 9 HTTP 409 Conflicts. Exactly 1 S3 object created. |
| **storage-ver** | `file_versions.storage_version_id` Populated | **PASS** | Exact non-empty S3 `VersionId` captured and stored in PostgreSQL `file_versions.storage_version_id`.                                       |
| **proto-01**    | Content-Type Validation                      | **PASS** | Multipart upload (`multipart/form-data`) rejected with HTTP 415.                                                                           |
| **proto-02**    | SHA-256 Integrity Verification               | **PASS** | Mismatch against optional `declaredSha256` rejects with HTTP 400.                                                                          |
| **proto-03**    | Empty File Rejection                         | **PASS** | Zero-byte body rejected with HTTP 400.                                                                                                     |
| **proto-04**    | Truncated Stream Detection                   | **PASS** | Early EOF mismatching declared `Content-Length` rejected with HTTP 400.                                                                    |
| **status-01**   | GET `/upload/:id/status` Polling             | **PASS** | Returns current upload session state and associated `fileId`.                                                                              |

---

## 4. Test Suite Summary

- Unit Tests: 3/3 passing (`tests/unit/api/counting-stream.test.ts`)
- Integration Tests: 12/12 passing (`tests/integration/api/p10-streaming-upload.test.ts`)
- Monorepo Total: 26/26 test suites passing (321/321 tests passing)
- Linting, Formatting, OpenAPI, and Typecheck: 100% PASS
