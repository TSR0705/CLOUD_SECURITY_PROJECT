# Phase P9 — Storage Provider & Quarantine Bucket

## 1. Executive Summary

Phase P9 implements the provider-neutral object storage abstraction and AWS S3 implementation (`@sug/storage`) for the Secure Upload Gateway (SUG). It establishes immutable write-once quarantine semantics, explicit S3 object versioning controls, exact `VersionId` retrieval guarantees, and strict validation of server-controlled quarantine object paths.

Key achievements:

1. **Provider-Neutral Storage Contract (`StorageProvider`)**: Clean asynchronous interface providing `putIfAbsent`, `getByVersion`, and `head` methods without leaky provider abstractions.
2. **Write-Once Quarantine Semantics**: `putIfAbsent` enforces atomic creation preconditions (`If-None-Match: *`) and calculates/verifies SHA-256 digests. Duplicate writes on an existing key fail deterministically with `AlreadyExists` (HTTP 412).
3. **Exact `VersionId` Binding & Retrieval**: `getByVersion` requires a non-empty `VersionId` and queries S3 by explicit version. If the specified version is missing, it raises `VersionMissing` (HTTP 404). It **never** silently falls back to the latest object version.
4. **Server-Controlled Quarantine Key Scheme**: `buildQuarantineKey(applicationId, uploadId)` strictly formats keys as `incoming/<applicationId>/<uploadId>`, completely preventing path traversals (`..`), path separators (`/`, `\`), null bytes, whitespace, or arbitrary client-supplied filenames from reaching storage.
5. **Deterministic Error Normalization & Credential Sanitization**: Translates raw AWS SDK exceptions into strongly-typed `StorageError` subclasses while stripping access keys (`AKIA...`, `ASIA...`), secret access keys, bearer tokens, and Authorization headers.
6. **Integration Spike Verification**: Routes the P2 storage spike assumptions (S3-01 through S3-06) through `S3Provider` against LocalStack S3 (`sug-quarantine-local`).

---

## 2. Core Storage Architecture (`@sug/storage`)

### 2.1 StorageProvider Interface

```typescript
export interface StorageProvider {
  /**
   * Write-once object put. Enforces If-None-Match: * and records VersionId and SHA-256.
   * Rejects duplicate writes on an existing key with AlreadyExists.
   */
  putIfAbsent(params: PutObjectParams): Promise<PutObjectResult>;

  /**
   * Retrieves object content for a specific, exact VersionId.
   * Empty versionId is rejected with InvalidRequest.
   * Missing version is rejected with VersionMissing. Never falls back to latest version.
   */
  getByVersion(params: GetObjectParams): Promise<GetObjectResult>;

  /**
   * Retrieves object metadata/head information for a specific key and optional versionId.
   */
  head(params: HeadObjectParams): Promise<HeadObjectResult>;
}
```

### 2.2 S3Provider Implementation

`S3Provider` interacts with AWS S3 / LocalStack using AWS SDK v3 (`@aws-sdk/client-s3`):

- **Atomic Creation**: `PutObjectCommand` always includes `IfNoneMatch: '*'`.
- **Integrity Verification**: `ChecksumAlgorithm: 'SHA256'` is always attached, computing the digest on upload and converting base64 checksums into canonical 64-character hex strings.
- **Versioning Verification**: S3 response must return a non-empty `VersionId`. If missing, the operation fails immediately with `STORAGE_UNAVAILABLE` rather than accepting an unversioned object.
- **Streaming Pipeline**: `getByVersion` returns a standard Node.js `Readable` stream, preventing memory buffering for large uploads.

---

## 3. Server-Controlled Quarantine Key Scheme

Quarantine object keys must follow the strict server-controlled layout:

$$\text{Key} = \text{incoming}/\langle\text{applicationId}\rangle/\langle\text{uploadId}\rangle$$

### Security Controls:

1. **No Client Filenames**: Client-provided filenames, extensions, and directory paths are rejected and excluded from the storage key.
2. **Identifier Whitelist**: Identifiers are validated against `/^[a-zA-Z0-9_-]{1,128}$/`.
3. **Traversal Prevention**: Inputs containing `..`, `/`, `\`, null bytes (`\0`), whitespace, or URL encodings (`%2e%2e%2f`) throw an `InvalidRequest` error before any storage call is made.

---

## 4. Deterministic Error Normalization

Raw provider and network errors are mapped into strongly-typed `StorageError` classes:

| Raw S3 Signal / Code                     | Normalized Error     | HTTP Status | Invariant / Behavior                      |
| :--------------------------------------- | :------------------- | :---------: | :---------------------------------------- |
| `PreconditionFailed` / 412               | `AlreadyExists`      |     412     | Write-once collision; prevents overwrites |
| `NoSuchVersion` / 404 (with `versionId`) | `VersionMissing`     |     404     | Missing exact version; zero fallback      |
| `NoSuchKey` / `NotFound` / 404           | `NotFound`           |     404     | Key does not exist in bucket              |
| `AccessDenied` / 403                     | `PermissionDenied`   |     403     | IAM / bucket policy rejection             |
| `InvalidArgument` / 400                  | `InvalidRequest`     |     400     | Bad parameters, invalid key format        |
| `TimeoutError` / `ECONNREFUSED` / 5xx    | `StorageUnavailable` |     503     | Storage backend unavailable               |

### Credential Leakage Prevention

Error messages pass through `sanitizeMessage()`, which strips AWS access keys (`AKIA...`, `ASIA...`), secret access keys, authorization headers, passwords, and bearer tokens, replacing them with `[REDACTED]`.

---

## 5. Verification & Test Coverage

### Test Suites:

- `tests/unit/storage/quarantine-key.test.ts` (11 tests): Path traversal rejection, special character rejection, UUID and alphanumeric identifier validation, key parsing.
- `tests/unit/storage/s3-provider-errors.test.ts` (16 tests): Parameter validation, S3 error normalization (412 $\to$ AlreadyExists, 404 $\to$ VersionMissing, etc.), credential sanitization.
- `tests/integration/storage/s3-provider.test.ts` (7 tests): Live LocalStack S3 testing (write-once duplicate rejection, exact VersionId retrieval, SHA-256 round-trip survival, head lookups).

### Summary:

- **Total Test Suites**: 24 passed (24)
- **Total Tests**: 306 passed (306)
- **Quality Gates**: `pnpm lint`, `pnpm typecheck`, `pnpm format:check`, `pnpm openapi:check` all pass with 0 errors.
