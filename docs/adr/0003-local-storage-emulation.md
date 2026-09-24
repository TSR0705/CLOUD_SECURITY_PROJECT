# ADR 0003: Local Storage Emulation (LocalStack Community & fake-gcs-server)

## Status
PROVISIONAL / CHANGED (DEC-002, DEC-019, OPEN-2)

## Context
Local development and automated CI suites require faithful, local S3-compatible and Google Cloud Storage (GCS) emulators to test:
1. Object versioning (`VersionId` generation and deterministic retrieval).
2. Conditional writes (`If-None-Match: *` returning HTTP 412 Precondition Failed when an object key exists).
3. Checksum verification (`ChecksumAlgorithm: 'SHA256'` round-trip).
4. Cross-cloud replication preconditions (`ifGenerationMatch: 0`).

The original specification referenced MinIO. However, MinIO's public repository was archived, community prebuilt images were removed, and the `minio/minio` Docker Hub repository is unavailable. We need a modern, maintained S3 emulator and a reliable GCS emulator.

## Decision
1. **Primary S3 Emulator**: We adopt **LocalStack Community** (`localstack/localstack:2026.08.3`) configured with `SERVICES=s3`.
   - LocalStack Community supports S3 bucket versioning, `If-None-Match` on `PutObject` (since v3.7.0), `If-Match` (since v4.0.3), and SHA-256 checksums.
2. **P2 Storage Spike (Technical Gate)**:
   - In Phase 2, a formal test suite (`packages/storage/test/assumptions.test.ts`) will execute five mandatory assertions against LocalStack:
     - `PutObject` generates a valid `VersionId`.
     - `PutObject` with `If-None-Match: *` rejects duplicate writes with HTTP 412.
     - `GetObject` by an older `VersionId` returns previous bytes even if a new version exists.
     - `ChecksumAlgorithm: 'SHA256'` validates successfully.
     - Overwrite prevention works as expected.
3. **Fallback Strategy (SeaweedFS)**:
   - If LocalStack fails any of these five assertions, the project will immediately pivot to **SeaweedFS 4.45** (which supports S3 versioning, conditional headers, and per-identity access controls).
4. **Local GCS Emulator**:
   - We adopt **`fsouza/fake-gcs-server:1.56.1`** using the **JSON API exclusively**. The JSON API correctly honors `ifGenerationMatch: 0`, generation tracking, and declared CRC32C validation (the XML API does not).

## Alternatives Considered
- **MinIO**: Discarded due to repository archival, licensing restrictions, and lack of official distribution channels.
- **SeaweedFS 4.45**: High performance and native multi-identity support, but S3 API surface is less identical to AWS than LocalStack. Retained as primary fallback.
- **Google Cloud Storage Testbench**: Python-based emulator; heavier than `fake-gcs-server` without significant benefit for single-bucket write-once testing.

## Security Impact
Allows local end-to-end testing of write-once constraints, version immutability, and conditional promotion before deploying to live cloud infrastructure. Local privilege separation will use distinct AWS access key credentials per service.

## Cost Impact
Zero cloud cost during development and testing phases. Runs entirely within the local Docker Compose network.

## Research Impact
Ensures that experiments evaluating TOCTOU races and baseline comparison promoters (Phase 32) can run consistently in local test environments.

## Consequences
- LocalStack Community image download is larger (~1.5 GB); startup time must be budgeted in CI.
- LocalStack Community does not enforce IAM policies locally (DEC-003); real IAM policy enforcement must be verified on AWS in Phase 25/29.

## Evidence & Source References
- LocalStack S3 Documentation (v3.7.0, v4.0.3 conditional write support).
- Build Plan: Section 1.2 (DEC-002, DEC-019), Section 1.3 (OPEN-2), Section 2.2 (P2 contract).
- fake-gcs-server: JSON API upload implementation (`upload.go`).
