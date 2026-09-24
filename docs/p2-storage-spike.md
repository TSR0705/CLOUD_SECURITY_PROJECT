# P2 Storage Assumption Spike Report

## Executive Summary

Phase P2 executed an experimental technical spike against live, local container emulators to determine whether the local development environment can faithfully support the exact artifact-bound promotion and multi-cloud replication semantics required by the Secure Upload Gateway architecture.

Both **LocalStack S3** and **fake-gcs-server JSON API** were tested with automated integration assertions without mocks. All tests passed.

---

## Environment

| Component            | Version / Specification                             | Notes                                             |
| :------------------- | :-------------------------------------------------- | :------------------------------------------------ |
| **Operating System** | Windows 11 Pro (WSL 2 backend)                      | Kernel 6.18.33.2-microsoft-standard-WSL2          |
| **Docker Engine**    | 29.6.1 (Docker Desktop)                             | WSL 2 Engine integration                          |
| **LocalStack**       | 2026.8.4 (image: `localstack/localstack:2026.08.3`) | Community S3 service on port 4566                 |
| **fake-GCS Server**  | 1.56.1 (image: `fsouza/fake-gcs-server:1.56.1`)     | HTTP JSON API on port 4443                        |
| **PostgreSQL**       | 18 (image: `postgres:18-alpine`)                    | Infrastructure availability verified on port 5432 |
| **Node.js**          | 24.14.0 (Active LTS)                                | Host execution runtime                            |
| **pnpm**             | 12.5.1 (Corepack pinned)                            | Monorepo package manager                          |

---

## S3 Tests (LocalStack Community)

| Test Identifier | Test Name                 | Expected Behavior                                                                         | Actual Behavior                                                                                             |  Result  |
| :-------------- | :------------------------ | :---------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------- | :------: |
| **S3-01**       | Versioned `PutObject`     | Non-empty `VersionId` string returned upon upload                                         | S3 `PutObject` returns 32-character alphanumeric `VersionId` (e.g. `AaDScSyPLOPxpZC6...`)                   | **PASS** |
| **S3-02**       | Create-Only `PutObject`   | Duplicate write rejected with HTTP 412 when `If-None-Match: *` is supplied                | SDK raises `PreconditionFailed` (HTTP 412); existing object is preserved without silent overwrite           | **PASS** |
| **S3-03**       | Old `VersionId` Retrieval | `GetObject` with historical `VersionId` returns original bytes after key overwrite        | Explicit `GetObject(VersionId: V1)` returns original content (`version-one`) while V2 returns `version-two` | **PASS** |
| **S3-04**       | SHA-256 Round Trip        | Pre-upload SHA-256 and byte length match post-retrieval digest and length                 | Digest (`c31337...`) and size (16,384 bytes) preserved identically through storage round-trip               | **PASS** |
| **S3-05**       | Identity Tuple Extraction | Interaction produces complete `(bucket, key, versionId, sha256, size)` record             | All 5 elements populated deterministically from storage interaction                                         | **PASS** |
| **S3-06**       | Historical Immutability   | Subsequent uploads to same key create distinct `VersionId` without altering prior version | `v1 !== v2`; querying V1 returns original bytes and SHA-256                                                 | **PASS** |

---

## GCS Tests (fake-gcs-server JSON API)

| Test Identifier | Test Name                    | Expected Behavior                                                             | Actual Behavior                                                                                                   |  Result  |
| :-------------- | :--------------------------- | :---------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------- | :------: |
| **GCS-01**      | `ifGenerationMatch=0` Create | Creation succeeds on non-existent object; returns generation string           | HTTP 200 OK returned; object metadata includes generation (e.g. `1790237042076603`)                               | **PASS** |
| **GCS-02**      | Create-Only Replay           | Attempting creation of existing object with `ifGenerationMatch=0` is rejected | HTTP 412 Precondition Failed returned with error payload `{"error":{"code":412,"message":"Precondition failed"}}` | **PASS** |
| **GCS-03**      | Generation Tracking          | Object exposes generation; updates produce distinct generation value          | Generated metadata exposes monotonic generation string; replacement produces `gen1 !== gen2`                      | **PASS** |

---

## Artifact Identity Support

The central architectural question of Phase P2:

> _"Can our local environment reliably emulate the exact object-version and conditional-write behaviors required to implement artifact-bound promotion?"_

**Answer: YES.**

The local environment fully satisfies the storage semantics required for artifact-bound promotion:

1. **Exact-Artifact Addressing**: When a file is uploaded to quarantine storage (`sug-quarantine-local`), S3 returns a unique `VersionId`. The decision engine and promotional worker can bind to this specific `VersionId`.
2. **Anti-TOCTOU Guarantee**: Even if a hostile actor uploads a malicious file to the exact same key during scanning, the promotion worker queries strictly by `bound_storage_version_id`. The emulator guarantees that the historical version remains accessible, unaltered, and hash-verified.
3. **Write-Once Promotion & Replication**:
   - In S3 clean storage: `PutObject` with `If-None-Match: *` prevents overwriting existing promoted files.
   - In GCS replica storage: `POST` with `ifGenerationMatch: 0` prevents overwriting replicated ciphertext.

The complete identity tuple:
$$\text{Artifact} = (\text{bucket}, \text{key}, \text{version\_id}, \text{SHA-256}, \text{size})$$
is fully supported and proven by the test suite `tests/integration/storage/assumptions.test.ts`.

---

## Emulator Limitations & Observations

1. **LocalStack IAM Enforcement**:
   - LocalStack Community does not enforce IAM access policies locally (consistent with DEC-003). All credentials (`test`/`test`) possess administrative access.
   - _Mitigation_: Privilege separation is architecturally isolated through distinct service clients and validated in cloud environments (Phase 29).
2. **LocalStack Licensing / Auth Token**:
   - The 2026.x LocalStack container requires `LOCALSTACK_AUTH_TOKEN` in the environment to bootstrap the runtime supervisor.
   - _Mitigation_: The token is stored in the local, gitignored `.env` file and passed into `docker-compose.yml`.
3. **fake-gcs-server API Compatibility**:
   - Generation preconditions (`ifGenerationMatch: 0`) and generation metadata are supported **exclusively** via the GCS JSON API (`/upload/storage/v1/b/...` and `/storage/v1/b/...`). The XML multipart API does not enforce generation preconditions.
   - _Mitigation_: The project client library (`@google-cloud/storage` / HTTP client) will use the JSON API exclusively, in conformance with ADR 0003.

---

## Decision

**LOCALSTACK ACCEPTED WITH DOCUMENTED LIMITATIONS**

The LocalStack Community + fake-gcs-server pairing successfully passes 100% of the required storage security assertions. The SeaweedFS fallback is **NOT** required.
