# Architecture & Engineering Decision Register

This register records all baseline architectural, technological, and security decisions for the Secure Upload Gateway (SUG).

### Status Legend
- **APPROVED**: Decision verified, aligned with specifications, and frozen for implementation.
- **CHANGED**: Decision deliberately supersedes an earlier specification requirement, with verifiable evidence provided.
- **OPEN**: Architectural question or fork requiring experimental validation (e.g., P2 spike) or stakeholder confirmation.
- **RESOLVED**: Previously open decision that has been formally settled through verification.

---

## 1. Decision Matrix

| ID | Decision | Status | Reason | Alternatives | Evidence | Impact | Affected Components |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DEC-001** | Job queue inside PostgreSQL using `SELECT ... FOR UPDATE SKIP LOCKED` | **APPROVED** | Single state store to secure and back up; queue rows constitute audit evidence; target throughput is tens to hundreds of files/min. | Redis + BullMQ; AWS SQS; RabbitMQ; `pg-boss` library | PostgreSQL Official Documentation on `SKIP LOCKED` concurrency | Zero broker cost; atomic transactions spanning files and queue | `scanner`, `promotion`, `replication`, schema |
| **DEC-002** | Local S3-compatible storage emulator is LocalStack Community (`localstack/localstack:2026.08.3`), not MinIO | **CHANGED** (Spec said MinIO) | MinIO repository archived (April 2026); Docker Hub image returns 404; LocalStack Community supports versioning, conditional `If-None-Match`, and SHA-256 checksums. | MinIO from source; AIStor Free; SeaweedFS 4.45; Garage; RustFS | MinIO README; LocalStack v3.7.0 release notes & S3 docs | P2 spike validates compatibility; SeaweedFS retained as fallback | Docker Compose, `packages/storage`, local test suite |
| **DEC-003** | Local privilege separation enforced via application credentials; full IAM policy enforcement verified on AWS | **CHANGED** (Spec used MinIO per-user policies) | LocalStack Community does not enforce IAM policies locally (paid feature); distinct credential pairs simulate separation locally; real negative IAM tests run on AWS in P29. | SeaweedFS with `-s3.config` identities; run IAM tests only on AWS | LocalStack Community IAM Documentation | Local tests prove credential scoping; cloud tests prove IAM boundary | `tests/security/iam`, `packages/storage` |
| **DEC-004** | Administrative dashboard built with Next.js 16 (App Router, Tailwind 4, shadcn/ui) as an isolated, secret-free container | **CHANGED** (Spec said React + Vite SPA) | Provides server-rendered shells and streaming UI for large logs, while strictly isolating UI from database and storage secrets. Route Handlers only forward JWT. | React + Vite static SPA; monolithic server serving UI | Next.js 16 Documentation; Tailwind CSS v4 docs | Clean Z8 separation; frontend holds zero secrets | `apps/dashboard`, `services/api` |
| **DEC-005** | PostgreSQL 18 (`postgres:18-alpine`) as the primary relational database | **CHANGED** (Spec said 16; brief said 16; see OPEN-1) | Native `uuidv7()` provides time-ordered, index-friendly UUIDs; supported to Nov 2030; optimized row locking for `SKIP LOCKED`. | PostgreSQL 16 (supported to 2028); PostgreSQL 17 | PostgreSQL 18 Release Notes | Eliminates external UUIDv7 libraries; index efficiency | Database migrations, Compose, Kysely schema |
| **DEC-006** | Observability metrics library is `@prometheus-io/client 0.16.x` | **CHANGED** (Spec referenced prom-client) | `prom-client 15.1.3` is officially marked deprecated on npm in favor of `@prometheus-io/client`. | Deprecated `prom-client`; OpenTelemetry SDK | npm registry deprecation notice for `prom-client` | Clean Prometheus integration without deprecation warnings | `packages/shared/metrics`, observability |
| **DEC-007** | TypeScript pinned to `6.0.3`; ESLint 10 flat config; `typescript-eslint 8.70.1` | **CHANGED** (Spec said TypeScript 5) | TypeScript 7 currently lacks programmatic AST APIs required by `typescript-eslint`; ESLint 9 reached EOL August 2026. | TypeScript 7.0; ESLint 9 legacy config | TS 7.0 announcement; `typescript-eslint` peer dependencies | Type-safety, architectural boundary linting via `eslint-plugin-boundaries` | All packages and services |
| **DEC-008** | Node.js 24 LTS (`node:24-alpine`) and pnpm workspaces | **APPROVED** | Active LTS supported through April 2028; all selected libraries require Node $\ge 22$; Corepack/pnpm 12 deterministic locking. | Node.js 22 LTS; Node.js 26 Current | Node.js official release schedule | Fast, reproducible monorepo builds | Root configuration, Dockerfiles, CI |
| **DEC-009** | Fastify 5.12 with Zod 4.6 type provider; streaming `application/octet-stream` upload; no multipart parser | **APPROVED** | Eliminates multipart CVEs, ReDoS, and disk buffering; streams directly to S3 with in-memory tee SHA-256 and byte-budget ceilings. | Express + Multer; Busboy; Fastify-multipart | OWASP File Upload Guidance; Multer CVE history | Zero disk consumption on API nodes; flat memory RSS | `services/api`, `packages/policy-engine` |
| **DEC-010** | ClamAV 1.4.6 LTS with in-house 60-line TypeScript INSTREAM client | **APPROVED** | ClamAV 1.4 is the official LTS line (to Aug 2027); `clamscan` npm package is abandoned (2024); official clamd protocol is concise and robust. | ClamAV 1.5 (regular short-lived release); `clamscan` npm | ClamAV EOL Policy; official clamd protocol reference | Robust INSTREAM scanning with zero third-party wrapper dependencies | `services/scanner`, Docker Compose |
| **DEC-011** | YARA-X 1.20.0 CLI subprocess integration; NDJSON stdout parsing | **APPROVED** | Subprocess invocation ensures worker process safety; NDJSON parsing provides complete rule metadata and match offsets; exit code 0/1 ignored for matches. | `@virustotal/yara-x` WASM (no production readiness guarantee); classic YARA v4 | YARA-X CLI documentation and CLI source | High-performance compiled Rust rule evaluation | `services/scanner`, rule repository |
| **DEC-012** | Application-level envelope encryption (AES-256-GCM, `SUG1` format); per-file DEK; KEK via Docker Secret / SSM | **APPROVED** | NIST SP 800-38D compliant; ensures ciphertext at rest across all storage providers; protects against cloud provider IAM leaks. | SSE-S3 only; KMS-only envelope | NIST SP 800-38D; RFC 3394 AES Key Wrap | True client-side confidentiality; KEK never exposed to GCS | `packages/crypto`, `services/promotion` |
| **DEC-013** | Infrastructure as Code using Terraform 1.16 / OpenTofu; IAM access keys bootstrapped via AWS CLI | **APPROVED** | Prevents plaintext IAM access keys and SSM SecureString values from being recorded in Terraform state files. | Storing keys in TF state with PGP; CloudFormation | AWS Provider v6 Documentation; Terraform best practices | State file contains zero plaintext credentials | `infrastructure/aws` |
| **DEC-014** | GCP project created manually once (`gcloud projects create`) and referenced by Terraform | **APPROVED** | Google Terraform provider requires Organization resource to create parentless projects; personal billing accounts lack Organization root. | Automating project creation in TF | Google Terraform Provider documentation | Reliable deployment on individual/academic billing accounts | `infrastructure/gcp` |
| **DEC-015** | Workload Identity Federation (WIF) from AWS role to GCP service account; zero static JSON keys | **APPROVED** | Google Auth library exchanges AWS STS temporary session credentials for short-lived OAuth tokens; eliminates long-lived service account keys. | Static service account JSON keys; long-lived HMAC keys | Google Cloud AIP-4117 (WIF for AWS) | Zero long-lived cross-cloud credentials | `services/replication`, `infrastructure/gcp` |
| **DEC-016** | Explicit `DenyOverwrite` bucket policy (`s3:if-none-match`); `CopyObject` strictly forbidden | **APPROVED** | Enforces immutability at storage layer; AWS documents that conditional write bucket policies break server-side `CopyObject`. | Relying on code checks alone; using S3 `CopyObject` | AWS S3 Conditional Writes Documentation | Storage-enforced TOCTOU protection; promoter streams through itself | Bucket policies, `services/promotion` |
| **DEC-017** | AWS CloudWatch billing alarm on `EstimatedCharges` via `us-east-1` provider alias | **APPROVED** | Metric `EstimatedCharges` exists strictly in `us-east-1` and requires console activation; protects student account from accidental charges. | AWS Budgets alone | AWS Billing and Cost Management Guide | Immediate alert if spend exceeds $0.01 / $5.00 | `infrastructure/aws/budgets.tf` |
| **DEC-018** | Plain HTTP inside Docker network; optional Caddy reverse proxy for TLS profile | **APPROVED** | Avoids installing local root CAs into developer trust stores for development; cloud SDKs use TLS automatically against AWS/GCP. | Forcing self-signed TLS inside all dev containers | Caddy Docker Documentation | Simpler local debugging; zero certificate friction in CI | Docker Compose, Caddyfile |
| **DEC-019** | Local GCS emulation via `fsouza/fake-gcs-server:1.56.1` using JSON API exclusively | **APPROVED** | JSON API properly honors `ifGenerationMatch: 0`, generations, and declared CRC32C validation; XML API does not. | Google storage-testbench | `fake-gcs-server` source code (`upload.go`) | Faithful local replication testing before GCP deployment | Docker Compose, `packages/storage` |
| **DEC-020** | User password hashing using Argon2id (`argon2 0.45` Node-API) | **APPROVED** | Memory-hard password hashing recommended by OWASP; prebuilt Node-API binaries for Node 24. | bcrypt; PBKDF2; scrypt | OWASP Password Storage Cheat Sheet | High resistance to GPU-assisted offline cracking | `services/api`, auth modules |
| **DEC-021** | Archive inspection via `yauzl 3.4` with two-phase resource budgets | **APPROVED** | Lazy central-directory streaming without extraction; prevents Fifield-style non-recursive and recursive zip bombs. | `@zip.js/zip.js`; `node-stream-zip`; `adm-zip` | Fifield (2019) WOOT Best Paper; `yauzl` npm docs | Complete protection against archive-based DoS | `packages/security-engine/archive` |
| **DEC-022** | Test automation via Vitest 5, k6 2.2 for performance, ESLint 10 | **APPROVED** | Modern, native ESM test runner with `clearMocks: true` by default; k6 provides reproducible load and latency testing. | Jest; Mocha; Artillery | Vitest 5 release notes; k6 documentation | High-speed unit and integration test cycles | `tests/`, root config |

---

## 2. Open Decisions (Status & Tracking)

### OPEN-1: PostgreSQL Version Selection (18 vs 16)
- **Question**: Revert to PostgreSQL 16 (as stated in initial brief) or keep PostgreSQL 18 (DEC-005)?
- **Current Recommended Answer**: **PostgreSQL 18** (`postgres:18-alpine`).
- **Rationale**: PostgreSQL 18 provides native `uuidv7()` for time-ordered primary keys, improved concurrency in `SKIP LOCKED`, and support through November 2030. Reverting to PG 16 would require an application-level UUIDv7 generator or random UUIDv4 which fragments indexes.
- **Status**: **OPEN** (Default: 18).

### OPEN-2: Local S3 Emulator (LocalStack Community vs SeaweedFS)
- **Question**: Should local S3 emulation use LocalStack Community or SeaweedFS?
- **Current Answer**: **LocalStack Community** (`localstack/localstack:2026.08.3`) is the primary choice.
- **Technical Gate**: The Phase 2 storage assumption spike (`packages/storage/test/assumptions.test.ts`) tests:
  1. `PutObject` returns valid `VersionId`.
  2. `PutObject` with `If-None-Match: *` returns HTTP 412 on overwrite attempt.
  3. `GetObject` by older `VersionId` returns original bytes.
  4. Checksum `SHA256` round-trips correctly.
- **Fallback**: If LocalStack fails any assertion, the project pivots to **SeaweedFS 4.45** in Phase 2.
- **Status**: **OPEN** (Decided by P2 Spike).

### OPEN-3: Missing Source Documents Reconciliation
- **Question**: Reconcile potential conflicts from missing source documents (`Secure_File_Upload_Gateway_Full_Literature_Survey.docx`, `secure-upload-gateway-stage1.md`).
- **Current State**: **RESOLVED**. `secure-upload-gateway-literature-survey.docx` is present in the repository under `DOCUMENTS/` and was analyzed in depth. All literature findings (Dubin CDR, Fifield zip bombs, Jana & Shmatikov evasion, Crosby & Wallach audit integrity) match and support the frozen architecture.
- **Status**: **RESOLVED**.

### OPEN-4: Development Environment Baseline
- **Question**: Confirm host development environment assumptions.
- **Current State**: **RESOLVED / VERIFIED**. Verified on host: Windows 11 with Docker Desktop (`29.6.1`), WSL 2 kernel (`6.18.33.2-microsoft-standard-WSL2`), Node.js `v24.14.0`, and Git `2.53.0`.
- **Status**: **RESOLVED**.
