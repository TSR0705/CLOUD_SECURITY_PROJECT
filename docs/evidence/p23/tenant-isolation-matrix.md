# Phase P23 Deliverable: Multi-Tenant Authorization & Isolation Matrix

This matrix documents the authorization enforcement and tenant-isolation boundaries across all public and internal API endpoints in the Secure Upload Gateway (SUG).

## Boundary Enforcement Model

The Gateway implements multi-tenant cryptographic and relational isolation:

1. **Application Scoping**: Every resource (`upload_sessions`, `files`, `file_versions`, `scan_jobs`, `scan_results`, `security_decisions`, `audit_events`) is bound directly to an `application_id`.
2. **API Key Authentication**: Ingestion and client retrieval use scoped API keys hashed with argon2id and peppered. Every authenticated request resolves the caller's `application_id`.
3. **Fail-Closed Relational Guards**: SQL queries enforce `WHERE application_id = $auth_app_id` or join across parent entities. Cross-tenant access attempts return HTTP 403 Forbidden or HTTP 404 Not Found without leaking object existence or metadata.
4. **Role-Based Access Control (RBAC)**: Dashboard, security analyst, and admin endpoints require signed JWT bearer tokens with cryptographic role verification (`analyst`, `admin`).

---

## Endpoint Permission Matrix

| Endpoint Route                          | HTTP Method | Caller Identity        | Target Resource Owner | Expected Status    | Security Behavior & Leak Prevention                                                    |
| --------------------------------------- | ----------- | ---------------------- | --------------------- | ------------------ | -------------------------------------------------------------------------------------- |
| `/api/v1/upload-sessions`               | `POST`      | Tenant A (`apiKeyA`)   | Tenant A              | `201 Created`      | Upload session created with pinned JWT token and policy snapshot                       |
| `/api/v1/upload-sessions`               | `POST`      | Tenant B (`apiKeyB`)   | Tenant B              | `201 Created`      | Upload session created under Tenant B application ID                                   |
| `/api/v1/upload/:id`                    | `PUT`       | Tenant A (`tokenA`)    | Session A             | `200 OK`           | Streaming ingest with SHA-256 verification and quarantine storage                      |
| `/api/v1/upload/:id`                    | `PUT`       | Tenant B (`tokenB`)    | Session A             | `401 / 403`        | Pinned session token mismatch; upload rejected; storage untouched                      |
| `/api/v1/files/:id`                     | `GET`       | Tenant A (`apiKeyA`)   | Tenant A              | `200 OK`           | Returns file metadata (filename, size, status, MIME type)                              |
| `/api/v1/files/:id`                     | `GET`       | Tenant B (`apiKeyB`)   | Tenant A              | `403 / 404`        | Cross-tenant metadata blocked; returns RFC 7807 problem details; no metadata leaked    |
| `/api/v1/files/:id/download`            | `GET`       | Tenant A (`apiKeyA`)   | Tenant A              | `200 OK`           | Streams decrypted clean payload with strict CSP and download security headers          |
| `/api/v1/files/:id/download`            | `GET`       | Tenant B (`apiKeyB`)   | Tenant A              | `403 / 404`        | Cross-tenant download blocked; zero bytes transmitted; access logged to audit trail    |
| `/api/v1/files/:id`                     | `DELETE`    | Tenant A (`apiKeyA`)   | Tenant A              | `204 No Content`   | Soft-deletes file; records `file.deleted` audit event                                  |
| `/api/v1/files/:id`                     | `DELETE`    | Tenant B (`apiKeyB`)   | Tenant A              | `403 / 404`        | Unauthorized deletion rejected; file status unchanged                                  |
| `/api/v1/scans/:jobId`                  | `GET`       | Tenant A (`apiKeyA`)   | Tenant A              | `200 OK`           | Returns multi-engine scan findings and aggregate outcome                               |
| `/api/v1/scans/:jobId`                  | `GET`       | Tenant B (`apiKeyB`)   | Tenant A              | `403 / 404`        | Cross-tenant scan inspection rejected; findings shielded                               |
| `/api/v1/security-decisions/:id/review` | `POST`      | Tenant A (`apiKeyA`)   | Tenant A              | `401 Unauthorized` | API key lacks human analyst credentials; override rejected                             |
| `/api/v1/security-decisions/:id/review` | `POST`      | Analyst (`jwtAnalyst`) | Any Tenant            | `200 OK`           | Authorized security review; changes state to ALLOW or BLOCK; emits `decision.reviewed` |
| `/api/v1/audit/events`                  | `GET`       | Tenant A (`apiKeyA`)   | System / Multi        | `401 Unauthorized` | Tenant API key cannot query system audit log                                           |
| `/api/v1/audit/events`                  | `GET`       | Admin (`jwtAdmin`)     | System / Multi        | `200 OK`           | Admin inspects tamper-evident SHA-256 hash-chained audit log                           |

---

## Invariant Guarantees

1. **Zero Data Leakage**: No tenant can infer the existence, hash, filename, size, or scan results of another tenant's files.
2. **Cryptographic Storage Isolation**: Quarantine objects use envelope encryption (AES-256-GCM) with AAD binding `application_id`, `file_id`, and `version_no`. Even direct storage access cannot decrypt across boundaries.
3. **Audit Completeness**: All access attempts, including rejected cross-tenant requests, produce immutable, forward-secure audit events.
