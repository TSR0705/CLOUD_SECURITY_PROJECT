# ADR 0008: Streaming Ingestion Model, Zero-Buffering, and No-Multipart Policy

## Status
APPROVED (DEC-009, DEC-016)

## Context
Handling file uploads in web applications is one of the most vulnerable operations in software engineering (CWE-434). Traditional patterns rely on `multipart/form-data` parsers (e.g., Multer, Busboy, Formidable). Multipart parsers have a continuous history of high-severity CVEs, including:
- ReDoS via crafted boundary strings.
- Arbitrary file writes via unvalidated filenames in header parts.
- Disk exhaustion by buffering large chunks to `/tmp`.
- Memory starvation and garbage collection stalls under high concurrent upload volume.
- Race conditions between temporary file creation and validation.

Furthermore, direct presigned uploads to cloud storage bypass application-level byte counting and rate enforcement, allowing attackers to upload excessively large payloads before backends can react.

## Decision
We mandate a **strict, streaming `application/octet-stream` ingestion pipeline** with zero disk buffering in `services/api`:

1. **Fastify 5 Framework**:
   - `services/api` uses **Fastify 5.12**, `@fastify/type-provider-zod 1.0`, and **Zod 4.6** for schema validation.
2. **Elimination of Multipart Parsers**:
   - `multipart/form-data` parsing is explicitly **BANNED** in the API service. No multipart library will be installed or imported.
3. **Two-Phase Upload Protocol**:
   - **Phase A (Session Creation — `POST /upload/session`)**: The client provides file metadata (`filename`, `declared_size`, `declared_mime`, `policy_id`). The API verifies client API keys/JWT, runs precheck validation rules, creates an `upload_sessions` row, and issues a short-lived, single-use EdDSA signed upload token (`aud=sug-upload`, `jti`, `sid`, 10-minute expiry).
   - **Phase B (Raw Streaming Ingestion — `PUT /upload/:id`)**: The client streams raw bytes with `Content-Type: application/octet-stream` and `Authorization: Bearer <upload_token>`.
4. **Streaming Resource Limits and Tee Hashing**:
   - The incoming HTTP request stream is piped directly into the S3 quarantine storage provider.
   - An in-memory pass-through stream (Tee) calculates the incremental **SHA-256 hash** and monitors the byte count.
   - **Hard Cutoff**: If the byte stream exceeds `min(declared_size, policy.max_file_size)`, the stream is immediately destroyed, the socket closed, the partial upload aborted, and HTTP 413 returned. Memory consumption (RSS) remains completely flat.
   - 30-second socket idle timeout prevents Slowloris-style upload starvation attacks.
5. **Atomic Session Claim**:
   - A single-use upload session token can only be claimed once. Concurrent upload attempts with the same token fail atomically via an optimistic lock in PostgreSQL (`UPDATE upload_sessions SET status = 'UPLOADING' WHERE id = :id AND status = 'INITIALIZED'`).
6. **Immutable Quarantine Key Scheme**:
   - Quarantine keys follow the strict pattern `incoming/<app_id>/<upload_id>`. Filenames supplied by clients are NEVER used in storage keys.
   - Every `PutObject` executes with `If-None-Match: *` and `ChecksumAlgorithm: 'SHA256'`. S3 bucket policies enforce `DenyOverwrite` (DEC-016).

## Alternatives Considered
- **Standard Multipart/Form-Data**: Rejected due to high historical CVE volume, parser complexity, and risk of unbuffered temporary file creation.
- **Direct-to-S3 Presigned PUT**: Rejected because the storage provider cannot enforce fine-grained policy validation, stream-level byte ceilings, or atomic single-use session claims before storage consumption.

## Security Impact
- Eliminates file upload buffer overflow, disk exhaustion on edge nodes, and path traversal via filename manipulation.
- Guarantees that every object in quarantine is tagged with a system-generated immutable key and authenticated upload session ID.

## Cost Impact
Zero disk usage on the API container. Minimal RAM requirements allow the API service to operate efficiently under container memory limits (512MB limit).

## Research Impact
Validates Hypothesis H5 (low-latency streaming upload with minimal overhead) and directly feeds the Artifact Identity model (Phase 12).

## Consequences
- Clients must upload files in two distinct API calls (session creation $\to$ streaming PUT).
- File upload clients must support raw binary streaming.

## Evidence & Source References
- Build Plan: Section 1.2 (DEC-009, DEC-016), Section 2.2 (P8, P9, P10 contracts).
- OWASP File Upload Security Guidelines.
- MITRE CWE-434, CWE-400.
