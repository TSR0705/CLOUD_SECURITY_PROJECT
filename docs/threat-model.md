# Threat Model: Secure Upload Gateway (SUG)

## 1. System Purpose
The Secure Upload Gateway (SUG) is a Zero Trust, quarantine-first cloud security layer designed to ingest untrusted files from external users and client applications, perform multi-layered static and signature analysis, enforce deterministic security policies, and safely promote cryptographically verified, encrypted artifacts to trusted cloud object storage across AWS and Google Cloud Platform.

---

## 2. Protected Assets
The primary assets protected by the gateway are:
1. **Trusted Clean Storage (`sug-clean-*`)**: Production object storage housing sanitized enterprise and application files. Must never receive unscanned, unapproved, or modified payloads.
2. **Replicated Storage (`sug-replica-*`)**: GCS cross-cloud backup bucket. Must maintain exact ciphertext parity with clean storage.
3. **Database & Evidence Store (PostgreSQL 18)**: File records, scanning findings, deterministic decision audit trails, and job queues.
4. **Cryptographic Key Material (KEK / DEK)**: Master Key Encryption Key and ephemeral Data Encryption Keys.
5. **Audit Event Log (`audit_events`)**: Cryptographic hash chain recording all system transitions; must remain strictly tamper-evident and non-repudiable.
6. **Underlying Compute and Host Runtimes**: Node.js microservices, container daemon, and host OS.

---

## 3. Threat Actors & Personas
- **External Attacker (Unauthenticated)**: Attempts unauthenticated access, network denial-of-service, slowloris upload starvation, or API reconnaissance.
- **Malicious Authenticated User**: Holds valid API keys or dashboard credentials. Attempts to upload web shells, ransomware, polyglot payloads, zip bombs, or exploit race conditions to overwrite scanned files.
- **Compromised Ingestion Node (Z2)**: An attacker who achieves code execution in `services/api`.
- **Compromised Scanner Worker (Z4)**: An attacker who achieves code execution in `services/scanner` via memory corruption or parser vulnerabilities during file parsing (e.g., ClamAV, `libmagic`, `sharp`, `qpdf`).
- **Malicious Internal Administrator / Rogue Auditor**: An insider with database credentials attempting to tamper with historical audit records or bypass quarantine.
- **Compromised Secondary Cloud Provider (GCP)**: An attacker with administrative control over the replica cloud project attempting to read enterprise data.

---

## 4. Trust Zones & Boundaries
The gateway is structured into eight distinct Trust Zones:

| Zone | Component | Trust Level | Boundaries Crossed | Inbound / Outbound Controls |
| :--- | :--- | :--- | :--- | :--- |
| **Z1** | Client Applications | Untrusted | Boundary B1 $\to$ Z2 | HTTPS, API Key / JWT, Rate Limiting, CORS |
| **Z2** | Ingest API (`services/api`) | Semi-Trusted | Boundary B2 $\to$ Z3, B3 $\to$ DB | Streaming byte counter, no multipart, `If-None-Match: *` |
| **Z3** | Quarantine Storage (`sug-quarantine-*`) | Untrusted Content | Boundary B4 $\to$ Z4, B5 $\to$ Z5 | Bucket Versioning, 7-day TTL, DenyOverwrite policy |
| **Z4** | Scanner Worker (`services/scanner`) | High Risk (Complex Parsers) | Boundary B6 $\to$ DB | Read-only root filesystem, dropped caps, no public egress |
| **Z5** | Promotion Worker (`services/promotion`) | Trusted Mediator | Boundary B7 $\to$ Z6, B8 $\to$ DB | Version-bound re-fetch, SHA-256 verification, envelope encryption |
| **Z6** | Clean Storage (`sug-clean-*`) | Highly Trusted | Boundary B9 $\to$ Z7 | AES-256-GCM ciphertext only, write-once policy |
| **Z7** | GCS Replica (`sug-replica-*`) | Disaster Recovery | Boundary B10 (Cloud to Cloud) | Workload Identity Federation, `ifGenerationMatch: 0` |
| **Z8** | Dashboard (`apps/dashboard`) | Management & Audit | Boundary B11 $\to$ Z2 | Fastify API only, JWT/RBAC, no direct DB/cloud access |

---

## 5. Data Flow Diagram (DFD)
```
[Client / Z1] 
     │ 1. POST /upload/session (metadata, policy_id)
     ▼
[services/api / Z2] ──(2. Claim session & issue upload token)──► [PostgreSQL / DB]
     │
     │ 3. PUT /upload/:id (Streaming application/octet-stream)
     ├────────────────────────────────────────┐
     │ Tee stream                             │ Tee hash & size check
     ▼                                        ▼
[Quarantine S3 / Z3] (versioned)        [PostgreSQL / DB] (Insert files, file_versions, scan_jobs)
     ▲
     │ 4. GetObject by VersionId
     ▼
[services/scanner / Z4] (Network Isolated)
  ├── ClamAV 1.4 LTS (INSTREAM)
  ├── YARA-X 1.20 CLI
  ├── Archive & Zip-Bomb Audit (yauzl 3.4)
  └── Format Validators (PDF, OOXML, Image, Polyglot)
     │ 
     ▼ 5. Write scan_results & trigger decide()
[Decision Engine / Z4-Z5] ──(6. Write security_decisions: ALLOW/BLOCK/QUARANTINE)──► [PostgreSQL / DB]
     │
     ▼ 7. If un-superseded ALLOW, claim promotion_job
[services/promotion / Z5]
     │ 8. Re-fetch quarantine object by exact bound_storage_version_id
     │ 9. Re-verify SHA-256 and byte length (TOCTOU protection)
     │ 10. Envelope Encrypt (AES-256-GCM, SUG1 envelope)
     │
     ▼ 11. PutObject If-None-Match: *
[Clean S3 / Z6] ──(12. Insert cloud_objects & audit_events)──► [PostgreSQL / DB]
     │
     ▼ 13. Claim replication_job
[services/replication / Z7]
     │ 14. Stream ciphertext via Workload Identity Federation (WIF)
     ▼
[Google Cloud Storage / Z7] (ifGenerationMatch: 0)
```

---

## 6. Privileged Identities & Least Privilege Mapping
1. **`sug_api` (DB) / `UPLOAD_ROLE` (Cloud)**:
   - Holds credentials ONLY to write `incoming/*` in quarantine storage.
   - CANNOT write to clean storage (`sug-clean-*`).
   - CANNOT insert into `security_decisions` or `cloud_objects`.
2. **`sug_scanner` (DB) / `SCANNER_ROLE` (Cloud)**:
   - Holds credentials ONLY to read `sug-quarantine-*` by version ID.
   - CANNOT write to quarantine or clean storage.
   - CANNOT insert into `security_decisions`.
3. **`sug_promotion` (DB) / `PROMOTION_ROLE` (Cloud)**:
   - The SOLE identity with `s3:PutObject` permission on `sug-clean-*`.
   - Accesses SSM Parameter Store for master KEK.
   - Reads only verified `ALLOW` decisions from PostgreSQL.
4. **`sug_replication` (DB) / `REPLICATION_ROLE` (Cloud)**:
   - Reads ciphertext from clean S3.
   - Federated into GCP via WIF as `roles/storage.objectCreator` on `sug-replica-*`.

---

## 7. STRIDE Threat Analysis & Mitigations

### S — Spoofing (Identity & Authenticity)
- **Threat**: Attacker spoofs client identity or reuses an expired upload token.
- **Mitigation**: Ephemeral EdDSA signed tokens (`aud=sug-upload`, `jti`, 10m expiry). Single-use atomic database session claim (`UPDATE ... WHERE status = 'INITIALIZED'`) prevents token replay.
- **Threat**: Attacker creates fake scan results.
- **Mitigation**: `services/scanner` authenticates via dedicated database role `sug_scanner`. API nodes have no grant to insert `scan_results`.

### T — Tampering (Data Integrity)
- **Threat (TOCTOU)**: Attacker uploads an innocent file, waits for the scan to pass, and overwrites the quarantine object with malware before promotion.
- **Mitigation**: Promotions are bound to `(storage_version_id, sha256, size)`. Promoter re-reads the exact version ID, re-hashes bytes, and aborts with `BLOCK / HASH_MISMATCH` if content changed. S3 bucket policy enforces `DenyOverwrite`.
- **Threat**: Attacker or corrupt DBA modifies audit log history.
- **Mitigation**: Cryptographic hash chain (`event_hash = SHA256(seq || prev_hash || type || payload)`). PostgreSQL trigger `forbid_mutation()` blocks `UPDATE` and `DELETE`. Periodic Ed25519-signed checkpoints committed to S3 Object Lock (Compliance mode) and GCS.

### R — Repudiation
- **Threat**: User claims they did not upload a malicious file, or administrator denies approving a quarantined file.
- **Mitigation**: All actions generate an immutable, hash-chained `audit_events` row linking client API key, user ID, IP hash, file version, artifact SHA-256, and timestamp.

### I — Information Disclosure (Confidentiality)
- **Threat**: Unauthorized actor accesses clean files directly in S3 or via secondary cloud replica.
- **Mitigation**: All files at rest in clean S3 and GCS replicas are stored exclusively as `SUG1` AES-256-GCM ciphertext. KEK is never stored in GCS or the dashboard. Downloads require authenticated gateway verification (`verify-before-release`).

### D — Denial of Service (Resource Exhaustion)
- **Threat**: Attacker uploads a multi-gigabyte file or Fifield non-recursive zip bomb (28M:1 expansion).
- **Mitigation**: Streaming upload destroys socket if byte count exceeds declared limit or policy max. Archive validator enforces lazy central-directory inspection before decompression, capping entries (< 2,000), expansion ratio (< 100:1), and uncompressed size (< 100MB) inside a 256MB memory-capped worker thread.
- **Threat**: Slowloris upload attacks.
- **Mitigation**: Fastify 30-second socket idle timeout and `@fastify/rate-limit`.

### E — Elevation of Privilege
- **Threat**: Attacker gains Remote Code Execution (RCE) in `services/scanner` via a ClamAV or libmagic vulnerability.
- **Mitigation**: Scanner container runs with read-only root filesystem, dropped Linux capabilities (`cap_drop: ALL`), non-root user, and internal network isolation (no internet egress). The scanner's database role (`sug_scanner`) and cloud role (`SCANNER_ROLE`) lack permissions to write clean storage or approve files.

---

## 8. Residual Risks & Accepted Constraints
1. **Zero-Day Signature Evasion**: ClamAV signature scanning cannot detect unknown zero-day malware.
   * *Status*: Accepted constraint of static analysis. Mitigated by layered YARA-X rules, deterministic format validations, and strict extension/magic consistency.
2. **LocalStack IAM Emulation Gap**: LocalStack Community does not enforce IAM policies locally.
   * *Status*: Mitigated by strict application credential separation locally and running full negative IAM blast-radius suites against AWS S3 in Phase 29.
3. **Advanced Polyglot Misses**: Highly obscure polyglots (e.g., polyglot files valid across 3+ rare formats) may not be detected by standard heuristics.
   * *Status*: Documented limitation (Literature Survey Section 6.2).

---

## 9. Out-of-Scope Threats
- Physical access or hypervisor compromise of cloud infrastructure (AWS/GCP data centers).
- End-user endpoint compromise (malware already running on client workstations).
- Compromise of official operating system package repositories or Node.js core binaries.
- Real-time dynamic detonation analysis / virtual machine sandboxing (deferred past MVP).
