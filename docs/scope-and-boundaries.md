# Project Scope, Boundaries, and MVP Inclusions

## 1. Project Objective & Core MVP Scope
The primary objective of the Secure Upload Gateway (SUG) is to implement a research-backed, quarantine-first security gateway that halts malicious, malformed, or policy-violating file uploads before they reach trusted cloud object storage, while preventing Time-of-Check-to-Time-of-Use (TOCTOU) file substitution attacks.

### Mandatory MVP Inclusions (Tracks 1–5, Phases P0–P39)
- **Monorepo Architecture**: pnpm workspaces with TypeScript 6.0.3, ESLint 10, and strict service boundaries.
- **Local Emulation**: Docker Compose with PostgreSQL 18, LocalStack Community (`2026.08.3`) for S3, `fake-gcs-server` for GCS, and ClamAV LTS (`1.4.6`).
- **Relational Schema & Job Queue**: PostgreSQL 18 with native `uuidv7()`, append-only audit hash chain, and `FOR UPDATE SKIP LOCKED` asynchronous job queue.
- **Zero-Buffering Ingestion**: Fastify 5 API with raw `application/octet-stream` streaming, in-memory SHA-256 tee computation, and strict byte-budget cutoff.
- **Deterministic Validation**: Filename safety, extension allowlists/denylists, MIME type verification, and magic-byte detection (`file-type` + `libmagic`).
- **Multi-Engine Inspection**: ClamAV INSTREAM scanning, YARA-X 1.20 CLI subprocess analysis, non-recursive and recursive zip-bomb defenses (`yauzl 3.4`), and format checks (PDF active content, OOXML macros, basic polyglots).
- **Deterministic Decision Engine**: Pure mathematical evaluation (Rules R1–R7) with strict fail-closed precedence.
- **Cryptographic Security**: Application-level envelope encryption (`SUG1` envelope, AES-256-GCM, per-file DEK, master KEK) with verify-before-release decryption.
- **Anti-TOCTOU Promotion**: Exact-artifact binding to `(bucket, key, version_id, sha256, size)` with mandatory re-fetch and re-hash.
- **Cloud Infrastructure**: AWS S3 (quarantine, clean, audit) and GCP GCS replica provisioned via Terraform, with cross-cloud Workload Identity Federation (WIF).
- **Observability**: Prometheus metrics (`@prometheus-io/client`) and Grafana alert dashboards.
- **Administrative Dashboard**: Isolated Next.js 16 web application communicating strictly via authenticated Fastify API endpoints.
- **Empirical Research Artifact**: Reproducible TOCTOU attack harness (Phase 32) and experimental validation suite (Phase 38).

---

## 2. Explicit Out-of-Scope List (Do Not Build for MVP)
To avoid scope creep and maintain strict academic and engineering rigor, the following technologies and features are **EXPLICITLY EXCLUDED** from the MVP:

1. **Kubernetes (K8s / EKS / GKE)**:
   - *Reason*: Excessive operational overhead for a student-team deployment. Docker Compose locally and single-instance/Fargate patterns in cloud are fully sufficient.
2. **Apache Kafka / RabbitMQ / Redis (BullMQ)**:
   - *Reason*: PostgreSQL `SKIP LOCKED` provides atomic transactions spanning file metadata and queue state without requiring external broker infrastructure.
3. **Machine Learning / Deep Learning Malware Detection**:
   - *Reason*: Literature surveys confirm that ML malware models suffer from adversarial evasion, lack explainability, and do not outperform deterministic rules for single-file triage (Literature Survey Section 3.2).
4. **Blockchain-Based Audit Logging**:
   - *Reason*: Literature demonstrates that blockchain consensus introduces latency and infrastructure costs unjustified for single-organization threat models. Relational append-only tables with cryptographic hash chains and S3 Object Lock compliance mode provide mathematically equivalent tamper evidence (Literature Survey Section 3.5).
5. **Dynamic Sandbox / Detonation Chamber (e.g., Cuckoo Sandbox, CAPE)**:
   - *Reason*: Virtual machine orchestration and execution latency (minutes per file) directly violate the gateway's low-latency streaming requirements.
6. **Generic Content Disarm and Reconstruction (CDR)**:
   - *Reason*: Effective CDR requires custom, format-by-format reconstruction parsers (Dubin group methodology). Deferred to post-MVP research extensions.
7. **OAuth 2.0 / OIDC / Third-Party Social Logins**:
   - *Reason*: Ephemeral EdDSA upload tokens and internal Argon2id user authentication provide complete, secure RBAC without third-party identity provider complexity.
8. **Multipart / Chunked Resumable Uploads (e.g., tus protocol, S3 Multipart)**:
   - *Reason*: Multipart parsers introduce high CVE risk (CWE-434). Single-stream octet-stream satisfies the gateway's $\le 50\text{ MB}$ payload requirement.
9. **Additional Cloud Providers (Azure Blob, Cloudflare R2, Wasabi)**:
   - *Reason*: AWS S3 (primary) and Google Cloud Storage (secondary) fully demonstrate multi-cloud resilience and Workload Identity Federation.
10. **Complex Distributed Tracing / APM (OpenTelemetry Collector, Jaeger, Datadog)**:
    - *Reason*: Standard Pino structured JSON logging and Prometheus metric endpoints satisfy all observability requirements.
11. **Commercial Security Appliances (e.g., OPSWAT MetaDefender, Palo Alto WildFire)**:
    - *Reason*: The project focuses on open-source, reproducible, self-hosted security primitives.

---

## 3. Potential Future Work (Post-v1.0 Extensions)
Features that may be explored in academic papers or future releases after v1.0.0 is frozen:
- Format-specific CDR for PDF and PNG files using pure TypeScript rebuilders.
- Polyglot detection using compiled eBPF file format hooks.
- S3 Object Lambda integration for on-the-fly decryption streaming.
- Hardware Security Module (HSM) / AWS CloudHSM integration for root KEK protection.
