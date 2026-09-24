# Research Hypotheses & Evaluation Framework (H1–H5)

This document formalizes the five core scientific and engineering hypotheses (H1–H5) evaluated by the Secure Upload Gateway project. These hypotheses will be tested using reproducible experiment scripts, formal statistical metrics, and standardized attack datasets in Phases 23, 29, 32, 35, 36, and 38.

> [!IMPORTANT]
> This document records research targets, testbed designs, and planned experiments. In accordance with scientific integrity, no experimental results are fabricated. All metrics will be populated during experimental execution.

---

## Hypothesis H1: Multi-Layered Validation Detection Efficacy

### 1. Formal Hypothesis
A multi-layered validation pipeline (combining strict MIME/magic-byte consistency, ClamAV antivirus signatures, YARA-X heuristic rules, structural archive verification, and active format analysis) detects a statistically significantly higher percentage of malicious and malformed upload attack classes than traditional single-layer extension or MIME-only checks.

### 2. Variables
- **Independent Variable**: Validation pipeline configuration:
  - Configuration $C_0$: Extension check only (naive baseline).
  - Configuration $C_1$: Extension + client-declared MIME check.
  - Configuration $C_2$: Magic-byte detection (`file-type` + `libmagic`).
  - Configuration $C_3$: Full SUG Multi-Layered Pipeline (MIME/Magic + ClamAV + YARA-X + Archive Audit + Format Checks).
- **Dependent Variable**: Detection Rate (True Positive Rate / Recall) across standardized attack classes:
  $$\text{Recall} = \frac{\text{True Positives (Correct Blocks)}}{\text{Total Malicious Samples}}$$
  and False Positive Rate (FPR) across benign sample sets:
  $$\text{FPR} = \frac{\text{False Positives (Incorrect Blocks)}}{\text{Total Benign Samples}}$$

### 3. Baseline & Comparison
Baseline $C_0$ (filename extension validation against an allowlist) and $C_1$ (client MIME header matching).

### 4. Evaluation Corpus
A standardized corpus of 80 distinct test files generated in Phase 35 (`tests/fixtures/generate.ts`), mapped across:
- EICAR runtime-assembled test virus strings.
- Non-recursive zip bombs (Fifield 2019 WOOT construction) and recursive bombs.
- Active-content PDFs containing `/JavaScript` and `/Launch` actions.
- Macro-enabled OOXML files (`vbaProject.bin`).
- Mitra-generated polyglot files (e.g., JPEG/ZIP, PDF/ZIP, GIF/JS).
- Extension-spoofed files (e.g., `.jpg` containing an ELF or Windows PE binary).
- Control group: 50 diverse benign documents, spreadsheets, and images.

### 5. Planned Experiment
Execute automated test suite `tests/security/corpus.test.ts` across configurations $C_0$ through $C_3$. Record verdict (`ALLOW`, `BLOCK`, `QUARANTINE`, `ERROR`) and detection reason for each sample.

### 6. Statistical Test
McNemar's test for paired nominal data comparing $C_0$ vs $C_3$ detection counts:
$$\chi^2 = \frac{(b - c)^2}{b + c}$$
with significance threshold $\alpha = 0.01$.

### 7. Success & Falsification Conditions
- **Supported Condition**: Configuration $C_3$ achieves $\ge 95\%$ recall across the 80 attack classes while maintaining $0\%$ false positive rate on the benign corpus, with $p < 0.01$ relative to baseline $C_0$.
- **Falsification Condition**: $C_3$ fails to detect more than $80\%$ of attack classes, or exhibits a false positive rate $> 2\%$ on the benign control corpus.

### 8. Evidence Location
`docs/evidence/phase-35/security-matrix.csv` and `docs/evidence/phase-38/h1-evaluation.json`.

---

## Hypothesis H2: Quarantine-First Pipeline Invariant Enforcement

### 1. Formal Hypothesis
A quarantine-first architecture—enforced by database-driven state machines, atomic row locks, and service privilege separation—guarantees that zero unscanned, unapproved, or malformed files reach trusted cloud storage, even in the presence of service crashes, worker termination, or simulated hardware faults.

### 2. Variables
- **Independent Variable**: Fault injection type during file ingestion and processing (Chaos Test Suite):
  - Normal execution.
  - Hard kill of `services/scanner` worker mid-scan (`SIGKILL`).
  - Temporary PostgreSQL database disconnection / connection pool exhaustion.
  - Abrupt S3 storage network disconnect during upload stream.
  - Worker crash during promotion.
  - Job queue message duplication (at-least-once replay).
- **Dependent Variable**: Invariant violation count ($N_{\text{violations}}$) measured by `invariants.sql`:
  - Number of objects in clean storage lacking an un-superseded `ALLOW` record.
  - Number of clean storage objects whose SHA-256 diverges from `scan_results`.
  - Number of file state transitions lacking a corresponding `audit_events` row.

### 3. Baseline & Comparison
A direct-to-cloud upload pattern where files are placed in application storage and asynchronously validated by an external webhook.

### 4. Evaluation Corpus
1,000 randomized files (500 benign, 500 malicious) streamed concurrently under chaos conditions (`tests/integration/chaos.ts`).

### 5. Planned Experiment
Phase 23 chaos harness executes 1,000 concurrent file uploads while randomly killing containers, injecting network faults, and duplicating queue rows. Following test completion, `invariants.sql` inspects the database and storage buckets.

### 6. Statistical Metric
Exact count of invariant violations:
$$N_{\text{violations}} = 0$$

### 7. Success & Falsification Conditions
- **Supported Condition**: $N_{\text{violations}} \equiv 0$ across all 1,000 executions under chaos conditions. Every failed file resolves to `ERROR` or remains in `QUARANTINE`; zero unapproved files reach clean storage.
- **Falsification Condition**: Any file lands in clean storage without an un-superseded `ALLOW` decision ($N_{\text{violations}} > 0$).

### 8. Evidence Location
`docs/evidence/phase-23/chaos-summary.json` and `docs/evidence/phase-38/h2-invariants.log`.

---

## Hypothesis H3: Cryptographic Version & Hash Binding for TOCTOU Prevention

### 1. Formal Hypothesis
Binding promotional decisions to an immutable 5-tuple `(bucket, key, version_id, sha256, size)` and re-verifying the exact byte hash at promotion time eliminates 100% of Time-of-Check-to-Time-of-Use (TOCTOU) file substitution vulnerabilities in cloud object storage, whereas conventional key-only promotion pipelines suffer predictable exploit rates proportional to race window latency.

### 2. Variables
- **Independent Variable**:
  - Promotional protocol:
    - $P_0$: Key-only promotion (naive baseline: copies by `bucket/key`).
    - $P_1$: Version-only promotion (queries by `VersionId` but skips re-hash).
    - $P_2$: Hash-only promotion (re-hashes head of key).
    - $P_3$: Bound Promotion (SUG Protocol: exact `VersionId` fetch + in-memory re-hash + conditional clean write).
  - Race window delay $\Delta t \in [10\text{ ms}, 500\text{ ms}]$.
- **Dependent Variable**: Exploitation Rate ($R_{\text{exploit}}$):
  $$R_{\text{exploit}} = \frac{\text{Unscanned Malicious Files Promoted}}{\text{Total Race Injection Trials}}$$

### 3. Baseline & Comparison
Baseline $P_0$ (traditional background worker that reads the latest object by key and copies to clean storage).

### 4. Evaluation Corpus
A paired test dataset consisting of benign file $A$ (`clean.pdf`, SHA-256 $H_A$) and malicious file $B$ (`shell.pdf`, SHA-256 $H_B$) targeting the identical object key.

### 5. Planned Experiment
Phase 32 TOCTOU Attack Harness (`tests/security/toctou/race.ts`). Executes 1,000 trials per promotional protocol ($P_0, P_1, P_2, P_3$) across varying race windows $\Delta t$. In each trial, benign file $A$ is submitted; immediately after scan completion, an adversary thread replaces the quarantine key with file $B$.

### 6. Statistical Metric
Exploitation percentage with 99% confidence intervals (Clopper-Pearson method):
$$R_{\text{exploit}}(P_3) = 0.00\% \quad (99\%\text{ CI: } [0.00\%, 0.26\%])$$

### 7. Success & Falsification Conditions
- **Supported Condition**: $R_{\text{exploit}}(P_3) \equiv 0$ across 1,000 trials, while baseline $P_0$ exhibits $R_{\text{exploit}}(P_0) > 0$ under identical race conditions.
- **Falsification Condition**: Any trial in $P_3$ results in the promotion of modified file $B$.

### 8. Evidence Location
`docs/evidence/phase-32/toctou-results.csv` and `docs/evidence/phase-38/h3-toctou-table.csv`.

---

## Hypothesis H4: Least-Privilege IAM Blast-Radius Restriction

### 1. Formal Hypothesis
Decomposing gateway permissions into role-separated, stage-specific IAM identities (`UPLOAD_ROLE`, `SCANNER_ROLE`, `PROMOTION_ROLE`, `REPLICATION_ROLE`, `AUDITOR_ROLE`) restricts the unauthorized action blast radius of a compromised component to zero cross-boundary privilege escalations, as verified by automated negative permission matrices.

### 2. Variables
- **Independent Variable**: The active role identity assumed during the test.
- **Dependent Variable**: Forbidden Action Success Rate ($S_{\text{forbidden}}$) across a 40-action permission matrix:
  $$S_{\text{forbidden}} = \frac{\text{Forbidden Actions Succeeded}}{\text{Total Forbidden Actions Tested}}$$

### 3. Baseline & Comparison
A monolithic IAM role granting read/write access across all gateway buckets and database tables.

### 4. Evaluation Corpus
A standardized matrix of 40 security-sensitive operations (e.g., `sug_scanner` attempting to write clean storage, `sug_api` attempting to delete quarantine objects, `sug_replication` attempting to read plaintext or delete GCS replicas).

### 5. Planned Experiment
Phase 29 Cloud IAM Negative Suite (`tests/security/iam/blast-radius.ts`). The test harness assumes each role credential sequentially and attempts all 40 operations against live AWS S3 and GCP storage.

### 6. Statistical Metric
Forbidden action success count:
$$S_{\text{forbidden}} \equiv 0 \quad (\text{Zero forbidden successes across all roles})$$

### 7. Success & Falsification Conditions
- **Supported Condition**: $S_{\text{forbidden}} = 0$ (all unauthorized API calls return HTTP 403 / AccessDenied and generate CloudTrail audit alerts).
- **Falsification Condition**: Any service identity successfully executes an unauthorized action outside its trust zone ($S_{\text{forbidden}} > 0$).

### 8. Evidence Location
`docs/evidence/phase-29/blast-radius-matrix.csv` and AWS CloudTrail audit logs.

---

## Hypothesis H5: Operational Latency & Throughput Overhead

### 1. Formal Hypothesis
The complete quarantine, scanning, deterministic decision, and envelope-encryption pipeline introduces an operational processing latency under 2.5 seconds for standard document and image uploads ($\le 10\text{ MB}$), maintaining steady-state throughput of at least 30 uploads per minute without unbounded memory growth.

### 2. Variables
- **Independent Variable**: Concurrency level ($N \in \{1, 5, 10, 25, 50\}$ concurrent users) and payload size ($100\text{ KB}, 1\text{ MB}, 10\text{ MB}$).
- **Dependent Variable**:
  - Ingestion latency ($T_{\text{ingest}}$): time to stream and deposit in quarantine.
  - End-to-end promotion latency ($T_{\text{e2e}}$): upload to clean storage ciphertext availability.
  - Node.js Resident Set Size (RSS) memory consumption.

### 3. Baseline & Comparison
Direct streaming upload without security inspection (Fastify streaming to S3).

### 4. Evaluation Corpus
Standardized file suite: 100 KB plain text, 1 MB PDF document, 10 MB high-resolution image.

### 5. Planned Experiment
Phase 36 Load and Performance Testing with k6 (`tests/perf/upload-benchmark.js`). Measure P50, P90, P95, and P99 latency profiles across 10-minute steady-state runs.

### 6. Target Metrics (Planned Benchmarks)
- Ingest response time: $P_{95} \le 500\text{ ms}$ for $1\text{ MB}$ files.
- End-to-end promotion time: $P_{95} \le 2,500\text{ ms}$ for $1\text{ MB}$ files.
- Memory consumption: API container RSS $\le 256\text{ MB}$; Scanner container RSS $\le 512\text{ MB}$ (excluding ClamAV daemon).

### 7. Success & Falsification Conditions
- **Supported Condition**: P95 end-to-end latency remains $\le 2.5\text{ s}$ for files $\le 10\text{ MB}$ under steady-state load (10 concurrent streams), with zero socket timeout errors and flat memory profile.
- **Falsification Condition**: P95 latency exceeds 5.0 seconds for normal 1 MB files or containers trigger OOM restart under sustained load.

### 8. Evidence Location
`docs/evidence/phase-36/k6-summary.csv` and `docs/evidence/phase-36/memory-rss.png`.
