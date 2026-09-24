# ADR 0009: Multi-Engine Security Scanning, Archive Safety, and Fail-Closed Analysis

## Status
APPROVED (DEC-010, DEC-011, DEC-021)

## Context
Malware detection relying exclusively on antivirus signatures suffers from critical blind spots. As proven by Jana & Shmatikov (2012), signature engines (including ClamAV) are routinely bypassed by chameleon attacks (format-confusion tricks) and werewolf attacks (parser differential attacks). Furthermore, modern attackers leverage:
- Non-recursive zip bombs (Fifield 2019) that achieve 28,000,000:1 compression ratios without nesting.
- Embedded macros and external relationships in OOXML documents.
- Polyglot files (e.g., GIF/JavaScript or PDF/ZIP) that exploit multiple valid file headers (Koch et al. 2022).
- Zero-day threats that lack published signature hashes (Sihwail et al. 2018).

A robust file gateway requires multi-layered, deterministic, and signature-based verification executed under strict isolation.

## Decision
We establish a multi-engine, fail-closed scanning pipeline in `services/scanner`:

### 1. In-House ClamAV Integration (INSTREAM Protocol)
- Deploys **ClamAV 1.4.6 LTS** (`clamav/clamav:1.4.6`) on the isolated `scan` network.
- Configured via explicit environment variables (`CLAMD_CONF_*`):
  - `StreamMaxLength 55M`, `MaxFileSize 55M`, `MaxScanSize 200M`, `MaxRecursion 10`, `MaxFiles 2000`, `MaxScanTime 60000`, `AlertExceedsMax yes`, `AlertEncrypted yes`, `AlertEncryptedArchive yes`, `MaxThreads 4`, `ConcurrentDatabaseReload no`.
- We implement an in-house **60-line TypeScript INSTREAM client** (avoiding unmaintained npm packages).
  - Uses `zINSTREAM\0` framing, 4-byte big-endian chunk length, and a 0-length terminating chunk.
  - Strict classification: **ONLY `stream: OK` is clean**. Any other response (e.g., `stream: Eicar-Test-Signature FOUND`, timeout, connection reset) maps to `BLOCK` or `ERROR`.
  - Signature age tracking: if signatures are older than 7 days, scanner reports `ERROR / SCANNER_UNAVAILABLE`.

### 2. YARA-X Subprocess Rule Engine
- Integrates **YARA-X 1.20.0 CLI** (`yr scan --output-format ndjson`).
- Invoked via subprocess with explicit timeout (30 seconds).
- Parsed strictly from NDJSON stdout output, **NEVER from exit codes** (since YARA-X returns exit code 0 or 1 for general execution status, not match detection).
- Rule metadata tags define `severity` and `confidence`.
- Rules are version-controlled in the repository; `signature_version` equals the git commit SHA.

### 3. Non-Recursive Zip-Bomb and Archive Security
- Archive inspection uses **`yauzl 3.4`** for lazy central-directory parsing before extracting or decompressing bytes.
- Enforces two-phase budget protection against Fifield-style bombs:
  - Phase 1 (Central Directory Audit): verify total uncompressed size, entry count (< 2,000), compression ratio limit (< 100:1), single EOCD, no duplicate filenames, supported compression methods only (0 = stored, 8 = deflated), no encryption bit.
  - Phase 2 (Decompression Ceilings): worker thread execution with hard memory cap (256MB RSS), streaming byte-counter, and 10-second processing ceiling.
  - Path traversal check: blocks `../`, absolute paths, leading slashes, and symlinks.

### 4. Format-Specific Structural Checks
- **PDF**: `qpdf` normalization and active content scan (checks for `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles`).
- **OOXML** (`.docx`, `.xlsx`, `.pptx`): Validates internal OPC archive structure, checks for VBA macro storage (`vbaProject.bin`), and audits `_rels/` for external target relationships.
- **Images**: Trailing-data analysis and embedded script header scans using `sharp 0.35` and `libmagic`.
- **Polyglots**: Validates that file structure strictly conforms to declared and detected magic signatures without secondary conflicting format signatures.

### 5. Deterministic Decision Engine (Rules R1–R7)
- Evaluates findings through pure mathematical rules:
  - **R1 (Result Identity Verification)**: Scanned hash must equal ingest hash.
  - **R2 (Required Check Completeness)**: All policy-mandated checks must exist. Any missing check yields `ERROR`.
  - **R3 (Critical Finding Check)**: Any finding with severity `CRITICAL` or `HIGH` yields `BLOCK`.
  - **R4 (Detector Disagreement)**: Discrepancies between magic bytes, file extension, and MIME yield `QUARANTINE`.
  - **R5 (Archive Integrity)**: Structural archive violations yield `BLOCK`.
  - **R6 (Risk Score Threshold)**: Weighted sum of medium/low findings must remain below policy threshold.
  - **R7 (Clean Verification)**: Only if all checks pass without error is `ALLOW` emitted.
- **Property Test Invariant**: Property tests over 10,000 simulated cases verify that ANY error or missing required check NEVER produces an `ALLOW` verdict.

## Alternatives Considered
- **Machine Learning Classifiers**: Rejected for MVP due to adversarial evasion, lack of explainability, and absence of standardized public benchmarks (Literature Survey Section 3.2).
- **Dynamic Sandbox / Detonation Chamber (Cuckoo/Cape)**: Out of scope due to massive infrastructure overhead, multi-minute execution latency, and non-deterministic behavior.
- **Generic CDR (Content Disarm and Reconstruction)**: Identified in literature as the strongest advanced-phase addition, but deferred past MVP due to the need for per-format rebuild pipelines (Dubin group methodology).

## Security Impact
Guarantees multi-layered defense. An attacker bypassing ClamAV signatures is stopped by YARA-X rules, structural archive checks, or polyglot validators. Fail-closed design ensures unexpected failures halt promotion.

## Cost Impact
ClamAV container requires 3–4 GiB RAM; container limits (`limits.memory: 4G`) prevent host memory exhaustion. Zero external SaaS scanning costs.

## Research Impact
Validates Hypothesis H1 (layered validation outperforms single checks) and provides the evaluation corpus data for Chapter 5 of the research paper.

## Consequences
- Requires maintaining YARA-X rule sets in git.
- Scanner worker requires `qpdf`, `file` (libmagic), and ClamAV network access.

## Evidence & Source References
- Jana & Shmatikov (2012): IEEE S&P (Chameleon & Werewolf attacks on ClamAV).
- Fifield (2019): USENIX WOOT Best Paper (A better zip bomb).
- Koch et al. (2022): ACM CSET (Polyglot file detection).
- Build Plan: Part 1.2 (DEC-010, DEC-011, DEC-021), Part 2.2 (P14–P18 contracts).
