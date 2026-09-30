# Phase P15 — YARA-X Integration & Pattern Matching

## 1. Architecture Overview

Phase P15 integrates **YARA-X 1.20.0** (`yr` CLI) as the deterministic heuristic and pattern-matching engine for the Secure Upload Gateway (SUG) scanner service. YARA-X scans staged quarantine artifacts whose cryptographic identity (storage VersionId, SHA-256 digest, and size) has been verified.

```
+-----------------------------------------------------------------------------------------+
| Scanner Worker (services/scanner)                                                       |
|                                                                                         |
|  1. claimScanJob() (PostgreSQL atomic FOR UPDATE SKIP LOCKED)                           |
|  2. Retrieve artifact from quarantine storage by exact VersionId                         |
|  3. Verify cryptographic SHA-256 identity against file_versions.sha256_ingest           |
|  4. ClamAvScanner.scanStream() (if enabled) -> scan_results row (scanner.clamav)        |
|  5. YaraScanner.scanFile() -> subprocess spawn                                          |
+-----------------------------------+-----------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------------------------+
| YARA-X Subprocess (`yr` CLI 1.20.0)                                                     |
|                                                                                         |
|  Exact Invocaton:                                                                       |
|    yr scan --output-format ndjson --timeout 30 --print-meta rules/ <staged-artifact>    |
|                                                                                         |
|  Output Modes:                                                                          |
|    Match: {"path":"...","rules":[{"identifier":"Rule","meta":[["severity","high"],...]]}|
|    Clean: {"path":"...","rules":[]}                                                     |
|    Syntax Error: error[E001]: syntax error (exit code 1)                                |
+-----------------------------------+-----------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------------------------+
| Findings Persistence Layer                                                              |
|                                                                                         |
|  - Parse NDJSON output line-by-line, validate mandatory metadata                        |
|  - Derive signature_version (Git SHA of rules/)                                         |
|  - Insert finding into scan_results:                                                    |
|      check_id: 'scanner.yara'                                                           |
|      engine: 'yara-x', engine_version: '1.20.0'                                         |
|      signature_version: <rules_git_sha>                                                 |
|      outcome: PASS | FAIL | ERROR                                                       |
|      reason_code: CLEAN | MALWARE_DETECTED | SCANNER_ERROR                              |
|      severity: <mapped_severity>, confidence: <mapped_confidence>                       |
|      evidence: { status, matchedRules, matches, rawOutput }                             |
|      scanned_storage_version_id, scanned_sha256, scanned_size                           |
|  - On CLEAN or MATCH: completeScanJob(SUCCEEDED) (P18 decision engine handles verdict)   |
|  - On ERROR: failScanJob(attempts++, retryable: true)                                   |
+-----------------------------------------------------------------------------------------+
```

---

## 2. YARA-X Version & Binary Pinning

- **Engine Version**: `1.20.0`
- **CLI Executable**: `yr`
- **Release Source**: VirusTotal YARA-X official GitHub releases:
  - Windows: `https://github.com/VirusTotal/yara-x/releases/download/v1.20.0/yara-x-v1.20.0-x86_64-pc-windows-msvc.zip`
  - Linux (Container): `https://github.com/VirusTotal/yara-x/releases/download/v1.20.0/yara-x-v1.20.0-x86_64-unknown-linux-gnu.tar.gz`
- **Pinned SHA-256 (Linux release)**: `cabb8df46492fff59c51261302c71ed9cb2cef393d3f0ca560801a34a8e24cbe`
- **Verification**: `yr --version` outputs `yara-x-cli 1.20.0`.
- **Constraint**: Classic YARA v4 is strictly forbidden. YARA-X 1.20.0 is Rust-native, memory-safe, and provides formal NDJSON structured serialization.

---

## 3. Subprocess Invocation & NDJSON Protocol

### 3.1 Subprocess Execution

Scanning is executed via Node.js `child_process.spawn` using explicit argument arrays (`shell: false`). Untrusted filenames and paths are passed as discrete arguments, eliminating shell-interpolation and command-injection attack surfaces.

### 3.2 Canonical Command

```bash
yr scan --output-format ndjson --timeout 30 --print-meta packages/scanner/rules <file>
```

### 3.3 NDJSON Parser Rationale

In YARA-X, the CLI returns exit code `0` when scanning completes, regardless of whether rules matched or not. Matches MUST NEVER be inferred from process exit codes.

- **Match Payload Output (exit code 0)**:
  ```json
  {
    "path": "<file>",
    "rules": [
      {
        "identifier": "RuleName",
        "meta": [
          ["description", "..."],
          ["severity", "critical"],
          ["confidence", "high"]
        ]
      }
    ]
  }
  ```
- **Clean Scan Output (exit code 0)**:
  ```json
  { "path": "<file>", "rules": [] }
  ```
- **Compilation / Syntax Error (exit code 1)**:
  Emitted to `stderr` with non-zero exit code.

The parser validates every NDJSON line, extracts all matched rules, normalizes metadata tuples, and ensures complete multi-match preservation without silent drops.

---

## 4. Rule Directory & Versioning

- **Location**: `packages/scanner/rules/`
- **Source Control**: All YARA rules are committed in Git. No compiled binaries (`.yarc`) are tracked.
- **Initial Canonical Rules**:
  - `packages/scanner/rules/p15_threat.yar`: Matches canonical threat pattern `SUG_MALWARE_TEST_PATTERN_P15_THREAT` (`scan-03`).
  - `packages/scanner/rules/p15_secondary.yar`: Secondary threat pattern `SUG_SECONDARY_TEST_PATTERN_P15_THREAT` for multiple-match testing.

---

## 5. Rule Metadata Contract

All production YARA rules must contain mandatory metadata for `severity` and `confidence`.

### 5.1 Severity Vocabulary

| Rule Metadata | Database Enum (`SeverityLevel`) | Meaning                                  |
| ------------- | ------------------------------- | ---------------------------------------- |
| `critical`    | `CRITICAL`                      | Severe threat / known malware pattern    |
| `high`        | `HIGH`                          | High-risk pattern or credential exposure |
| `medium`      | `MEDIUM`                        | Suspicious heuristic indicator           |
| `low`         | `LOW`                           | Minor anomaly or informational finding   |
| `info`        | `INFO`                          | Baseline telemetry                       |

### 5.2 Confidence Vocabulary

| Rule Metadata | Database Enum (`ConfidenceLevel`) | Meaning                                        |
| ------------- | --------------------------------- | ---------------------------------------------- |
| `confirmed`   | `CONFIRMED`                       | Exact cryptographic or deterministic signature |
| `high`        | `HIGH`                            | Specific heuristic or unambiguous pattern      |
| `medium`      | `MEDIUM`                          | Probable pattern with context dependence       |
| `low`         | `LOW`                             | Loose pattern or weak indicator                |

Rules missing `severity` or `confidence` fail closed with `ERROR` and are blocked from production consideration.

---

## 6. Signature Version Provenance

Every YARA scan finding recorded in `scan_results` attaches a deterministic `signature_version`.

- **Primary Source**: Git commit SHA of the versioned rules directory:
  ```bash
  git log -1 --format=%H -- packages/scanner/rules
  ```
- **Build Manifest**: During container/package builds, a `rules_manifest.json` is generated with `{ "version": "<sha>" }`.
- **Runtime Fallback**: If `.git` is stripped in production containers, `computeRulesDirectoryContentHash()` calculates a deterministic SHA-256 tree hash over all sorted `.yar` and `.yara` file contents.

---

## 7. Benign Corpus Gate (`fp-01`)

A security rule cannot be considered eligible for blocking until it passes the benign-corpus false-positive gate (`fp-01`).

- **Corpus Location**: `tests/fixtures/corpus/benign/`
- **File Types**: `.txt`, `.json`, `.csv`, `.xml`, `.pdf`, `.png`.
- **Gate Contract**:
  1. Enumerates all files in the curated benign corpus.
  2. Scans each file against `packages/scanner/rules/`.
  3. Asserts exactly `0` false-positive rule matches.

---

## 8. Definition of Done: Syntax Error Build Gate

To guarantee invalid rules cannot enter production:

1. `tests/fixtures/yara/invalid/syntax_error.yar` contains a deliberately invalid rule.
2. `scripts/validate-yara-rules.mjs` executes `yr compile` and metadata validation.
3. Compiling the invalid fixture exits with code `1` and emits syntax diagnostics.
4. The test suite asserts that the validation gate fails on syntax errors.

---

## 9. Fail-Closed Error Guarantees

In accordance with fail-closed security invariants:

| Condition                     | System Response                 | scan_results Outcome                    |
| ----------------------------- | ------------------------------- | --------------------------------------- |
| Missing `yr` binary           | `status: 'ERROR'`               | `ERROR`, `reason_code: 'SCANNER_ERROR'` |
| Process timeout (>30s)        | Child killed, `status: 'ERROR'` | `ERROR`, `reason_code: 'SCANNER_ERROR'` |
| Malformed NDJSON              | `status: 'ERROR'`               | `ERROR`, `reason_code: 'SCANNER_ERROR'` |
| Missing/Invalid Rule Metadata | `status: 'ERROR'`               | `ERROR`, `reason_code: 'SCANNER_ERROR'` |
| Missing Target Artifact       | `status: 'ERROR'`               | `ERROR`, `reason_code: 'SCANNER_ERROR'` |
| Non-Zero Exit Code            | `status: 'ERROR'`               | `ERROR`, `reason_code: 'SCANNER_ERROR'` |

Errors are NEVER converted to `CLEAN`.

---

## 10. Terminology & Phase Boundary

### 10.1 Canonical Terminology

- When a scan produces 0 rule matches, the gateway records:
  > **"YARA-X produced no known rule match"** (Outcome: `PASS`, Reason: `CLEAN`).
- The gateway DOES NOT state:
  > _"YARA-X proved the file is safe."_

### 10.2 Phase Boundary (Zero P16+ Contamination)

Phase P15 produces pattern-matching telemetry.

- **P15 Scope**: Subprocess invocation, NDJSON parsing, metadata mapping, `scan_results` persistence.
- **Out of Scope (Deferred to P16–P20)**:
  - Archive inspection & ZIP-bomb checks (P16).
  - Deep content inspection for PDF/OOXML (P17).
  - Risk scoring and ALLOW/BLOCK policy decisions (P18).
  - Artifact promotion and AES-256-GCM encryption (P19).
  - Cloud replication (P20).
