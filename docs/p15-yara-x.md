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

Rules missing `severity` or `confidence` fail closed with `ERROR` and are rejected by the validation gate.

---

## 6. Signature Version Provenance & Manifest Architecture

Every YARA scan finding recorded in `scan_results` attaches a deterministic `signature_version`. To avoid operational ambiguity, the gateway differentiates the Git commit revision from the cryptographic content tree hash:

### 6.1 Provenance Hierarchy (`resolveYaraProvenance`)

1. **Environment Override**: `process.env.YARA_RULES_VERSION` (used for deterministic testing or pinned deployment overrides).
2. **Build-Time Manifest (`rules_manifest.json`)**:
   Generated during `pnpm build` and container builds. Contains:
   ```json
   {
     "signatureVersion": "262ebdac9c92cc61e1ce0b1c978793ae0267534f",
     "rulesGitRevision": "262ebdac9c92cc61e1ce0b1c978793ae0267534f",
     "rulesContentSha256": "a41bbca2b93af4c5db230cd52b2f141d27411e4cba3179dbf6d1a203e5462da5",
     "generatedAt": "2026-09-30T13:18:09.709Z"
   }
   ```
   If the manifest's `rulesContentSha256` matches current rule contents, the embedded `signatureVersion` is used immediately. This completely eliminates runtime dependency on `.git` in production containers.
3. **Live Git Repository**:
   If `.git` is present and clean, resolves `git log -1 --format=%H -- packages/scanner/rules`. If rule files have uncommitted modifications, the version reflects the mutation (`${gitSha}-dirty-${contentHash.slice(0, 8)}`).
4. **Deterministic Content Tree Hash Fallback**:
   If Git is absent and no manifest exists, computes a deterministic SHA-256 tree hash over all sorted `.yar` and `.yara` file contents.

### 6.2 Provenance Invariants

- **Reproducibility**: Identical rules always resolve to the exact same version string.
- **Sensitivity**: Any alteration to rule content produces a different version string.
- **Isolation**: Container runtimes operate with zero `.git` repository access.

---

## 7. Benign Corpus Gate (`fp-01`)

A security rule cannot be considered eligible for promotion to the production rule set until it passes the benign-corpus false-positive gate (`fp-01`).

- **Corpus Location**: `tests/fixtures/corpus/benign/`
- **File Types**: `.txt`, `.json`, `.csv`, `.xml`, `.pdf`, `.png`.
- **Gate Contract**:
  1. Enumerates all files in the curated benign corpus.
  2. Scans each file against `packages/scanner/rules/`.
  3. Asserts exactly `0` false-positive rule matches.

---

## 8. Definition of Done: Normal Build Gate Integration (`pnpm build`)

To guarantee invalid rules cannot enter production:

1. **Root Build Lifecycle Integration**:
   ```json
   "build": "node scripts/validate-yara-rules.mjs packages/scanner/rules && tsc -b"
   ```
2. **Package Build Lifecycle Integration**:
   ```json
   "build": "node ../../scripts/validate-yara-rules.mjs rules && tsc"
   ```
3. **Compilation & Metadata Verification**:
   The validation gate invokes `yr compile` and parses all rule metadata before any TypeScript compilation occurs.
4. **Fail-Fast Build Abort**:
   If any syntax error or missing metadata is detected, `validate-yara-rules.mjs` exits with code `1`, immediately terminating `pnpm build` with detailed compiler diagnostics on `stderr`.
5. **Recovery**:
   Restoring valid syntax allows `pnpm build` to succeed cleanly (exit code `0`) and regenerate `rules_manifest.json`.

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

## 10. Terminology & Phase Boundary (P15 vs P18 Audit)

### 10.1 Canonical Terminology

- When a scan produces 0 rule matches, the gateway records:
  > **"YARA-X produced no known rule match"** (Outcome: `PASS`, Reason: `CLEAN`).
- The gateway DOES NOT state:
  > _"YARA-X proved the file is safe."_

### 10.2 Phase Boundary & Separation of Responsibilities

Phase P15 is strictly an observational pattern-matching engine. It does NOT make authorization decisions:

1. **Database Isolation**:
   - `services/scanner` writes findings exclusively to `scan_results` (check_id `scanner.yara`).
   - `services/scanner` does NOT touch, query, or insert rows into `security_decisions` (0 writes, 0 references).
2. **Zero Decision Logic**:
   - The scanner worker records `overallSeverity` and `overallConfidence` solely to populate the columns of the `scan_results` row.
   - It NEVER evaluates ALLOW, BLOCK, or QUARANTINE policy decisions.
   - When matching a threat rule, the scan job transitions to `SUCCEEDED` (meaning the scan job completed execution successfully).
3. **P18 Decision Engine Responsibility**:
   - In Phase P18, the decision engine evaluates the complete set of finding rows in `scan_results` against application policy rules to synthesize the authoritative `security_decisions` verdict.
4. **Out of Scope (Deferred to P16–P20)**:
   - Archive inspection & ZIP-bomb checks (P16).
   - Deep content inspection for PDF/OOXML (P17).
   - Risk scoring and ALLOW/BLOCK policy decisions (P18).
   - Artifact promotion and AES-256-GCM encryption (P19).
   - Cloud replication (P20).
