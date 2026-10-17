# Phase P17 — Findings Model and Format Checks

## Executive Summary

Phase P17 implements the canonical findings model and format-specific security checks for the Secure Upload Gateway (SUG). It establishes deterministic, immutable security findings persistence in PostgreSQL (`scan_results`), binds all findings to the canonical Phase P12 `ArtifactIdentity` tuple, and exposes the findings through the authenticated edge API (`GET /api/v1/scans/:id`).

### Scope Boundaries & Strict Non-Goals

- **Detection & Evidence Only**: Phase P17 is strictly an evidence and detection phase. It produces raw inspection results (`PASS`, `FAIL`, `SUSPICIOUS`, `ERROR`, `SKIPPED`).
- **Zero Policy / Decision Contamination**: P17 **never** makes `ALLOW`, `BLOCK`, or `QUARANTINE` decisions, does **not** evaluate policy rules, does **not** calculate risk scores, and does **not** implement file promotion or quarantine release logic. All decision and evaluation logic is strictly reserved for Phase P18.
- **Archive Engine Preservation**: Phase P16 safe archive inspection is fully preserved and reused for OOXML container inspection without modification.

---

## 1. Findings Model & Canonical Reason Code Registry

### Database Schema & Immutability (`scan_results`)

The `scan_results` relation stores individual check outcomes. It is governed by a `forbid_mutation()` trigger enforcing append-only immutability.

```sql
CREATE TABLE scan_results (
    id                          uuid PRIMARY KEY DEFAULT uuidv7(),
    scan_job_id                 uuid NOT NULL REFERENCES scan_jobs(id),
    file_version_id             uuid NOT NULL REFERENCES file_versions(id),
    check_id                    text NOT NULL,
    engine                      text NOT NULL,
    engine_version              text,
    signature_version           text,
    outcome                     finding_outcome NOT NULL,
    reason_code                 text,
    severity                    severity_level NOT NULL DEFAULT 'INFO',
    confidence                  confidence_level NOT NULL DEFAULT 'CONFIRMED',
    evidence                    jsonb NOT NULL DEFAULT '{}',
    scanned_storage_version_id  text NOT NULL,
    scanned_sha256              bytea NOT NULL CHECK (octet_length(scanned_sha256) = 32),
    scanned_size                bigint NOT NULL,
    duration_ms                 integer,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scan_job_id, check_id)
);
```

### Idempotency Contract

Idempotency across job retries or replayed scans is enforced at the database level via:

```sql
INSERT INTO scan_results (...) VALUES (...)
ON CONFLICT (scan_job_id, check_id) DO NOTHING;
```

This respects table append-only immutability while preventing duplicate records.

### P12 Artifact Identity Tuple Binding

Every finding record asserts the exact cryptographic identity of the scanned artifact:

- `scanned_storage_version_id`: S3 VersionId of the staged quarantine object.
- `scanned_sha256`: Cryptographic SHA-256 digest calculated by the scanner streaming boundary.
- `scanned_size`: Exact byte length of the staged object.

---

## 2. Canonical Reason Code Registry

Reason codes are centrally defined in `@sug/shared/reasons` (`packages/shared/src/reasons.ts`):

| Check ID                     | Canonical Reason Code          | Outcome   | Default Severity | Description                                            |
| ---------------------------- | ------------------------------ | --------- | ---------------- | ------------------------------------------------------ |
| `universal`                  | `CLEAN`                        | `PASS`    | `INFO`           | No malicious pattern or structural violation detected. |
| `universal`                  | `SCANNER_ERROR`                | `ERROR`   | `HIGH`           | Engine or parser subprocess error.                     |
| `universal`                  | `NOT_APPLICABLE`               | `SKIPPED` | `INFO`           | Detector not applicable to format.                     |
| `universal`                  | `MALWARE_DETECTED`             | `FAIL`    | `CRITICAL`       | Antivirus or YARA signature match.                     |
| `scanner.archive`            | `ARCHIVE_BOMB_DETECTED`        | `FAIL`    | `CRITICAL`       | Archive bomb structure or ratio exceeded.              |
| `scanner.pdf`                | `ACTIVE_CONTENT_DETECTED`      | `FAIL`    | `HIGH`           | Executable actions or scripts in PDF.                  |
| `scanner.pdf`                | `PDF_MALFORMED`                | `ERROR`   | `HIGH`           | Corrupt or invalid PDF structure.                      |
| `scanner.ooxml.macro`        | `OOXML_MACRO_DETECTED`         | `FAIL`    | `HIGH`           | VBA macro project or macro ContentType.                |
| `scanner.ooxml.relationship` | `OOXML_EXTERNAL_RELATIONSHIP`  | `FAIL`    | `MEDIUM`         | Relationship targeting external URI.                   |
| `scanner.image.trailing`     | `IMAGE_TRAILING_DATA_DETECTED` | `FAIL`    | `HIGH`           | Appended data after format EOF marker.                 |
| `scanner.signature.embedded` | `EMBEDDED_EXECUTABLE_DETECTED` | `FAIL`    | `CRITICAL`       | PE/ELF/Mach-O header at offset > 0.                    |
| `scanner.polyglot`           | `POLYGLOT_DETECTED`            | `FAIL`    | `CRITICAL`       | Contradictory dual format headers.                     |

---

## 3. Format Detectors Implementation

### A. PDF Active Content Detector (`scan-04`)

- **Package**: `packages/security-engine/src/format/pdf.ts`
- **Engine**: `qpdf` (CLI) with internal FlateDecode decompressor fallback.
- **Normalization**: Executes `qpdf --qdf --object-streams=disable` to expand object streams when `qpdf` is installed. Fallback inflates `/Filter /FlateDecode` streams with strict memory limits (10 MB per stream, 50 MB total).
- **Keywords**: Detects `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles`, `/SubmitForm`, `/XFA`, `/OpenAction`. Normalizes hex notation (e.g. `/#4a#61#76#61#53#63#72#69#70#74` -> `/JavaScript`).

### B. OOXML Macro & Relationship Detectors (`scan-05` & `scan-06`)

- **Package**: `packages/security-engine/src/format/ooxml.ts`
- **Engine**: In-process `yauzl` stream inspection without disk extraction.
- **Macro Check (`scan-05`)**: Inspects container parts for `word/vbaProject.bin`, `xl/vbaProject.bin`, `ppt/vbaProject.bin`, `vbaData.xml`, and macro ContentTypes in `[Content_Types].xml`.
- **External Relationship Check (`scan-06`)**: Parses `_rels/.rels` and part `.rels` files for `TargetMode="External"`.
  - **Zero Network Invariant**: Strictly static XML parsing. Absolutely zero HTTP requests or DNS lookups are performed.

### C. Image Trailing Data Detector

- **Package**: `packages/security-engine/src/format/image-trailing.ts`
- **Formats**: PNG (`IEND` chunk), JPEG (`EOI` marker `0xFF 0xD9`), GIF (`0x3B` trailer).
- Flags any non-whitespace/payload data appended after format-legal termination markers.

### D. Embedded Executable Signature Detector

- **Package**: `packages/security-engine/src/format/embedded-sig.ts`
- Scans for executable headers concealed at offset > 0:
  - Windows PE: `MZ` header with valid `e_lfanew` pointing to `PE\0\0`.
  - Linux ELF: `\x7fELF` with valid class, endianness, and version.
  - macOS Mach-O: 32/64-bit and Universal Fat headers.

### E. Polyglot Matrix Detector

- **Package**: `packages/security-engine/src/format/polyglot.ts`
- Evaluates conflicting format signatures:
  - `poly-01`: GIF header with valid ZIP EOCD / Central Directory (FAIL / `POLYGLOT_DETECTED`).
  - `poly-02`: JPEG SOI with valid ZIP EOCD (FAIL / `POLYGLOT_DETECTED`).
  - `poly-03`: PDF header with valid ZIP EOCD (FAIL / `POLYGLOT_DETECTED`).
  - `poly-04`: Advanced parasitic container without standard EOCD. Explicitly marked as a **DOCUMENTED MISS** in evidence without artificial rule fudging.

---

## 4. Scan Findings API (`GET /api/v1/scans/:id`)

The edge API provides access to scan status and findings:

- **Authentication**: Supports P6 API keys (`Bearer sug_...`) and P7 Dashboard User JWTs (`Bearer <jwt>`).
- **Tenant Isolation**: Asserts that the scan job's application matches the calling API key's `application_id`. Cross-tenant access returns HTTP 403 Forbidden.
- **Deterministic Ordering**: Findings are sorted deterministically by `check_id ASC`.
- **OpenAPI 3.0.3**: Synchronized in `docs/openapi.json`.

---

## 5. Verification Matrix & Quality Gates

| Test Suite             | File                                                  | Tests | Result |
| ---------------------- | ----------------------------------------------------- | ----- | ------ |
| Format Unit Tests      | `tests/unit/security-engine/format-checks.test.ts`    | 22    | PASS   |
| Scanner Integration    | `tests/integration/scanner/p17-format-checks.test.ts` | 7     | PASS   |
| Scan API Integration   | `tests/integration/api/p17-scans-api.test.ts`         | 6     | PASS   |
| Database Invariants    | `tests/integration/db/invariants.test.ts`             | 15    | PASS   |
| OpenAPI Spec Check     | `scripts/generate-openapi.mjs --check`                | 1     | PASS   |
| YARA Rules Validation  | `scripts/validate-yara-rules.mjs`                     | 1     | PASS   |
| Overall Monorepo Suite | Vitest Full Run                                       | 668   | PASS   |
