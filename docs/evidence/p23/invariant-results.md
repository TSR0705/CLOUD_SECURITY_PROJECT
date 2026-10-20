# Phase P23 Deliverable: SQL Invariant Verifier Results

This document records the verification results of the canonical `invariants.sql` suite executed against the live PostgreSQL database via `pnpm db:invariants`.

- **Script Runner**: `scripts/run-invariants.ts`
- **Target Database**: `postgres://sug_admin:***@127.0.0.1:5433/sug`
- **Execution Timestamp**: 2026-10-20
- **Overall Invariant Status**: **PASS (0 Violations)**

---

## Invariant Evaluation Matrix

| Invariant ID | Violations | Status   | Rule Description                                                        | Security / Integrity Guarantee                                                                      |
| ------------ | ---------- | -------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **INV-01A**  | 0          | `[PASS]` | Clean object without un-superseded ALLOW decision                       | Prohibits unverified, pending, or rejected files from existing in the clean bucket                  |
| **INV-01B**  | 0          | `[PASS]` | Clean object with invalid file status                                   | Ensures files with clean objects are strictly in `PROMOTED` or `DELETED` status                     |
| **INV-02**   | 0          | `[PASS]` | Clean object exists for BLOCKED or QUARANTINED file version             | Guarantees blocked malware or quarantined files never enter clean storage                           |
| **INV-03A**  | 0          | `[PASS]` | Audit sequence non-monotonic or duplicate sequence numbers              | Enforces strict forward-secure strictly increasing sequence ordering                                |
| **INV-03B**  | 0          | `[PASS]` | Audit event prev_hash does not match preceding event_hash               | Validates unbroken SHA-256 cryptographic chaining across all audit events                           |
| **INV-03C**  | 0          | `[PASS]` | Audit event with NULL event_hash or prev_hash                           | Enforces presence of cryptographic hashes for all audit events (genesis prev_hash is zeroed 64-hex) |
| **INV-04A**  | 0          | `[PASS]` | File application_id mismatch with upload_session                        | Enforces multi-tenant ownership consistency between files and sessions                              |
| **INV-04B**  | 0          | `[PASS]` | Audit event application_id mismatch with referenced file                | Prevents cross-tenant contamination in the audit event trail                                        |
| **INV-04C**  | 0          | `[PASS]` | Upload session policy belongs to different application                  | Enforces tenant-isolation between applications and security policies                                |
| **INV-05A**  | 0          | `[PASS]` | Cloud object with empty or null storage_version_id                      | Ensures cloud object immutable version tracking is always populated                                 |
| **INV-05B**  | 0          | `[PASS]` | File version with empty or null storage_version_id                      | Enforces version ID presence across all ingestion records                                           |
| **INV-05C**  | 0          | `[PASS]` | Clean object sha256_plain diverges from file_versions sha256_ingest     | Guarantees plaintext identity preservation between ingestion and promotion                          |
| **INV-05D**  | 0          | `[PASS]` | Clean object sha256_plain diverges from scan_results scanned_sha256     | Ensures that what was scanned is identical to what was promoted                                     |
| **INV-05E**  | 0          | `[PASS]` | Clean object sha256_plain diverges from security_decisions bound_sha256 | Validates exact cryptographic binding between decisions and clean objects                           |
| **INV-06A**  | 0          | `[PASS]` | Finished scan_job missing finished_at timestamp                         | Enforces queue lifecycle state consistency for scan jobs                                            |
| **INV-06B**  | 0          | `[PASS]` | Finished promotion_job missing finished_at timestamp                    | Enforces queue lifecycle state consistency for promotion jobs                                       |

---

## Invariant Verifier Fail-Closed Test Verification

The verifier itself is tested against synthetic violations in `tests/integration/db/invariants-verifier.test.ts`:

- **Synthetic Corrupted Audit Hash**: Injected single-row corruption in audit chain. Verifier immediately catches breach and reports failure on `INV-03B`.
- **Synthetic Clean Object Without Decision**: Injected unauthorized clean object row. Verifier catches breach and reports failure on `INV-01A`.
- **Clean Baseline**: Verifier passes with 0 violations.

Result: 3 of 3 verifier integration tests pass.
