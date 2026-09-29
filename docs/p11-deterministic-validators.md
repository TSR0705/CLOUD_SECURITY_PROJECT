# Phase P11 — Deterministic Validators

## 1. Executive Summary

Phase P11 implements the deterministic, pre-scanning validation engine for the Secure Upload Gateway (SUG) inside `packages/security-engine`. It provides pure, stateless validation functions with strict type safety, zero external I/O or network dependencies, and complete independence from HTTP frameworks (Fastify), database layers (PostgreSQL), and cloud storage SDKs (AWS SDK).

Key achievements:

1. **Filename Safety & Sanitization (`val-08`)**: Full protection against directory traversal (`../`, `..\`, `%2e%2e`, `%2f`, `%5c`), null-byte injection (`\0`, `%00`), control characters (ASCII 0x00–0x1F, 0x7F–0x9F), Unicode direction overrides (e.g. Right-to-Left Override `U+202E`), and Windows device/reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
2. **Double-Extension Masquerade Detection (`val-03`)**: Distinguishes legitimate compound extensions (e.g. `.tar.gz`) from malicious executable masquerades (e.g. `invoice.pdf.exe`) and hidden executables (e.g. `invoice.exe.pdf`).
3. **Magic-Byte Signature Detection (`val-04`)**: Identifies file formats from initial byte sequences using `file-type` v22, strictly bounded to a 4,100-byte prefix with zero streaming overflow, supplemented with custom text/markup detectors for XML, SVG, JSON, and CSV.
4. **Detector Consistency Rule (`val-06`)**: Performs 3-way validation comparing filename extension, client-declared MIME, and detected magic signatures. Respects OOXML container compatibility (`DOCX`/`XLSX`/`PPTX` inside `ZIP`) and text subtype compatibility (`CSV`/`JSON`/`XML` within `TEXT`).
5. **Libmagic Integration (`val-07`)**: Provides wrapper functions (`detectMimeWithLibmagic`, `detectMimeFromBufferWithLibmagic`) for the POSIX `file --mime-type -b` utility with mockable command execution support.
6. **File Size Validation (`val-12`)**: Validates actual byte counts against declared size, policy maximum (`maxFileSize`), and global hard ceilings (50 MB).
7. **Canonical Type Map**: Strongly typed catalog of 18 canonical file types mapping primary/secondary extensions, standard MIME types, magic signatures, and container/subtype compatibility hierarchies.

---

## 2. Architecture & Pure Dependency Boundary

In accordance with the project architecture guidelines and ESLint boundary constraints:
- `packages/security-engine` imports **only** from `@sug/shared`.
- It has **zero dependencies** on Fastify, PostgreSQL, AWS SDK, S3, or `@sug/policy-engine`.
- All validator functions are pure, deterministic functions that take inputs and options and return structured validation result objects containing boolean pass/fail flags, standardized canonical reason codes, and descriptive error messages.

```
                              Raw File / Upload Metadata
                                          │
                     ┌────────────────────┴────────────────────┐
                     │                                         │
                     ▼                                         ▼
            validateFilename()                        extractExtension()
            - Traversal rejection                     - Compound handling
            - Null-byte protection                    - Policy allow/block
            - Control chars / RTL
            - Windows device names
                     │                                         │
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                             validateDoubleExtension()  (val-03)
                             - Disarm hidden executables
                             - Allow legitimate compound extensions
                                          │
                     ┌────────────────────┴────────────────────┐
                     │                                         │
                     ▼                                         ▼
           validateDeclaredMime()                     detectMagic() (val-04)
           - RFC parameter parsing                    - First 4,100 bytes only
           - Normalization                            - file-type v22 + custom
                     │                                         │
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                         validateTypeConsistency()  (val-06)
                         - 3-Way: Extension vs MIME vs Magic
                         - OOXML / ZIP container compatibility
                         - Text / CSV / JSON subtype compatibility
                                          │
                                          ▼
                            validateFileSize()  (val-12)
                            - Actual vs declared vs policy
```

---

## 3. Implemented Modules

### 3.1 `types.ts`
Defines canonical file types:
- Documents: `PDF`, `DOCX`, `XLSX`, `PPTX`
- Images: `JPEG`, `PNG`, `GIF`, `WEBP`, `TIFF`, `SVG`
- Text & Data: `TEXT`, `CSV`, `JSON`, `XML`
- Archives: `ZIP`, `TAR`, `GZIP`
- Binaries & Fallbacks: `EXECUTABLE`, `OCTET_STREAM`

And canonical validation result structures and reason codes:
- `FilenameValidationResult`
- `ExtensionValidationResult`
- `DoubleExtensionResult`
- `DeclaredMimeResult`
- `MagicDetectionResult`
- `LibmagicResult`
- `TypeConsistencyResult`
- `FileSizeValidationResult`

### 3.2 `type-map.ts`
- Holds `CANONICAL_TYPE_DEFINITIONS` for all 18 types.
- Builds non-colliding reverse-lookup indexes (`EXTENSION_TO_TYPE`, `MIME_TO_TYPE`, `MAGIC_EXT_TO_TYPE`, `MAGIC_MIME_TO_TYPE`) prioritizing primary definitions.
- Provides container compatibility (`DOCX`/`XLSX`/`PPTX` in `ZIP`) and subtype compatibility (`CSV`/`JSON`/`XML` in `TEXT`, `SVG` in `XML`).

### 3.3 `filename.ts` (`val-08`)
- Rejects directory traversal paths, including encoded forms (`%2e%2e`, `%2f`, `%5c`).
- Rejects null bytes (`\0`, `%00`), control characters (ASCII 0–31, 127–159), and right-to-left override sequences (`\u202E`, `\u202D`, `\u200E`, `\u200F`).
- Rejects Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`).
- Enforces maximum length of 255 characters.
- Provides `sanitizeFilename()` to replace unsafe characters with safe alternatives while preserving valid extensions.

### 3.4 `extension.ts` & `double-extension.ts` (`val-03`)
- `extractExtension()` handles dotfiles (`.gitignore`), trailing dots (`file.`), multiple dots (`report..pdf`), and compound extensions (`.tar.gz`).
- `validateDoubleExtension()` analyzes the penultimate extension. If the final or penultimate extension is an executable extension (`.exe`, `.dll`, `.bat`, `.sh`, `.bin`, `.scr`, `.msi`, `.vbs`, `.ps1`), flags `DOUBLE_EXTENSION_DENIED` with specific classification (`EXECUTABLE_FINAL` or `EXECUTABLE_PENULTIMATE`).

### 3.5 `mime.ts`
- `parseAndNormalizeMime()` parses `type/subtype`, validates against RFC 2045/6838 token grammar, lowercases, and strips parameters (e.g. `charset=utf-8`).
- `validateDeclaredMime()` checks client-provided MIME strings against optional allowlists and blocklists.

### 3.6 `magic.ts` (`val-04`)
- Reads at most `MAX_MAGIC_BUFFER_BYTES` (4,100 bytes).
- Uses `file-type` v22 to identify binary signatures.
- Includes custom UTF-8 text/markup inspection for SVG (`<svg`), XML (`<?xml`), JSON (`{` or `[`), and CSV (comma-separated headers).

### 3.7 `libmagic.ts` (`val-07`)
- Provides CLI integration with the system `file` command: `file --mime-type -b <path>`.
- Allows injection of a custom/mock executor for testing without requiring native POSIX `file` installed on the host.

### 3.8 `consistency.ts` (`val-06`)
- Evaluates 3-way consistency among:
  1. Filename Extension
  2. Declared MIME Type
  3. Detected Magic Bytes
- Returns:
  - `CONSISTENT`: All available detectors agree or are compatible.
  - `MAGIC_EXTENSION_MISMATCH`: Magic bytes contradict file extension.
  - `MAGIC_MIME_MISMATCH`: Magic bytes contradict declared MIME type.
  - `MIME_EXTENSION_MISMATCH`: Declared MIME contradicts file extension.
  - `UNDETERMINED`: No detector could determine the file type.

### 3.9 `size.ts` (`val-12`)
- Verifies that `actualSizeBytes` does not exceed `maxSizeBytes` (policy or default 50 MB limit).
- Verifies that `actualSizeBytes` matches `declaredSizeBytes` (if provided).
- Enforces positive non-zero file sizes (`EMPTY_FILE`).

---

## 4. Test Verification & DoD Mapping

| DoD Criterion | Description | Test Suite | Status |
|:---|:---|:---|:---:|
| `val-03` | Double-extension denylist & compound handling | `tests/unit/security-engine/double-extension.test.ts` | PASS (21 tests) |
| `val-04` | Magic-byte detection bounded to 4,100 bytes | `tests/unit/security-engine/magic.test.ts` | PASS (15 tests) |
| `val-06` | 3-way detector consistency rule | `tests/unit/security-engine/consistency.test.ts` | PASS (9 tests) |
| `val-07` | libmagic CLI integration wrapper | `tests/unit/security-engine/libmagic.test.ts` | PASS (6 tests) |
| `val-08` | Filename safety & sanitization | `tests/unit/security-engine/filename.test.ts` | PASS (30 tests) |
| `val-12` | File size validation rule | `tests/unit/security-engine/size.test.ts` | PASS (8 tests) |
| — | Extension extraction & allowlist | `tests/unit/security-engine/extension.test.ts` | PASS (16 tests) |
| — | MIME parsing & normalization | `tests/unit/security-engine/mime.test.ts` | PASS (13 tests) |
| — | Canonical type map & 100% branch coverage | `tests/unit/security-engine/type-map.test.ts` | PASS (29 tests) |
| **Total** | **Security Engine Unit Test Suite** | **9 suites / 147 tests** | **147/147 PASS** |

Monorepo regression test suite:
- **35 test files passed**
- **468 total tests passed**
- **TypeScript build (`tsc -b`)**: 0 errors
- **ESLint (`eslint .`)**: 0 errors
- **Prettier formatting**: 100% compliant
- **OpenAPI specification**: In sync
