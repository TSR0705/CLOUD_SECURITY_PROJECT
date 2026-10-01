# Phase P16 — Archive Inspection & Zip-Bomb Security

## 1. Architecture Overview

Phase P16 implements safe, deterministic, fail-closed archive inspection for untrusted ZIP and Open Office XML (OOXML: DOCX, XLSX, PPTX) containers in the Secure Upload Gateway (SUG) scanner service.

The implementation is located in `packages/security-engine/src/archive/` and uses `yauzl 3.4.0` with strict two-phase inspection and dedicated worker thread isolation.

```
+---------------------------------------------------------------------------------------------------+
| Scanner Worker (services/scanner/src/worker.ts)                                                   |
|                                                                                                   |
|  1. claimScanJob() (PostgreSQL atomic FOR UPDATE SKIP LOCKED)                                     |
|  2. Retrieve artifact from quarantine storage by exact VersionId                                   |
|  3. Verify cryptographic SHA-256 identity against file_versions.sha256_ingest                     |
|  4. ClamAvScanner.scanStream() (P14) -> scan_results (scanner.clamav)                             |
|  5. YaraScanner.scanFile() (P15)     -> scan_results (scanner.yara)                               |
|  6. inspectArchive() (P16)           -> scan_results (scanner.archive)                            |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| Worker Thread Boundary (packages/security-engine/src/archive/inspect.ts)                           |
|                                                                                                   |
|  - Spawns isolated Node.js Worker (worker_threads.Worker)                                         |
|  - Enforces hard timeout (maxExtractionMs: 10,000 ms) via worker.terminate()                      |
|  - Tracks isolated worker peak RSS memory (maxMemoryBytes: 256 MB)                                |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                         +------------------------+------------------------+
                         |                                                 |
                         v                                                 v
+-----------------------------------------------+ +-----------------------------------------------+
| Phase 1: Structural Binary Validation         | | Phase 2: Controlled Streaming Decompression   |
| (structural.ts)                               | | (streaming.ts)                                |
|                                               | |                                               |
| - Verify single valid EOCD (no chameleon)     | | - Lazy consumption via yauzl open()           |
| - Validate Central Directory boundaries       | | - Per-entry & cumulative decompressed bytes   |
| - Cross-check CD against Local File Headers   | | - Instantaneous ratio tracking                |
| - Check overlapping physical byte ranges      | | - Streaming CRC-32 validation (zlib.crc32)    |
| - Detect duplicate entry names                | | - Recursive nested archive inspection         |
| - Reject unsafe paths (Zip Slip, UNC, devices)| | - Bounded nested depth enforcement (<= 3)     |
| - Reject symlinks (Unix mode 0120000)         | |                                               |
| - Reject encryption (GPBF bit 0 set)          | |                                               |
| - Enforce compression methods (0, 8 only)     | |                                               |
+-----------------------------------------------+ +-----------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| Findings Persistence Layer (scan_results)                                                         |
|                                                                                                   |
|  - check_id: 'scanner.archive'                                                                    |
|  - engine: 'yauzl', engine_version: '3.4.0'                                                       |
|  - outcome: PASS | FAIL | ERROR                                                                   |
|  - reason_code: ARCHIVE_INSPECTION_PASSED | ARCHIVE_BOMB_DETECTED | ARCHIVE_PATH_TRAVERSAL | ...   |
|  - severity: CRITICAL | HIGH | MEDIUM | LOW | INFO                                                |
|  - confidence: CONFIRMED                                                                          |
|  - evidence: { entryCount, totalCompressedBytes, totalDecompressedBytes, overallRatio, ... }     |
|  - P18 Isolation: Worker NEVER makes ALLOW/BLOCK/QUARANTINE decisions                              |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Threat Model & Attack Vectors

ZIP archives are complex container formats with significant historical attack surfaces:

| Threat / Attack Vector                    | Exploit Mechanism                                                                                                                                                                    | P16 Defense Implementation                                                                                                                                                                                                                                 |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **High-Ratio ZIP Bombs**                  | Small compressed payload expanding to gigabytes or terabytes (e.g., 42.zip).                                                                                                         | Declared and running compression ratio capped at `100:1`. Absolute cumulative decompression ceiling capped at `100 MB`. Decompression aborts immediately when exceeded.                                                                                    |
| **Fifield Overlapping Ranges**            | Multiple Central Directory headers pointing to the same deflated byte stream (Fifield 2019 non-recursive zip bomb).                                                                  | Phase 1 parses all Local File Header spans (`[localOffset, localOffset + 30 + nameLen + extraLen + compSize)`) and asserts disjoint intervals via sorted range intersection checks (`ARCHIVE_OVERLAPPING_ENTRIES`).                                        |
| **Zip Slip / Path Traversal**             | Archive entries containing `../`, leading slashes, absolute paths (`C:\`), UNC shares (`\\server\share`), or reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`). | Strict path sanitizer normalizes and validates every entry name. Rejects path separators traversing outside root, null bytes, backslashes, drive letters, and Windows device names (`ARCHIVE_PATH_TRAVERSAL`).                                             |
| **Chameleon / Multiple EOCD**             | Multiple End of Central Directory records placed at arbitrary offsets to trick parsers into reading contradictory file trees.                                                        | Phase 1 scans the tail 65,557 bytes for `0x06054b50` signatures. Asserts exactly one legitimate EOCD at file termination matching the primary Central Directory offset. Multiple conflicting EOCD records cause immediate rejection (`ARCHIVE_CORRUPTED`). |
| **Symlink / Arbitrary File Writes**       | UNIX permission bits `0120000` or OS/2 symlink attributes pointing to sensitive host paths (e.g., `/etc/passwd`).                                                                    | Inspects `versionMadeBy` high byte (Unix) and upper 16 bits of `externalFileAttributes`. Rejects any entry with S_IFLNK mode (`ARCHIVE_SYMLINK_DETECTED`).                                                                                                 |
| **Encrypted Archives**                    | General Purpose Bit Flag bit 0 set (`0x0001`), concealing malicious content from downstream scanners.                                                                                | Bitwise check of `generalPurposeBitFlag & 0x0001`. Encrypted entries cannot be inspected and are rejected fail-closed (`ARCHIVE_ENCRYPTED`).                                                                                                               |
| **Compression Method Confusion**          | Obscure or unsupported compression methods (e.g., method 9 Deflate64, method 12 BZIP2, method 14 LZMA) causing parser crashes or evasion.                                            | Permitted compression methods are strictly limited to Method `0` (Stored) and Method `8` (Deflated). All others are rejected (`ARCHIVE_UNSUPPORTED_COMPRESSION`).                                                                                          |
| **Recursive Nested Bombs**                | Archives containing nested zip archives to arbitrary depth (tar/zip recursion attack).                                                                                               | Recursively inspects nested ZIP/OOXML payloads with a strict depth ceiling of `maxDepth: 3`. Cumulative decompression limits span all nested layers (`ARCHIVE_NESTED_DEPTH_EXCEEDED`).                                                                     |
| **Central Directory / LFH Discrepancies** | Mismatches between Central Directory metadata and Local File Header metadata (used to evade security gateways that read only CD).                                                    | Phase 1 opens the raw file and cross-checks CD entry offsets against on-disk Local File Headers, confirming matching compression methods and non-overlapping byte ranges.                                                                                  |
| **Corrupted / Spoofed Checksums**         | Deliberately corrupted CRC-32 values or lying uncompressed sizes.                                                                                                                    | Stream decompression calculates running `zlib.crc32(chunk, runningCrc)` and asserts equality against declared CRC-32 on stream termination (`ARCHIVE_CORRUPTED`).                                                                                          |

---

## 3. Inspection Budget Model

Inspection operates under an immutable, strictly bounded budget defined in `ArchiveInspectionBudget`:

```typescript
export interface ArchiveInspectionBudget {
  maxDecompressedBytes: number; // Cumulative unpacked byte limit (default: 100 MB)
  maxEntries: number; // Total entries permitted across archive (default: 1,000)
  maxRatio: number; // Maximum allowed compression ratio (default: 100:1)
  maxDepth: number; // Maximum allowed nested archive recursion depth (default: 3)
  maxArchiveSizeBytes: number; // Maximum input file size (default: 50 MB)
  maxExtractionMs: number; // Maximum inspection wall-clock time (default: 10,000 ms)
  maxMemoryBytes: number; // Peak RSS memory allowance for worker (default: 256 MB)
}
```

### Production Defaults:

- **`maxArchiveSizeBytes`**: `52,428,800` bytes (50 MB)
- **`maxDecompressedBytes`**: `104,857,600` bytes (100 MB)
- **`maxEntries`**: `1,000`
- **`maxRatio`**: `100:1`
- **`maxDepth`**: `3`
- **`maxExtractionMs`**: `10,000` ms (10.0 seconds)
- **`maxMemoryBytes`**: `268,435,456` bytes (256 MB)

If any limit is breached during either Phase 1 or Phase 2, inspection immediately terminates with a fail-closed `REJECTED` verdict.

---

## 4. Execution Boundary, Memory Architecture & RSS Disclosure

### 4.1 Worker Thread Isolation

Archive inspection executes within a dedicated Node.js Worker Thread (`node:worker_threads`):

- **Execution Isolation**: Offloads CPU-intensive deflation and decompression away from the scanner event loop.
- **Hard Timeout Enforcement**: The orchestrator (`inspectArchive()`) sets a timer for `maxExtractionMs` (10,000 ms). If the worker does not complete within 10 seconds, `worker.terminate()` is called immediately, killing the execution context and returning an `ARCHIVE_TIMEOUT` rejection.

### 4.2 Technically Accurate Memory Classification

In Node.js, `worker_threads` run as distinct V8 threads inside the **same operating system process**. The OS kernel tracks Resident Set Size (RSS) strictly at the OS process level, not per pthread/worker thread.

Consequently:

- `process.memoryUsage().rss` inside a worker thread measures the **Host Node.js Process Peak RSS**, not isolated worker memory.
- Under Node.js, true OS-level worker RSS isolation does not exist at the thread boundary.

### 4.3 Tri-Partite Model: Measurement vs Budget vs Enforcement

A strict technical distinction is maintained across:

1. **Memory Measurement**:
   - Host Process Peak RSS: `process.memoryUsage().rss` measured across the host process.
   - V8 Heap Statistics: `process.memoryUsage().heapUsed` and `v8.getHeapStatistics()`.
   - Reported in scan findings JSON for post-scan auditing.

2. **Memory Budget**:
   - Parameter: `maxMemoryBytes = 256 MB` (`268,435,456` bytes).
   - Nature: Soft threshold verified at inspection completion and during health checks.
   - Reality: `maxMemoryBytes` is NOT an OS-level or V8-level hard memory limit that preemptively traps instantaneous native memory spikes.

3. **Memory Enforcement (Actual Hard Controls)**:
   The actual hard defenses preventing memory exhaustion are:
   - **Streaming Chunk Decompression**: Entries are processed in 16–64 KB chunks. Each chunk is processed immediately for CRC-32 and byte counting and discarded for immediate garbage collection. Decompressed streams are never buffered into full-file Buffers.
   - **Cumulative Decompressed-Byte Ceiling (`maxDecompressedBytes: 100 MB`)**: Monitored on every chunk emitted by zlib. If cumulative bytes exceed 100 MB, `activeStream.destroy()` terminates decompression immediately.
   - **Real-Time Compression Ratio Ceiling (`maxRatio: 100:1`)**: Monitored on every chunk for entries > 1 MB. If instantaneous ratio exceeds 100:1, `activeStream.destroy()` terminates decompression immediately.
   - **Hard Execution Timeout (`maxExtractionMs: 10,000 ms`)**: Enforced by parent timer calling `worker.terminate()`.
   - **Container-Level Memory Limits**: In production deployments, Docker and Kubernetes cgroup memory ceilings (`--memory=4g`) enforce hard kernel-level memory boundaries.

### 4.4 Nested Archive Non-Materialization Sanity

- Recursive nested inspection is strictly lazy and budgeted.
- The outer archive is never extracted in full.
- Only the specific nested archive entry is streamed to a temporary file in `os.tmpdir()`.
- Nested archives are inspected with cumulative uncompressed byte budgets and nesting depth propagated (`maxDepth: 3`).
- Temporary nested files are immediately deleted in `finally` blocks upon completion.
- Arbitrary directory trees are never materialized to disk.

---

## 5. OOXML Container Boundary

Open Office XML documents (DOCX, XLSX, PPTX) are standard ZIP containers. In P16:

- OOXML files are inspected as valid ZIP containers under the structural and decompression budget gates.
- Entry names like `word/document.xml`, `[Content_Types].xml`, `_rels/.rels` are inspected for safe paths, compression methods, and non-bomb expansion.
- **Strict Non-Goal (P17 Boundary)**: P16 does **NOT** extract or inspect VBA macros (`vbaProject.bin`), DDE links, external relationship targets, or OLE embedded packages. That functionality belongs strictly to Phase P17.

---

## 6. Scanner Worker Integration & P18 Isolation

In `services/scanner/src/worker.ts`:

- When an incoming object is a ZIP or OOXML container (detected via file extension, MIME type, or policy configuration), the worker calls `inspectArchive()`.
- The scanner records the outcome in `scan_results` with:
  - `check_id`: `'scanner.archive'`
  - `engine`: `'yauzl'`, `engine_version`: `'3.4.0'`
  - `outcome`: `'PASS'` | `'FAIL'` | `'ERROR'`
  - `reason_code`: Corresponding reason code (`ARCHIVE_INSPECTION_PASSED`, `ARCHIVE_BOMB_DETECTED`, etc.)
  - `severity`: `CRITICAL` for bombs/traversal/symlinks/encryption, `MEDIUM` for anomalies, `INFO` for clean passes
  - `confidence`: `'CONFIRMED'`
  - `evidence`: Structured JSON containing entry counts, compressed/uncompressed sizes, overall ratio, and per-entry metadata.
- **Strict Non-Goal (P18 Boundary)**: The scanner worker strictly records findings. It never makes terminal policy decisions (`ALLOW`, `BLOCK`, `QUARANTINE`). Terminal decisions are the sole responsibility of the Phase P18 Decision Engine.

---

## 7. Verification & Test Suite Matrix (`arc-01` – `arc-09`)

| Test Code | Description                         | Input Characteristic                                             | Expected Outcome    | Reason Code                     |
| --------- | ----------------------------------- | ---------------------------------------------------------------- | ------------------- | ------------------------------- |
| `arc-01`  | Safe Normal Archive                 | Clean Store (0) and Deflate (8) entries within budget            | `PASS` / `ACCEPTED` | `ARCHIVE_INSPECTION_PASSED`     |
| `arc-02A` | Metadata High-Ratio ZIP Bomb        | Small file declaring > 1 GB uncompressed expansion in headers    | `FAIL` / `REJECTED` | `ARCHIVE_BOMB_DETECTED`         |
| `arc-02B` | Streaming Decompression Bomb        | Small headers (passes Phase 1); stream expands mid-decompression | `FAIL` / `REJECTED` | `COMPRESSION_RATIO_EXCEEDED`    |
| `arc-03`  | Nested Archive Depth Limit Exceeded | Nested ZIP archives exceeding depth 3                            | `FAIL` / `REJECTED` | `NESTED_ARCHIVE_DEPTH_EXCEEDED` |
| `arc-04`  | Entry Count Limit Exceeded          | Archive with entries exceeding maxEntries (1,000)                | `FAIL` / `REJECTED` | `ENTRY_COUNT_EXCEEDED`          |
| `arc-05`  | Overlapping Ranges (Fifield Bomb)   | Fifield non-recursive zip bomb sharing deflated streams          | `FAIL` / `REJECTED` | `OVERLAPPING_ENTRIES`           |
| `arc-06`  | Lying Size / Stream Mismatch        | Archive entry with lying declared uncompressed size              | `FAIL` / `REJECTED` | `SIZE_MISMATCH`                 |
| `arc-07`  | Zip Slip & Path Traversal           | Entries with `../`, `C:\`, UNC paths, `CON`/`PRN`/`NUL` devices  | `FAIL` / `REJECTED` | `ZIP_SLIP_DETECTED`             |
| `arc-08`  | Encrypted Archive Rejection         | Archive with General Purpose Bit Flag 0 set                      | `FAIL` / `REJECTED` | `ENCRYPTED_ARCHIVE_FORBIDDEN`   |
| `arc-09`  | Symlink Archive Rejection           | Archive with Unix mode `0120000` symlink header                  | `FAIL` / `REJECTED` | `SYMLINK_FORBIDDEN`             |

### Dual-Path Benchmark Evidence (`ARC-02`):

Detailed evidence is captured in `docs/evidence/p16/arc-02-performance.txt`, `docs/evidence/p16/archive-memory-rss.txt`, and `docs/evidence/p16/archive-test-summary.txt`:

1. **ARC-02A (Metadata-Level High-Ratio Bomb)**:
   - **Intercept**: Phase 1 binary structural check (before decompression)
   - **Declared Expansion**: 1,073,741,824 bytes (1.00 GB, ~936,130:1 ratio)
   - **Elapsed Duration**: 49.93 ms (SLA: < 10,000 ms) — **PASS**
   - **Host Process Peak RSS**: 96.39 MB (SLA: < 256 MB) — **PASS**
   - **Decompressed Bytes**: 0 bytes (halted before stream open) — **PASS**
   - **Disposition**: `REJECTED` fail-closed (`ARCHIVE_BOMB_DETECTED`) — **PASS**

2. **ARC-02B (Streaming Decompression Bomb)**:
   - **Intercept**: Phase 2 controlled streaming decompression
   - **Declared Expansion in Headers**: 500,000 bytes (~49:1 ratio, passes Phase 1)
   - **Elapsed Duration**: 55.63 ms (SLA: < 10,000 ms) — **PASS**
   - **Host Process Peak RSS**: 98.54 MB (SLA: < 256 MB) — **PASS**
   - **Decompressed Bytes at Abort**: 1,064,960 bytes (~1.05 MB before stream abort) — **PASS**
   - **Disposition**: `REJECTED` fail-closed (`COMPRESSION_RATIO_EXCEEDED`) — **PASS**
   - **Full Expansion Materialized**: NO (Stream destroyed immediately via `destroy()`) — **PASS**
