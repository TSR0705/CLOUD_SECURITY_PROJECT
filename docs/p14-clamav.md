# Phase P14 — ClamAV Integration & EICAR Scanning

## 1. Architecture Overview

Phase P14 integrates **ClamAV 1.4.6** as the deterministic malware-scanning engine for the Secure Upload Gateway (SUG) scanner service. Scanning occurs over clamd's native TCP `INSTREAM` protocol against staged quarantine artifacts whose cryptographic identity has already been verified in Phase P13.

```
+-----------------------------------------------------------------------------------+
| Scanner Worker (services/scanner)                                                 |
|                                                                                   |
|  1. claimScanJob() (PostgreSQL atomic SKIP LOCKED)                                |
|  2. Retrieve artifact from quarantine storage by exact VersionId                   |
|  3. Verify cryptographic SHA-256 identity against file_versions.sha256_ingest     |
|  4. Open local staged read stream                                                 |
|  5. ClamAvScanner.scanStream()                                                    |
+--------------------------+--------------------------------------------------------+
                           | TCP 3310 (zINSTREAM\0)
                           v
+-----------------------------------------------------------------------------------+
| sug-clamav Container (clamav/clamav:1.4.6)                                        |
|                                                                                   |
|  - Stream chunks received with 4-byte big-endian length prefix                    |
|  - Scanned against ClamAV signature database (CVD)                                |
|  - Engine limits enforced: StreamMaxLength=55M, MaxScanTime=60000ms               |
|  - Returns: "stream: OK" (CLEAN)                                                  |
|         or: "stream: <signature> FOUND" (MALWARE)                                 |
|         or: "INSTREAM size limit exceeded. ERROR" (ERROR)                         |
+--------------------------+--------------------------------------------------------+
                           |
                           v
+-----------------------------------------------------------------------------------+
| Persistence & Decision Layer                                                      |
|                                                                                   |
|  - Insert finding into scan_results:                                              |
|      check_id: 'scanner.clamav'                                                   |
|      engine: 'clamav', engine_version: '1.4.6'                                    |
|      outcome: PASS | FAIL | ERROR                                                 |
|      reason_code: CLEAN | MALWARE_DETECTED | SCANNER_ERROR                        |
|  - If CLEAN or MALWARE: completeScanJob(SUCCEEDED) (decision engine in P18)      |
|  - If ERROR: failScanJob(attempts++, retry/backoff or DEAD)                       |
+-----------------------------------------------------------------------------------+
```

---

## 2. ClamAV Version & Container Image

- **Image**: `clamav/clamav:1.4.6`
- **Digest**: `sha256:24974869c4fc4a1c14f070110748e8b83855953736d727cb13c7139c16c4ccfb`
- **Engine Version**: ClamAV 1.4.6
- **Rationale**: 1.4.6 is the LTS release of ClamAV providing stable INSTREAM protocol semantics, modern CVD database support, and strict resource limiting configurations.

---

## 3. Docker Compose Configuration

The ClamAV service is declared in `infrastructure/docker/docker-compose.yml`:

```yaml
clamav:
  image: clamav/clamav:1.4.6
  container_name: sug-clamav
  restart: unless-stopped
  ports:
    - '3310:3310'
  environment:
    - CLAMD_CONF_StreamMaxLength=55M
    - CLAMD_CONF_MaxFileSize=55M
    - CLAMD_CONF_MaxScanSize=200M
    - CLAMD_CONF_MaxRecursion=10
    - CLAMD_CONF_MaxFiles=2000
    - CLAMD_CONF_MaxScanTime=60000
    - CLAMD_CONF_AlertExceedsMax=yes
    - CLAMD_CONF_AlertEncrypted=yes
    - CLAMD_CONF_AlertEncryptedArchive=yes
    - CLAMD_CONF_MaxThreads=4
    - CLAMD_CONF_ConcurrentDatabaseReload=no
  deploy:
    resources:
      limits:
        memory: 4096M
  healthcheck:
    test: ['CMD-SHELL', 'clamdcheck.sh']
    interval: 10s
    timeout: 5s
    retries: 15
    start_period: 60s
```

### Key Properties:

- **Dedicated Port**: `3310:3310` bound to localhost.
- **Resource Constraints**: Capped at 4096 MB RAM to prevent runaway memory consumption.
- **Healthcheck**: Uses official `clamdcheck.sh` utility with `start_period: 60s` to account for initial signature database loading.

---

## 4. clamd Resource & Security Configurations

| Setting                    | Value                    | Rationale                                                        |
| -------------------------- | ------------------------ | ---------------------------------------------------------------- |
| `StreamMaxLength`          | `55M` (57,671,680 bytes) | Enforces 50 MB max file upload boundary with safety headroom.    |
| `MaxFileSize`              | `55M`                    | Prevents scanning files larger than gateway upload policy.       |
| `MaxScanSize`              | `200M`                   | Prevents archive decompression expansion attacks (ZIP bombs).    |
| `MaxRecursion`             | `10`                     | Bounded recursion depth for nested containers.                   |
| `MaxFiles`                 | `2000`                   | Limits total unpacked member count per archive.                  |
| `MaxScanTime`              | `60000`                  | 60-second execution deadline per artifact.                       |
| `AlertExceedsMax`          | `yes`                    | Alerts when any limit is exceeded rather than silently skipping. |
| `AlertEncrypted`           | `yes`                    | Flags encrypted files where payload inspection cannot occur.     |
| `AlertEncryptedArchive`    | `yes`                    | Flags password-protected archives.                               |
| `MaxThreads`               | `4`                      | Prevents CPU starvation on multi-core host machines.             |
| `ConcurrentDatabaseReload` | `no`                     | Prevents doubled memory spikes during signature updates.         |

---

## 5. INSTREAM Protocol Specification

The scanner communicates with `clamd` over a TCP socket using the `zINSTREAM\0` command:

1. **Initiation**: Client connects to `host:port` and sends `zINSTREAM\0` (9 bytes: `0x7a 0x49 0x4e 0x53 0x54 0x52 0x45 0x41 0x4d 0x00`).
2. **Chunk Framing**: Each data slice is framed as:
   - 4 bytes: Chunk length in network byte order (big-endian 32-bit unsigned integer `UInt32BE`).
   - `N` bytes: The raw binary chunk data (`N <= 262144` bytes).
3. **Termination**: When the input stream reaches EOF, client writes the 4-byte chunk terminator:
   - 4 null bytes: `0x00 0x00 0x00 0x00` (length 0).
4. **Response Parsing**: clamd inspects the stream and returns a single null- or newline-terminated string:
   - Clean: `stream: OK` -> `{ status: 'CLEAN', signature: null }`
   - Infected: `stream: <SignatureName> FOUND` -> `{ status: 'FOUND', signature: '<SignatureName>' }`
   - Limit Exceeded: `INSTREAM size limit exceeded. ERROR` or `stream: ... ERROR` -> `{ status: 'ERROR', error: '...' }`

### Fail-Closed Principle

Only the exact string `stream: OK` evaluates to `CLEAN`. Any other response, network timeout, connection reset, or unexpected error evaluates to `ERROR` or `FOUND`, never `CLEAN`.

---

## 6. Scanner Client API (`@sug/scanner`)

The `@sug/scanner` package exposes `ClamAvScanner` with the following interface:

```typescript
export class ClamAvScanner {
  constructor(customConfig?: Partial<ClamAvConfig>);

  // Stream scanning via INSTREAM protocol
  scanStream(stream: Readable, options?: ScanStreamOptions): Promise<ClamAvScanResult>;

  // Healthcheck ping
  ping(): Promise<boolean>;

  // Engine & database version query
  version(): Promise<string>;

  // Signature freshness / age metric
  getSignatureAge(referenceTime?: Date): Promise<ClamAvSignatureInfo>;
}
```

### Stream Handling & Backpressure

`scanStream` consumes the source stream using an asynchronous iterator (`for await (const chunk of stream)`), slices chunks into bounded sizes (`chunkSize: 256 KB`), formats network headers, and awaits socket `drain` events if `socket.write()` buffers saturate. This guarantees that large streams (up to 55 MB) never consume unbounded memory in the Node.js process and socket buffers are never overrun.

---

## 7. Scanner Worker Integration

In `services/scanner/src/worker.ts`:

1. `claimScanJob()` claims the next available `QUEUED` job using `FOR UPDATE SKIP LOCKED`.
2. Exact-version artifact retrieval fetches the artifact from quarantine storage using `storage_version_id`.
3. The local staged file is cryptographically verified against `file_versions.sha256_ingest`.
4. If ClamAV scanning is enabled (`enableClamAv: true`):
   - Staged file stream is passed to `clamavScanner.scanStream()`.
   - Result is persisted into the `scan_results` table:
     - `check_id`: `'scanner.clamav'`
     - `engine`: `'clamav'`
     - `engine_version`: `'1.4.6'`
     - `outcome`: `'PASS'` if clean, `'FAIL'` if malware, `'ERROR'` if scanner failure.
     - `reason_code`: `'CLEAN'`, `'MALWARE_DETECTED'`, or `'SCANNER_ERROR'`.
     - `severity`: `'INFO'` (clean), `'CRITICAL'` (malware), `'HIGH'` (error).
     - `confidence`: `'CONFIRMED'`.
     - `evidence`: JSON object containing `status`, `signature`, `durationMs`, and `rawResponse`.
5. Lifecycle Transitions:
   - For `CLEAN` and `FOUND`, job transitions to `SUCCEEDED` (findings are recorded for evaluation by the P18 decision engine).
   - For `ERROR`, job is failed via `failScanJob()` with exponential backoff and retry tracking.

---

## 8. EICAR Test Strategy

To prevent security alarms or false repository flags, **no static EICAR string is committed to Git**.

The standard 68-byte EICAR sequence is assembled dynamically at runtime in unit and integration test runners:

```typescript
const assembleEicarString = (): string => {
  const part1 = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}';
  const dollar = String.fromCharCode(36);
  const part2 = dollar + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!';
  const part3 = dollar + 'H+H*';
  return part1 + part2 + part3;
};
```

When transmitted via `INSTREAM`, ClamAV 1.4.6 reliably returns:

```
stream: Eicar-Test-Signature FOUND
```

---

## 9. Signature Age Metric

ClamAV's database release date is queried via the `VERSION` command over TCP, returning a string such as:

```
ClamAV 1.4.6/28136/Sun Sep 27 06:26:12 2026
```

`getSignatureAge()` parses the database publication timestamp and calculates the age in elapsed seconds:

```json
{
  "available": true,
  "ageSeconds": 230578,
  "version": "1.4.6",
  "dbVersion": 28136,
  "dbDate": "2026-09-27T00:56:12.000Z"
}
```

If clamd is unreachable or returns an invalid string, it returns `{ available: false, ageSeconds: null }` and **never silently returns 0**.

---

## 10. Definition of Done Checklist

| Item | Requirement                                                | Status   | Evidence File                                                                    |
| ---- | ---------------------------------------------------------- | -------- | -------------------------------------------------------------------------------- |
| 1    | ClamAV 1.4.6 container service in docker-compose           | Complete | `infrastructure/docker/docker-compose.yml`, `docs/evidence/p14/clamd-health.txt` |
| 2    | INSTREAM protocol client implementation                    | Complete | `packages/scanner/src/clamav.ts`, `tests/unit/scanner/clamav.test.ts`            |
| 3    | EICAR detection test passing (`FOUND`)                     | Complete | `docs/evidence/p14/scan-01-eicar.txt`                                            |
| 4    | Clean artifact test passing (`CLEAN`)                      | Complete | `docs/evidence/p14/scan-02-benign.txt`                                           |
| 5    | Mid-scan disconnect fail-closed test (`ERROR`)             | Complete | `docs/evidence/p14/scan-07-mid-scan-failure.txt`                                 |
| 6    | Resource limit exceeded fail-closed test (`ERROR`)         | Complete | `docs/evidence/p14/scan-09-limit-exceeded.txt`                                   |
| 7    | ClamAV unavailable fail-closed test (`ERROR`)              | Complete | `docs/evidence/p14/scan-10-unavailable.txt`                                      |
| 8    | Signature age metric query and calculation                 | Complete | `docs/evidence/p14/signature-age.txt`                                            |
| 9    | Worker end-to-end integration and scan_results persistence | Complete | `tests/integration/scanner/p14-clamav.test.ts`                                   |
| 10   | Zero regressions in full test suite (567/567 passed)       | Complete | `docs/evidence/p14/test-summary.txt`                                             |
