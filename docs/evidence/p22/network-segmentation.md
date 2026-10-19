# Phase P22: Docker Network Segmentation & Container Hardening

## 1. Network Segmentation Topology

In accordance with **ADR-0004**, the Docker Compose infrastructure divides communication into strictly isolated network planes. Host port bindings for local development and testing are restricted to the local loopback interface (`127.0.0.1`), and the security-critical `sug-scanner` container is confined exclusively to an internal network (`internal: true`) without external routes.

```
                   [ Host / Local Developer (127.0.0.1) ]
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            │ :5432                   │ :4566                   │ :3310
            ▼                         ▼                         ▼
    ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
    │     data     │          │    store     │          │     scan     │ (INTERNAL ONLY)
    │  (sug-data)  │          │ (sug-store)  │          │  (sug-scan)  │ (internal: true)
    └──────┬───────┘          └──────┬───────┘          └──────┬───────┘
           │                         │                         │
           ├─► sug-postgres ◄────────┼─────────────────────────┤
           │                         │                         │
           │                         ├─► sug-localstack ◄──────┤
           │                         │                         │
           │                         └─► sug-fake-gcs          │
           │                                                   │
           ├─► sug-clamav ◄────────────────────────────────────┤
           │                                                   │
           │                                                   └─► sug-scanner
           │                                                       (Zero external egress)
```

### Network Definitions in `infrastructure/docker/docker-compose.yml`

```yaml
networks:
  edge:
    name: sug-edge
    driver: bridge
  data:
    name: sug-data
    driver: bridge
  store:
    name: sug-store
    driver: bridge
  scan:
    name: sug-scan
    driver: bridge
    internal: true
  egress:
    name: sug-egress
    driver: bridge
```

---

## 2. Container Network Attachments & Trust Boundaries

| Container            | Purpose                                       | Attached Networks | Loopback Published Port | Isolated From                               |
| :------------------- | :-------------------------------------------- | :---------------- | :---------------------- | :------------------------------------------ |
| **`sug-postgres`**   | Primary relational database                   | `data`, `scan`    | `127.0.0.1:5432`        | `edge`, `egress`                            |
| **`sug-localstack`** | Local S3 emulation (quarantine, clean, audit) | `store`, `scan`   | `127.0.0.1:4566`        | `edge`, `egress`                            |
| **`sug-fake-gcs`**   | Local GCS JSON API emulation (replica)        | `store`           | `127.0.0.1:4443`        | `edge`, `scan`, `egress`                    |
| **`sug-clamav`**     | Antivirus scanning daemon                     | `scan`, `data`    | `127.0.0.1:3310`        | `store`, `edge`, `egress`                   |
| **`sug-scanner`**    | Security analysis background worker           | `scan`            | None (internal only)    | `data`, `store`, `edge`, `egress`, Internet |

### Key Isolation Guarantees:

1. **Scanner Complete Network Isolation (`internal: true`)**: `sug-scanner` is attached **strictly** to `scan`. Because `scan` is marked `internal: true` and `scanner` has no attachments to non-internal networks (`data`, `store`, `edge`, or `egress`), Docker creates no default gateway route on the container. External IP routing and DNS lookups fail fail-closed (`ENETUNREACH`, `EAI_AGAIN`).
2. **ClamAV Removed from Edge & Loopback Bound**: `clamav` has been completely removed from the perimeter `edge` network. It is attached to `scan` for internal communication with `sug-scanner`, and multi-homed to `data` strictly so the Docker daemon can establish host port forwarding for `127.0.0.1:3310` to satisfy local integration test suites (`tests/integration/scanner/p14-clamav.test.ts`). (Docker suppresses host port publishing on containers attached exclusively to `internal: true` networks). Public interface exposure is eliminated.
3. **Loopback-Only Host Bindings**: All host port mappings are explicitly bound to `127.0.0.1`, preventing public network interface exposure on the developer workstation.
4. **Internal Service Reachability**: `postgres` and `localstack` are multi-homed on `scan` so `sug-scanner` can query the database and read quarantine objects over the internal bridge, while remaining reachable from host test suites via `127.0.0.1`.

---

## 3. Scanner Container Hardening Configuration

The scanner worker is hardened using defense-in-depth container runtime constraints in `docker-compose.yml`:

```yaml
scanner:
  build:
    context: ../../
    dockerfile: services/scanner/Dockerfile
  container_name: sug-scanner
  restart: unless-stopped
  read_only: true
  user: '1000:1000'
  cap_drop:
    - ALL
  security_opt:
    - 'no-new-privileges:true'
  tmpfs:
    - /tmp:rw,noexec,nosuid,size=128M
  networks:
    - scan
  secrets:
    - aws_secret_access_key_scanner
    - db_password
  environment:
    NODE_ENV: production
    SERVICE_NAME: sug-scanner
    POSTGRES_HOST: postgres
    POSTGRES_PORT: 5432
    POSTGRES_USER: sug_scanner
    POSTGRES_DB: sug
    S3_ENDPOINT: http://localstack:4566
    AWS_ACCESS_KEY_ID_SCANNER: sug-scanner-key
    CLAMAV_HOST: clamav
    CLAMAV_PORT: 3310
  healthcheck:
    test: ['CMD', 'curl', '-f', 'http://127.0.0.1:3001/health']
    interval: 10s
    timeout: 5s
    retries: 10
    start_period: 15s
```

---

## 4. Live Verification Results on Actual `sug-scanner` Container

All verification checks are executed **directly against the live running `sug-scanner` container**:

### Test 1: External Internet Egress Block (Direct IP)

- **Command**: `docker exec sug-scanner node -e "fetch('http://1.1.1.1', { signal: AbortSignal.timeout(1500) })"`
- **Result**: `BLOCKED: ENETUNREACH` (Network is unreachable — zero gateway routing).

### Test 2: External DNS Resolution Block

- **Command**: `docker exec sug-scanner node -e "fetch('http://example.com', { signal: AbortSignal.timeout(1500) })"`
- **Result**: `BLOCKED: EAI_AGAIN` (No external nameserver resolution).

### Test 3: Required Internal Dependency Connectivity

- **Postgres (5432)**: `docker exec sug-scanner node -e "const net=require('net'); net.connect(5432, 'postgres', () => console.log('PG_OK'))"` -> `PG_OK`
- **ClamAV (3310)**: `docker exec sug-scanner node -e "const net=require('net'); net.connect(3310, 'clamav', () => console.log('CLAM_OK'))"` -> `CLAM_OK`
- **LocalStack S3 (4566)**: `docker exec sug-scanner node -e "fetch('http://localstack:4566/_localstack/health').then(() => console.log('S3_OK'))"` -> `S3_OK`

### Test 4: Filesystem Immutability

- **Root Filesystem**: Writing to `/root-test.txt` fails with `RO_BLOCKED: EROFS`.
- **Ephemeral Mount**: Writing to `/tmp/health-test.txt` succeeds (`TMP_OK: pass`).

### Test 5: Non-Root Execution and Dropped Capabilities

- **UID / GID**: `UID: 1000`, `GID: 1000`.
- **Linux Capabilities**: `CapEff: 0000000000000000` (all 5 capability bitmasks fully cleared).
- **Healthcheck**: Verified passing via `curl -f http://127.0.0.1:3001/health` returning `{"status":"ok","workerRunning":true,"clamav":true}`.
