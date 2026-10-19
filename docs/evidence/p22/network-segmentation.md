# Phase P22: Docker Network Segmentation & Container Hardening

## 1. Network Segmentation Topology

As specified in **ADR-0004**, the Docker Compose infrastructure divides communication into five distinct network planes to prevent lateral movement and enforce defense-in-depth:

```
                        [ External Ingress ]
                                 │
                                 ▼
                         ┌──────────────┐
                         │     edge     │ (Public Ingress Network)
                         └──────┬───────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │ (Edge API)            │                       │
        ▼                       │                       │
┌──────────────┐                │                       │
│     data     │ (Database)     │                       │
└──────┬───────┘                │                       │
       │                        │                       │
       ├─► sug-postgres         │                       │
       ├─► sug-scanner          │                       │
       └─► sug-promoter         │                       │
                                ▼                       │
                        ┌──────────────┐                │
                        │    store     │ (Storage)      │
                        └──────┬───────┘                │
                               ├─► sug-localstack       │
                               ├─► sug-fake-gcs         │
                               ├─► sug-scanner          │
                               └─► sug-promoter         │
                                                        ▼
                                                ┌──────────────┐
                                                │     scan     │ (INTERNAL ONLY)
                                                └──────┬───────┘
                                                       │ (internal: true)
                                                       ├─► sug-scanner
                                                       └─► sug-clamav
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

| Container            | Purpose                                       | Attached Networks       | Isolated From             |
| :------------------- | :-------------------------------------------- | :---------------------- | :------------------------ |
| **`sug-postgres`**   | Primary relational database                   | `data`                  | `edge`, `scan`, `egress`  |
| **`sug-localstack`** | Local S3 emulation (quarantine, clean, audit) | `store`                 | `edge`, `scan`, `egress`  |
| **`sug-fake-gcs`**   | Local GCS JSON API emulation (replica)        | `store`                 | `edge`, `scan`, `egress`  |
| **`sug-clamav`**     | Antivirus scanning daemon                     | `scan`, `edge`          | `data`, `store`, `egress` |
| **`sug-scanner`**    | Security analysis background worker           | `data`, `store`, `scan` | `edge`, `egress`          |

### Key Isolation Guarantees:

1. **Public DB Inaccessibility**: Database (`sug-postgres`) is attached solely to `data`; it cannot be reached from `edge` or `scan`.
2. **Scanner Network Confinement**: `sug-scanner` is attached to `data`, `store`, and `scan`. It is strictly excluded from `edge` and `egress`.
3. **Internal Scan Plane (`internal: true`)**: The `sug-scan` network explicitly disallows default gateways and routing to public IP addresses or external DNS.

---

## 3. Scanner Container Hardening Configuration

The scanner worker is hardened using defense-in-depth container runtime constraints:

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
    - data
    - store
    - scan
  secrets:
    - aws_secret_access_key_scanner
    - db_password
```

---

## 4. Live Verification Results

Dynamic container isolation was verified against the Docker engine:

### Test 1: External Internet Egress Block

Attempting to connect to public IP `1.1.1.1` from inside `sug-scan` network:

- **Command**: `docker run --rm --network sug-scan node:24-bookworm-slim node -e "fetch('http://1.1.1.1')"`
- **Result**: `BLOCKED: ENETUNREACH` (Network is unreachable).
- **DNS Lookup**: `BLOCKED: EAI_AGAIN` (No external resolver).

### Test 2: Read-Only Root Filesystem

Attempting to write to root filesystem:

- **Command**: `docker run --rm --read-only --user 1000:1000 --tmpfs /tmp node:24-bookworm-slim node -e "fs.writeFileSync('/evil.txt', 'x')"`
- **Result**: `RO_BLOCKED: EROFS` (Read-only file system).
- **Temporary Mount**: Writing to `/tmp/ok.txt` succeeded (`TMPFS_WRITABLE: ok`).

### Test 3: Non-Root Execution

Inspecting effective UID and GID:

- **Command**: `docker run --rm --user 1000:1000 node:24-bookworm-slim node -e "console.log(process.getuid())"`
- **Result**: `UID: 1000`, `GID: 1000`.

### Test 4: Linux Capabilities Dropped

Inspecting capability bitmasks from `/proc/1/status`:

- **Result**:
  - `CapInh: 0000000000000000`
  - `CapPrm: 0000000000000000`
  - `CapEff: 0000000000000000`
  - `CapBnd: 0000000000000000`
  - `CapAmb: 0000000000000000`
