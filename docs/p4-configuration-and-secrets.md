# P4 Configuration and Secret Management

## 1. Executive Summary

Phase P4 implements the centralized, Zod-validated configuration and secret management foundation for the Secure Upload Gateway (SUG) architecture. It establishes strict schema validation for all operational parameters, supports container file secrets via `/run/secrets/*` with deterministic precedence over development environment variables, prevents startup on missing or malformed secrets, enforces permanent zero-leak redaction in diagnostic logging and errors, and provides cryptographic developer secret generation utilities.

---

## 2. Configuration & Secret Contract

The configuration contract is defined in [`packages/shared/src/config.ts`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/packages/shared/src/config.ts) and exposed via `@sug/shared` and `@sug/shared/config`.

### Configuration Variables & Secrets Matrix

| Parameter / Variable              | Type   | Secret? | Source (Primary / Fallback)                                                    |                 Required?                  | Validation Rules                                                                                   |
| :-------------------------------- | :----- | :-----: | :----------------------------------------------------------------------------- | :----------------------------------------: | :------------------------------------------------------------------------------------------------- |
| `NODE_ENV`                        | String |   No    | Env: `NODE_ENV`                                                                |     Optional (default: `development`)      | `'development' \| 'production' \| 'test'`                                                          |
| `LOG_LEVEL`                       | String |   No    | Env: `LOG_LEVEL`                                                               |         Optional (default: `info`)         | `'trace' \| 'debug' \| 'info' \| 'warn' \| 'error' \| 'fatal'`                                     |
| `PORT`                            | Number |   No    | Env: `PORT`                                                                    |         Optional (default: `3000`)         | Integer between 1 and 65535                                                                        |
| `HOST`                            | String |   No    | Env: `HOST`                                                                    |       Optional (default: `0.0.0.0`)        | Non-empty string                                                                                   |
| `SERVICE_NAME`                    | String |   No    | Env: `SERVICE_NAME`                                                            |       Optional (default: `sug-api`)        | Non-empty string                                                                                   |
| `DATABASE_URL`                    | URL    |   No*   | Env: `DATABASE_URL` or derived                                                 |                  Required                  | Valid `postgres://` or `postgresql://` URI; password redacted in diagnostics                       |
| `POSTGRES_HOST`                   | String |   No    | Env: `POSTGRES_HOST`                                                           |      Optional (default: `127.0.0.1`)       | Hostname or IP address                                                                             |
| `POSTGRES_PORT`                   | Number |   No    | Env: `POSTGRES_PORT`                                                           |     Optional (default: `5432`/`5433`)      | Valid port number                                                                                  |
| `POSTGRES_USER`                   | String |   No    | Env: `POSTGRES_USER`                                                           |      Optional (default: `sug_admin`)       | Non-empty string                                                                                   |
| `POSTGRES_DB`                     | String |   No    | Env: `POSTGRES_DB`                                                             |         Optional (default: `sug`)          | Non-empty string                                                                                   |
| `S3_ENDPOINT`                     | URL    |   No    | Env: `S3_ENDPOINT`                                                             |              Optional in prod              | Valid URL or undefined in prod                                                                     |
| `AWS_REGION`                      | String |   No    | Env: `AWS_REGION`                                                              |      Optional (default: `us-east-1`)       | Non-empty string                                                                                   |
| `S3_QUARANTINE_BUCKET`            | String |   No    | Env: `S3_QUARANTINE_BUCKET`                                                    | Optional (default: `sug-quarantine-local`) | Non-empty string                                                                                   |
| `S3_CLEAN_BUCKET`                 | String |   No    | Env: `S3_CLEAN_BUCKET`                                                         |   Optional (default: `sug-clean-local`)    | Non-empty string                                                                                   |
| `GCS_ENDPOINT`                    | URL    |   No    | Env: `GCS_ENDPOINT`                                                            |              Optional in prod              | Valid URL or undefined in prod                                                                     |
| `GCS_REPLICA_BUCKET`              | String |   No    | Env: `GCS_REPLICA_BUCKET`                                                      |  Optional (default: `sug-replica-local`)   | Non-empty string                                                                                   |
| `GCS_PROJECT_ID`                  | String |   No    | Env: `GCS_PROJECT_ID`                                                          |  Optional (default: `sug-local-project`)   | Non-empty string                                                                                   |
| **`PEPPER`**                      | Secret | **Yes** | `/run/secrets/pepper` $\to$ `SUG_PEPPER`                                       |                  **Yes**                   | Generated as 32 random bytes (64 hex characters = 256-bit entropy); schema enforces $\ge 32$ chars |
| **`KEK`**                         | Secret | **Yes** | `/run/secrets/kek` $\to$ `SUG_KEK`                                             |                  **Yes**                   | 256-bit key: 64 hex characters or 32-byte base64                                                   |
| **`JWT_PRIVATE_KEY`**             | Secret | **Yes** | `/run/secrets/jwt_private_key` $\to$ `SUG_JWT_PRIVATE_KEY`                     |                  **Yes**                   | PKCS#8 PEM Ed25519 private key or raw 32/64-byte key                                               |
| **`CHECKPOINT_PRIVATE_KEY`**      | Secret | **Yes** | `/run/secrets/checkpoint_private_key` $\to$ `SUG_CHECKPOINT_PRIVATE_KEY`       |                  **Yes**                   | PKCS#8 PEM Ed25519 private key or raw 32/64-byte key                                               |
| **`POSTGRES_PASSWORD`**           | Secret | **Yes** | `/run/secrets/db_password` $\to$ `POSTGRES_PASSWORD`                           |          **Yes** (unless in test)          | Non-empty string                                                                                   |
| **`AWS_SECRET_ACCESS_KEY`**       | Secret | **Yes** | `/run/secrets/aws_secret_access_key` $\to$ `AWS_SECRET_ACCESS_KEY`             |           Optional in local dev            | Non-empty string ($\ge 4$ characters); global fallback                                             |
| `AWS_ACCESS_KEY_ID_<SVC>`         | String |   No    | Env: `AWS_ACCESS_KEY_ID_<SVC>`                                                 |             Optional override              | Per-service S3 Access Key ID (`API`, `SCANNER`, `PROMOTER`, `REPLICATOR`)                          |
| **`AWS_SECRET_ACCESS_KEY_<SVC>`** | Secret | **Yes** | `/run/secrets/aws_secret_access_key_<svc>` $\to$ `AWS_SECRET_ACCESS_KEY_<SVC>` |             Optional override              | Per-service S3 Secret Access Key; falls back to global key                                         |

---

## 3. Secret Resolution & Precedence Architecture

The secret resolver `resolveSecret(...)` enforces strict multi-source resolution:

```
┌────────────────────────────────────────────────────────┐
│               Secret Resolution Order                  │
├────────────────────────────────────────────────────────┤
│ 1. Docker File Secret (/run/secrets/<secret_name>)     │
│    • Checked first                                     │
│    • Rejects empty files immediately                   │
│    • Takes ABSOLUTE PRECEDENCE over environment vars   │
├────────────────────────────────────────────────────────┤
│ 2. Environment Variable Fallback (Local Dev Only)      │
│    • Evaluated ONLY IF the file secret does not exist  │
│    • Rejects empty environment variables               │
├────────────────────────────────────────────────────────┤
│ 3. Missing Handler                                     │
│    • Aborts startup via ConfigurationError             │
└────────────────────────────────────────────────────────┘
```

### Precedence Invariants

- An environment variable **CANNOT** override an existing Docker file secret. If `/run/secrets/pepper` exists, its value is used regardless of what is set in `SUG_PEPPER` or `PEPPER`.
- Empty secrets (files containing only whitespace or empty environment variables) are explicitly detected and cause immediate startup abort with `secret file is empty` or `secret environment variable is empty`.

### Per-Service Storage Credential Slots (Least Privilege)

To enforce isolation between architectural trust zones (ADR 0001 / ADR 0010), `config.storage.services` and `config.secrets.services` provide distinct credential slots:

- `api`: Ingestion service (writes to quarantine bucket).
- `scanner`: Analysis engines (read-only on quarantine bucket).
- `promoter`: File promotion engine (reads quarantine, writes to clean).
- `replicator`: Cloud replication engine (reads clean, writes to GCS replica).

Each service resolves credentials through:

1. Container file secret: `/run/secrets/aws_secret_access_key_<svc>`
2. Environment variables: `AWS_ACCESS_KEY_ID_<SVC>` and `AWS_SECRET_ACCESS_KEY_<SVC>`
3. Global storage credentials fallback: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

The helper function `getServiceStorageCredentials(config, serviceName)` resolves the effective credentials for any given service.

---

## 4. Redaction & Zero-Leak Diagnostics

To prevent sensitive material from leaking into monitoring, application logs, bug tracking tools, or core dumps:

1. **`redactConfig(config)`**:
   - Returns a cloned configuration where all fields in `config.secrets` (including base secrets and any per-service `secrets.services.<svc>.secretAccessKey`) are replaced with `'[REDACTED]'`.
   - Strips the password from `database.url` (e.g. `postgres://sug_admin:[REDACTED]@localhost:5433/sug`).
2. **`config.toRedacted()`**:
   - Instance method returning the sanitized configuration view.
3. **`config[util.inspect.custom]()`**:
   - Overrides Node.js inspection so `console.log(config)` and `util.inspect(config)` output only redacted data.
4. **`config.toJSON()`**:
   - Overrides JSON serialization so `JSON.stringify(config)` outputs only redacted data.
5. **`ConfigurationError` Safety**:
   - Error messages list strictly the parameter key name and the reason (e.g., `- KEK: required secret is missing`).
   - The error object and message **never** print attempted or existing secret values.

---

## 5. Local Secret Generation (`scripts/gen-secrets.sh`)

Developers generate local development secrets using [`scripts/gen-secrets.sh`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/scripts/gen-secrets.sh):

```bash
bash scripts/gen-secrets.sh [target_directory]
```

### Script Invariants

- Written in POSIX/Bash with `set -euo pipefail`.
- Uses `openssl` if available, falling back automatically to Node.js `crypto` module.
- Generates:
  - `pepper`: 32 random bytes (64 hex characters).
  - `kek`: 32 random bytes (64 hex characters) for AES-256 KeyWrap.
  - `jwt_private_key.pem` & `jwt_public_key.pem`: Ed25519 keypair.
  - `checkpoint_private_key.pem` & `checkpoint_public_key.pem`: Ed25519 keypair.
  - `db_password`: 24 random bytes (hex).
  - `aws_secret_access_key`: 30 random bytes (base64).
- Enforces filesystem permissions: `chmod 700` on the secrets directory and `chmod 600` on generated secret files.
- **Never logs secret values to stdout/stderr.** Outputs only `Generated local development secrets under <dir>`.

---

## 6. Docker Secret Integration

In containerized deployments, secrets are mounted via Docker Secrets:

- Secrets are declared under `secrets:` in [`infrastructure/docker/docker-compose.yml`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/infrastructure/docker/docker-compose.yml), mapping host files to `/run/secrets/<name>` inside containers.
- **Image Hygiene Invariants**:
  - Secrets are **NEVER** copied into Docker images via `COPY`.
  - Secrets are **NEVER** passed as build arguments (`ARG`).
  - Secrets are **NEVER** set as image environment variables (`ENV`).
  - Secrets are mounted strictly at container runtime as read-only files.

---

## 7. Version Control & Secret Hygiene

The repository enforces strict exclusion of secret material:

- [`.gitignore`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/.gitignore) explicitly ignores:
  - `secrets/`
  - `.env` and `.env.*` (preserving only [`.env.example`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/.env.example))
  - `*.pem`, `*.key`, `*.cert`, `*.crt`
- Automated Gitleaks scanning runs in CI and pre-commit checks:
  ```bash
  docker run --rm -v "${PWD}:/path" zricethezav/gitleaks:latest detect --source="/path" -v
  ```
- **`.gitleaksignore` Policy**:
  - Broad glob patterns (`*.ts`, `src/**`) or directory-level suppressions are **strictly prohibited**.
  - Entries are restricted exclusively to pinpointed line/rule fingerprints in local development template files (`.env`).
  - Source code, production configuration, and tests must never be exempted from secret scanning.
- [`.env.example`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/.env.example) contains only placeholders and documentation, with zero real secret values.

---

## 8. Rotation Strategy

- **Master KEK**: Wrapped DEKs inside `SUG1` envelopes allow rotating the master KEK without re-encrypting underlying file payloads (re-wrap phase).
- **JWT Key**: Ed25519 key rotation utilizes distinct key IDs (`kid` header); verification accepts current and transition keys.
- **Pepper**: Salt/pepper rotation requires rehashing existing API keys via database migration.
