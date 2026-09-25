# Phase P5 — Fastify API Foundation, Health & Readiness

## 1. Executive Summary

Phase P5 establishes the production-grade HTTP edge API foundation for the Secure Upload Gateway (SUG) using **Fastify 5.12**. It implements an in-memory testable application factory, injection-safe request correlation ID tracking, RFC 7807 / RFC 9457 `application/problem+json` error responses with zero-leak sanitization, defensive security headers via `@fastify/helmet`, in-memory rate limiting with health endpoint exemptions via `@fastify/rate-limit`, deterministic OpenAPI 3.0 specification generation via `@fastify/swagger`, a zero-I/O liveness probe (`GET /healthz`), and a multi-dependency readiness probe (`GET /readyz`) aggregating PostgreSQL 18 and S3/LocalStack reachability with strict bounded timeouts.

---

## 2. Fastify Application Architecture

The API service is located in `services/api` (`@sug/api`) and is structured to ensure complete decoupling between application initialization and network socket binding:

```
services/api/
├── src/
│   ├── app.ts              # Fastify application factory (createApp)
│   ├── server.ts           # Standalone HTTP server entrypoint (startServer)
│   ├── index.ts            # Public library exports for the package
│   ├── errors/
│   │   └── problem.ts      # RFC 7807/9457 Problem Details model & error handlers
│   ├── health/
│   │   ├── types.ts        # Readiness interfaces & response types
│   │   ├── database.ts     # Bounded non-mutating PostgreSQL readiness check
│   │   └── storage.ts      # Bounded non-mutating S3/LocalStack readiness check
│   └── routes/
│       └── health.ts       # Route plugin for /healthz and /readyz
└── package.json
```

### Application Factory (`createApp`)

- Signature: `createApp(options?: AppOptions): Promise<FastifyInstance>`
- Decouples server lifecycle from network listeners. Tests invoke endpoints entirely in memory via `app.inject()` without opening network sockets or competing for TCP ports.
- Supports dependency injection for `config`, `db` (`ReadinessDatabase`), and `storage` (`ReadinessStorage`), enabling unit tests to simulate timeout, degraded, or transient dependency failure modes without physical network dependencies.
- Binds clean shutdown hooks (`onClose`) ensuring database connection pools and AWS SDK clients are gracefully destroyed upon application closure.

### Server Entrypoint (`startServer`)

- Reads validated configuration through the Phase P4 configuration loader (`@sug/shared/config`).
- Binds to `config.port` (default `3000`) and `config.host` (default `0.0.0.0`).
- Registers process listeners on `SIGTERM` and `SIGINT` to trigger asynchronous graceful draining and server shutdown (`await app.close()`).

---

## 3. Request Correlation ID Policy

Every HTTP interaction with the gateway is assigned a unique, immutable request correlation ID:

1. **Header Name**: `X-Request-ID` (case-insensitive in incoming requests, canonically emitted on outgoing responses).
2. **Security & Validation Rules**:
   - Fastify's native automatic header adoption is disabled (`requestIdHeader: false`) so all incoming IDs are strictly routed through custom validator [`resolveRequestId`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/services/api/src/app.ts#L30-L45).
   - Length constraint: Must be between 1 and 64 ASCII characters.
   - Character whitelist: Alphanumeric characters, hyphens, and underscores only (`^[a-zA-Z0-9_-]{1,64}$`).
   - Injection Defense: Incoming values containing spaces, newlines (`\r`, `\n`), control characters, or non-whitelisted symbols are discarded immediately to protect against CRLF log injection and HTTP response splitting.
3. **Fallback Generation**: If the incoming header is absent, oversized, or fails the character whitelist, a cryptographically secure UUID (`crypto.randomUUID()`) is generated.
4. **Propagation**: Attached to the Fastify request context (`request.id`), propagated to all response headers via an `onSend` hook, and embedded into structured problem error payloads.

---

## 4. RFC 7807 / RFC 9457 Problem Details Error Model

All error responses strictly adhere to the IETF Problem Details standard using `Content-Type: application/problem+json; charset=utf-8`.

### Response Schema

```json
{
  "type": "urn:sug:error:not-found",
  "title": "Not Found",
  "status": 404,
  "detail": "The requested route '/unknown-route' does not exist",
  "instance": "/unknown-route",
  "requestId": "92f7c00e-6f81-42b7-a359-bb5eb4351a94"
}
```

### Deterministic Error Type Mappings

| HTTP Status | Type URN                           | Default Title           | Scenario                                          |
| :---------: | :--------------------------------- | :---------------------- | :------------------------------------------------ |
|   **400**   | `urn:sug:error:validation`         | `Validation Error`      | Request body, header, or query validation failure |
|   **404**   | `urn:sug:error:not-found`          | `Not Found`             | Unmatched route or non-existent resource path     |
|   **405**   | `urn:sug:error:method-not-allowed` | `Method Not Allowed`    | Unsupported HTTP verb                             |
|   **429**   | `urn:sug:error:rate-limit`         | `Too Many Requests`     | Exceeded rate limit bucket                        |
|   **500**   | `urn:sug:error:internal`           | `Internal Server Error` | Unexpected unhandled exceptions                   |

### Zero-Leakage Sanitization Invariant

To prevent information disclosure in all deployment tiers (development, testing, and production):

- Unhandled 500 errors are masked with the static string: `"An internal server error occurred"`.
- Stack traces are **never** returned to callers.
- Database connection strings, SQL statements, AWS credentials, Docker secret paths, and operating system filesystem paths are stripped and sanitized via regex boundary filters before serialization.

---

## 5. Security Middleware

### Security Headers (`@fastify/helmet`)

Registered with secure defaults optimized for REST APIs:

- `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing attacks.
- `X-Frame-Options: DENY`: Mitigates clickjacking attacks.
- `Strict-Transport-Security`: Enforces HTTPS transport.
- Content Security Policy (CSP) is explicitly disabled on pure API endpoints to prevent interfering with programmatic consumers, Next.js frontend route handlers, or client applications fetching JSON data.

### In-Memory Rate Limiting (`@fastify/rate-limit`)

- Configured with a default threshold of 100 requests per minute per IP address in production, and custom configurable ceilings for automated integration testing.
- Uses Fastify's local in-memory store; does NOT introduce distributed complexity (e.g. Redis) during Phase P5.
- Emits standard rate limiting headers: `x-ratelimit-limit`, `x-ratelimit-remaining`, and `x-ratelimit-reset`.
- Exceeding the threshold immediately yields HTTP 429 with RFC problem details (`urn:sug:error:rate-limit`).
- **Health Exemption Rule**: The `allowList` hook explicitly bypasses `/healthz` and `/readyz` so infrastructure monitors, Docker healthchecks, and Kubernetes probes are never throttled during traffic bursts.

---

## 6. Health & Readiness Probes

### Liveness Probe (`GET /healthz`)

- **Semantics**: Answers whether the Node.js event loop and Fastify process are running and capable of processing HTTP cycles.
- **Dependencies**: Performs **zero I/O**. It does NOT query PostgreSQL, S3, or any network dependency.
- **Response**: Immediate `HTTP 200` with payload:
  ```json
  {
    "status": "ok"
  }
  ```

### Readiness Probe (`GET /readyz`)

- **Semantics**: Answers whether the gateway is ready to accept and route production traffic.
- **Dependencies Aggregated**:
  1. **PostgreSQL 18 Database**: Verifies pool reachability by executing `SELECT 1` with a strict 2000ms query timeout via [`PostgresReadinessCheck`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/services/api/src/health/database.ts). Connections are released immediately in a `finally` block to prevent pool starvation.
  2. **Storage Subsystem (S3 / LocalStack)**: Verifies S3 reachability by dispatching a non-mutating `HeadBucketCommand` against the quarantine bucket (`sug-quarantine-local`) with a strict 2000ms timeout via [`S3ReadinessCheck`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/services/api/src/health/storage.ts).
- **Aggregation Logic**:
  - `DB Reachable` + `Storage Reachable` $\to$ **`HTTP 200`** `{ "status": "ready" }`
  - `DB Down` OR `Storage Down` OR `Timeout` $\to$ **`HTTP 503`** `{ "status": "not_ready" }`
- **Zero Information Disclosure Invariant**:
  The 503 response body contains strictly `{ "status": "not_ready" }`. It deliberately suppresses underlying stack traces, database IP addresses, ports, driver errors, or bucket names. Diagnostics are safely routed to internal warning logs without leaking credentials or infrastructure topology.

---

## 7. OpenAPI 3.0 Documentation & CI Validation

- Generated via `@fastify/swagger` using standard OpenAPI 3.0.3 specification rules.
- Output location: [`docs/openapi.json`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/docs/openapi.json).
- Includes full schema documentation for:
  - `GET /healthz` (200 OK)
  - `GET /readyz` (200 Ready, 503 Not Ready)
  - Components: `ProblemDetails` schema, `X-Request-ID` header.
- Does NOT document future APIs (P6+ endpoints) as they do not exist yet.
- **CI Validation**:
  - The script [`scripts/generate-openapi.mjs`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/scripts/generate-openapi.mjs) runs in check mode (`pnpm openapi:check`) in GitHub Actions CI prior to integration tests. If route schemas change without updating `docs/openapi.json`, CI fails immediately.

---

## 8. Development & Testing Commands

```bash
# 1. Start local Docker Compose emulators (PostgreSQL 18, LocalStack, fake-GCS)
docker compose -f infrastructure/docker/docker-compose.yml up -d --wait

# 2. Generate local secrets
bash scripts/gen-secrets.sh

# 3. Generate or validate OpenAPI documentation
corepack pnpm openapi:generate
corepack pnpm openapi:check

# 4. Run full test suite (Unit & Live Integration)
corepack pnpm test

# 5. Build packages
corepack pnpm build
```

---

## 9. Scope Boundary & Phase Invariants

### Strictly Excluded in Phase P5

The following functionality is intentionally deferred to subsequent phases according to the Build Plan:

- **P6**: Application registration, client API key hashing, HMAC verification.
- **P7**: User management, database authentication, Ed25519 JWT verification, RBAC permissions.
- **P8**: Security policies, upload sessions, upload tokens.
- **P9**: Complete `StorageProvider` abstraction, multipart upload coordination.
- **P10**: Streaming file upload pipeline, in-memory SHA-256 tee hashing, byte-budget ceilings.
- **P11+**: Multi-engine antivirus scanning (ClamAV), YARA inspection, asynchronous worker queue, cloud replication, management dashboard.
