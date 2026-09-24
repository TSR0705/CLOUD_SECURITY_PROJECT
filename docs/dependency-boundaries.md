# Monorepo Dependency Boundaries & Architectural Segregation

This document specifies the architectural and package boundaries enforced by ESLint 10 (`eslint-plugin-boundaries` v7.2.0) across the Secure Upload Gateway codebase.

---

## 1. Architectural Principles & Layering

The codebase is organized into three strictly segregated tiers:

```
[Apps: apps/*]
      │
      ▼
[Services: services/*] & [Client SDK: packages/sdk]
      │
      ▼
[Domain Packages: packages/*]
      │
      ▼
[Low-Level Foundation: packages/shared]
```

### Dependency Direction Rules

1. **Unidirectional Flow**: Dependencies must flow strictly from high-level orchestrators (`apps`, `services`) downward toward domain packages (`packages/*`), terminating at `@sug/shared`.
2. **Zero Inward Imports**: Domain packages must NEVER import from application or service modules.
3. **No Cross-Service Direct Coupling**: Microservices (`services/api`, `services/scanner`, `services/promotion`, `services/replication`) communicate exclusively through database tables and asynchronous job queues. A service must NEVER directly import the private implementation or source code of another service.
4. **Complete Quarantine of Dashboard**: The Next.js dashboard (`apps/dashboard`) is a Zone 8 (Z8) presentation component. It connects exclusively via HTTP/REST through `@sug/sdk` or `@sug/shared`. It has **ZERO** direct access to storage, database drivers, crypto keys, or scanning engines.

---

## 2. Permitted Dependency Matrix

| From Element              | Permitted Internal Dependencies (`allow`)                             | Explicitly Forbidden Dependencies                     |
| :------------------------ | :-------------------------------------------------------------------- | :---------------------------------------------------- |
| **`pkg-shared`**          | `[]` (None; leaf package)                                             | Any app, service, or other package                    |
| **`pkg-storage`**         | `@sug/shared`                                                         | All services, apps, `pkg-crypto`, `pkg-security`      |
| **`pkg-policy`**          | `@sug/shared`                                                         | All services, apps, storage, scanning                 |
| **`pkg-security`**        | `@sug/shared`                                                         | All services, apps, storage, crypto                   |
| **`pkg-scanner`**         | `@sug/shared`                                                         | All services, apps, promotion, crypto                 |
| **`pkg-decision`**        | `@sug/shared`                                                         | All services, apps, storage, promotion                |
| **`pkg-crypto`**          | `@sug/shared`                                                         | All services, apps, scanner, decision                 |
| **`pkg-audit`**           | `@sug/shared`                                                         | All services, apps, scanner, promotion                |
| **`pkg-sdk`**             | `@sug/shared`                                                         | All services, storage, crypto, decision               |
| **`service-api`**         | `@sug/shared`, `@sug/storage`, `@sug/policy-engine`                   | `service-promotion`, `service-scanner`, `pkg-crypto`  |
| **`service-scanner`**     | `@sug/shared`, `@sug/storage`, `@sug/scanner`, `@sug/security-engine` | `service-promotion`, `service-api`, `pkg-crypto`      |
| **`service-promotion`**   | `@sug/shared`, `@sug/storage`, `@sug/crypto`, `@sug/decision-engine`  | `service-scanner`, `service-api`                      |
| **`service-replication`** | `@sug/shared`, `@sug/storage`                                         | All other services, crypto, scanner                   |
| **`app-dashboard`**       | `@sug/shared`, `@sug/sdk`                                             | `pkg-storage` (DB/S3), `pkg-crypto`, all `services/*` |
| **`app-client`**          | `@sug/shared`, `@sug/sdk`                                             | All internal services, crypto, storage                |

---

## 3. Critical Boundary Violations & Security Rationales

### Violation 1: Dashboard importing Storage or Database (`app-dashboard` $\to$ `pkg-storage`)

- **Why Forbidden**: The dashboard is a public-facing web interface. If the dashboard container is compromised via XSS or SSRF, having direct database connection credentials or S3 access keys enables immediate data exfiltration and tampering.
- **Security Impact**: Breaches Zone 8 isolation; collapses least-privilege architecture.

### Violation 2: Scanner importing Promotion (`service-scanner` $\to$ `service-promotion`)

- **Why Forbidden**: The scanner service parses untrusted, potentially hostile binaries and documents using complex C/C++ libraries (ClamAV, libmagic, sharp). If memory corruption occurs inside the scanner, an attacker must NOT have access to promotional logic, clean storage credentials, or the master Key Encryption Key (KEK).
- **Security Impact**: Breaches Zone 4 isolation; enables malicious payloads to self-promote to clean storage.

### Violation 3: API importing Promotion or Crypto (`service-api` $\to$ `service-promotion` / `pkg-crypto`)

- **Why Forbidden**: The API service resides at the edge (Zone 2). It must only place incoming streams into quarantine storage. The API holds zero credentials to write to clean storage or access the master KEK.
- **Security Impact**: Violates Non-Negotiable Invariants 1 and 2.

### Violation 4: Packages importing Services (`packages/*` $\to$ `services/*`)

- **Why Forbidden**: Introduces circular dependencies, prevents package reusability, and leaks runtime-specific configuration into core cryptographic and mathematical validation logic.
- **Security Impact**: Code contamination and architectural decay.

---

## 4. Automated Enforcement Mechanism

Boundaries are enforced by `eslint-plugin-boundaries` v7.2.0 in `eslint.config.mjs`:

- Elements are mapped using file glob patterns.
- The `boundaries/dependencies` rule enforces `default: 'disallow'` with an explicit allowlist policy per element.
- Any unauthorized import immediately halts the build with exit code 1 in both local development and GitHub Actions CI.
