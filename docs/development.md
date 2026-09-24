# Local Development & Engineering Guide

This document outlines the local developer environment, required toolchains, package management, and validation workflows for the Secure Upload Gateway (SUG).

---

## 1. Prerequisites & Toolchain Baseline

The gateway development environment is pinned to specific toolchain versions (see [ADR 0007](adr/0007-runtime-and-toolchain.md)):

- **Node.js**: `24.x LTS` (Verified: `v24.14.0`)
- **Package Manager**: `pnpm 12.5.x` (Pinned via `"packageManager": "pnpm@12.5.1"`)
- **Corepack**: Bundled with Node 24 (`corepack enable pnpm` or `corepack pnpm <command>`)
- **TypeScript**: `6.0.3` (Pinned base compiler)
- **OS / Container Runtime**: Windows 11 with WSL 2 and Docker Desktop (see [ADR 0003](adr/0003-local-storage-emulation.md))

---

## 2. Getting Started

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/TSR0705/CLOUD_SECURITY_PROJECT.git
cd CLOUD_SECURITY_PROJECT

# Install all workspace dependencies reproducibly
corepack pnpm install --frozen-lockfile
```

---

## 3. Developer Workflows & Commands

All development commands are unified at the monorepo root:

| Command                      | Action              | Description                                                                               |
| :--------------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| `corepack pnpm lint`         | ESLint 10           | Validates TypeScript linting and architectural boundaries via `eslint-plugin-boundaries`. |
| `corepack pnpm typecheck`    | TypeScript Compiler | Typechecks all 16 workspace projects using project references (`tsc -b`).                 |
| `corepack pnpm test`         | Vitest 5            | Executes unit and workspace invariant test suites.                                        |
| `corepack pnpm format:check` | Prettier Check      | Verifies that all files conform to repository formatting standards.                       |
| `corepack pnpm format`       | Prettier Fix        | Formats all code, markdown, and configuration files.                                      |
| `corepack pnpm build`        | Build               | Compiles all packages into their respective `dist/` directories (`tsc -b`).               |

---

## 4. Architectural Boundaries

All workspace packages and services are governed by strict boundary rules enforced in CI.

- Services cannot import other services directly.
- The dashboard cannot import database, storage, or security-engine modules.
- Refer to [Dependency Boundaries Specification](dependency-boundaries.md) and [ADR 0004](adr/0004-service-privilege-separation.md) for complete details.

---

## 5. Continuous Integration (CI)

Every pull request and push to `main` triggers GitHub Actions (`.github/workflows/ci.yml`), executing:

1. `corepack pnpm install --frozen-lockfile`
2. `corepack pnpm lint`
3. `corepack pnpm typecheck`
4. `corepack pnpm test`
5. `corepack pnpm format:check`
6. `gitleaks` secret detection scan
