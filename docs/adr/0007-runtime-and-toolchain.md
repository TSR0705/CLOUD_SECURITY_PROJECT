# ADR 0007: Runtime Baseline, Toolchain, and Package Management

## Status
APPROVED (DEC-007, DEC-008, DEC-022, DEC-006, OPEN-4)

## Context
A mission-critical security codebase requires reproducible builds, strict type safety, strict architectural boundaries preventing cross-service code contamination, and modern testing frameworks. Tooling drift across Node.js versions, package managers, and TypeScript compilers introduces subtle bugs and security vulnerabilities.

The build plan establishes specific verified baselines as of late 2026.

## Decision
We freeze the following core runtime and developer toolchain:

1. **Runtime**:
   - **Node.js 24 LTS** (`node:24-alpine` for container images). Node 24 is the active LTS line supported through April 2028.
2. **Package Manager**:
   - **pnpm 12** as the monorepo package manager (using pnpm workspaces). Corepack or explicit pnpm installation in Dockerfiles ensures deterministic lockfile resolution.
3. **Language**:
   - **TypeScript pinned to 6.0.3**. (TypeScript 7 is avoided because it currently lacks programmatic AST compiler APIs required by linting plugins).
   - Strict TypeScript compiler flags: `strict: true`, `noImplicitAny: true`, `exactOptionalPropertyTypes: true`.
4. **Code Quality and Linting**:
   - **ESLint 10** using flat configuration (`eslint.config.js`).
   - `typescript-eslint 8.70.1`.
   - `eslint-plugin-boundaries 7.2.0` to enforce architectural boundaries between packages and services (e.g., forbidding `services/api` from importing internal modules of `services/promotion`).
5. **Testing Framework**:
   - **Vitest 5.0.x** for unit, integration, and property-based testing.
   - `k6 2.2` for load and stress testing.
6. **Metrics**:
   - **`@prometheus-io/client 0.16.x`** (replaces deprecated `prom-client 15.x`).
7. **Development Environment (OPEN-4)**:
   - Windows 11 host with Docker Desktop and WSL 2 backend.
   - `.gitattributes` enforcing LF line endings across all files to prevent Windows CRLF corruption in Linux containers.

## Alternatives Considered
- **npm / yarn**: Slower installation times, higher disk usage, and less strict symlink isolation compared to pnpm workspaces.
- **Jest**: Slower ESM execution, complex configuration with modern TypeScript compared to native Vite/Vitest.
- **prom-client**: Deprecated on npm in favor of the official `@prometheus-io/client`.

## Security Impact
- Monorepo boundaries (`eslint-plugin-boundaries`) prevent accidental leaking of internal service logic, credentials, or DB clients across zones.
- Dependency scanning via `pnpm audit --prod` and container scanning via Trivy.

## Cost Impact
Zero cost. All toolchain components are open source (MIT/Apache-2.0).

## Research Impact
Ensures that all benchmarks, latency measurements, and experiment test suites are completely reproducible across developer workstations and CI runners.

## Consequences
- Developers must use Node 24 LTS and pnpm.
- Docker containers must be built from verified Alpine base digests.

## Evidence & Source References
- Build Plan: Part 1.2 (DEC-006, DEC-007, DEC-008, DEC-022), Part 3.1 (Runtime and Tooling Verification Matrix).
- npm registry deprecation notice for `prom-client`.
- TypeScript 7.0 announcement and typescript-eslint compatibility matrix.
