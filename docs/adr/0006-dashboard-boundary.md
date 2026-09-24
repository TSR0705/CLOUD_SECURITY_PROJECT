# ADR 0006: Dashboard Architectural Boundary and Zero-Secret Frontend

## Status
APPROVED (DEC-004)

## Context
A security gateway requires an administrative and analytical interface for security analysts to review quarantined files, inspect scan results, configure security policies, audit cryptographic hash chains, and manage application API keys.

In many architectures, administrative web dashboards suffer from architectural boundary collapse: the web backend connects directly to the production database, evaluates authorization rules independently, or holds master encryption and cloud storage credentials. If the frontend server or framework suffers from a Server-Side Request Forgery (SSRF) or Remote Code Execution (RCE) vulnerability, the attacker gains direct access to storage and database layers.

## Decision
We deploy the dashboard as an isolated **Next.js 16** application (`apps/dashboard`) governed by strict architectural boundaries:
1. **Zero Database Access**: The Next.js dashboard container has NO database connection pool, NO database driver, and NO network connectivity to PostgreSQL port 5432.
2. **Zero Storage Credentials**: The dashboard container possesses NO AWS credentials, NO GCP credentials, and NO Key Encryption Key (KEK) material.
3. **Pure API Mediation**: All dashboard operations occur via HTTPS calls to the Fastify API (`services/api`). Next.js Route Handlers act strictly as reverse proxies forwarding the user's signed JWT bearer token.
4. **No Security Logic in UI**: Decision logic, file validation, signature evaluations, and policy enforcement are executed exclusively by the backend services. The UI displays evidence and triggers authenticated API endpoints.
5. **Modern Frontend Stack**: Built using Next.js 16 (App Router, Turbopack, TypeScript pinned to 6.0.3, Tailwind CSS v4, and shadcn/ui components).
6. **Isolated Docker Image**: The dashboard image contains only client assets and the minimal Next.js standalone runner. Environment secrets are strictly banned from client bundles; gitleaks scans prevent credential inclusion.

## Alternatives Considered
- **React + Vite Static SPA (Original Spec)**: Avoided running a Node.js server for the frontend, serving pure static files. While minimal, Next.js was selected to provide robust server-rendered shells, streaming UI for large audit logs, and simplified reverse-proxying of authenticated API calls.
- **Unified Monolith (Fastify Serving Frontend)**: Coupling Fastify with SSR/frontend rendering breaks service privilege separation and bloats the attack surface of the edge API gateway.

## Security Impact
Enforces Zone 8 (Z8) isolation. Compromise of the Next.js frontend gives the attacker no database access, no ability to bypass quarantine, and no access to clean storage ciphertext or cryptographic keys.

## Cost Impact
Minimal additional container resource footprint (~128MB RAM). Zero cloud compute costs in local environment.

## Research Impact
Provides a clean interface for capturing system overview screenshots, timeline visualizations, and audit chain verification states for the final research paper and demonstration.

## Consequences
- Requires running a separate container for `apps/dashboard`.
- Authentication must be managed strictly via RFC 8725-compliant JWT access tokens and secure HTTP-only refresh cookies.

## Evidence & Source References
- Build Plan: Section 1.2 (DEC-004), Section 2.2 (P31, P33, P34 contracts).
- RFC 8725: JSON Web Token Best Current Practices.
