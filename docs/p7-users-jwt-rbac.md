# Phase P7 — Dashboard Users, JWT and RBAC

## 1. Executive Summary

Phase P7 implements dashboard user authentication, EdDSA-signed JSON Web Tokens (JWT), Role-Based Access Control (RBAC), secure rotating refresh tokens, and account lockout protection for the Secure Upload Gateway (SUG).

It establishes:

1. **Argon2id Password Hashing**: Compliant with OWASP and RFC 9106 (`m=65536, t=3, p=4`).
2. **EdDSA (Ed25519) Short-Lived Access Tokens**: 15-minute lifespan (`900s`), strict audience (`sug-dashboard`), strict issuer (`sug-api`), and RFC 8725 algorithm-confusion mitigation.
3. **Rotating Refresh Tokens with Reuse Detection**: 7-day lifespan, SHA-256 hashed in database, transmitted exclusively via `HttpOnly; Secure; SameSite=Strict` cookies. Immediate automatic invalidation of all user sessions upon detected token replay.
4. **Brute-Force & Timing Attack Mitigation**: 5-attempt consecutive failed login account lockout (15-minute window), coupled with dummy Argon2id verification for nonexistent accounts to prevent user enumeration.
5. **Centralized RBAC**: Declarative Fastify pre-handler guards (`requireRole`) enforcing access controls across `admin`, `analyst`, and `auditor` roles.
6. **Tamper-Evident Audit Logging**: Fully integrated with PostgreSQL `audit_append()` hash-chained audit trails, logging zero credentials or raw secrets.

---

## 2. Cryptographic Architecture & Specifications

### 2.1 Password Hashing (Argon2id)

- **Algorithm**: `argon2id` (RFC 9106)
- **Memory Cost (`m`)**: 64 MiB ($65,536\text{ KiB}$)
- **Time Cost / Iterations (`t`)**: 3
- **Parallelism (`p`)**: 4 lanes / threads
- **Hash Length**: 32 bytes binary (43 characters base64)
- **Timing Attack Defense**: When authenticating unknown or non-existent usernames, a precomputed dummy Argon2id hash is verified to maintain constant response timing, eliminating account enumeration side-channels.

### 2.2 Dashboard JWT Specification (Ed25519 / EdDSA)

- **Signature Algorithm**: `EdDSA` over curve `Ed25519`
- **Lifespan**: 15 minutes ($900\text{ seconds}$)
- **JOSE Protected Header**:
  - `alg`: `"EdDSA"` (Edwards-curve Digital Signature Algorithm)
  - `typ`: `"JWT"` (JOSE header parameter per RFC 7519 / RFC 8725, not a payload claim)
- **JWT Payload (Claims)**:
  - `iss`: `"sug-api"` (fixed issuer)
  - `aud`: `"sug-dashboard"` (fixed audience)
  - `sub`: User UUID (`users.id`)
  - `role`: User role (`admin` | `analyst` | `auditor`)
  - `email`: User email address
  - `iat`: Epoch timestamp
  - `exp`: Epoch timestamp ($iat + 900$)
- **RFC 8725 Hardening**:
  - Verification strictly enforces `algorithms: ['EdDSA']`.
  - Symmetric key confusion attacks (e.g. `HS256` signed with public key) and `none` algorithm attacks are explicitly rejected.

### 2.3 Refresh Tokens & Rotation Architecture

- **Entropy**: 256 bits ($32\text{ bytes}$) via Node.js CSPRNG (`crypto.randomBytes(32).toString('base64url')`).
- **Database Storage**: Raw refresh tokens are **never** stored. Only the binary SHA-256 digest (`token_hash bytea(32)`) is persisted in `refresh_tokens`.
- **Delivery**: Transmitted strictly via HTTP cookie:
  - Name: `sug_refresh_token`
  - `Path`: `/api/v1/auth`
  - `HttpOnly`: `true`
  - `Secure`: `true` in production (`config.nodeEnv === 'production'`)
  - `SameSite`: `Strict`
  - `Max-Age`: 604,800 seconds ($7\text{ days}$)
- **Single-Use Rotation**: Every `/api/v1/auth/refresh` request issues a new refresh token, sets the previous token's `revoked_at` timestamp, and records `replaced_by` pointing to the new token ID.
- **Theft & Replay Detection**: If an already revoked or replaced refresh token is submitted, the gateway treats the event as a session compromise, immediately revokes **all** active refresh tokens for that user, and emits a `user.token_replay_detected` audit event.

---

## 3. Account Lockout & Brute-Force Defense (authz-05)

- **Failure Threshold**: 5 consecutive failed login attempts.
- **Lockout Duration**: 15 minutes (`now() + interval '15 minutes'`).
- **State Fields**: Managed in the `users` table:
  - `failed_logins integer NOT NULL DEFAULT 0`
  - `locked_until timestamptz NULL`
- **Behavior**:
  - While `locked_until > now()`, login attempts are immediately rejected with HTTP 423 (Locked) RFC 7807 problem details without performing password verification.
  - Upon successful authentication, `failed_logins` is reset to 0 and `locked_until` is cleared (`NULL`).

---

## 4. Role-Based Access Control Matrix (authz-06)

Centralized authorization is enforced via the `requireRole(...roles)` pre-handler:

| Route / Resource                | Allowed Roles      |  Admin  | Analyst | Auditor |   Unauthenticated   |
| :------------------------------ | :----------------- | :-----: | :-----: | :-----: | :-----------------: |
| `POST /api/v1/auth/login`       | Public             | Allowed | Allowed | Allowed |       Allowed       |
| `POST /api/v1/auth/refresh`     | Valid Cookie       | Allowed | Allowed | Allowed |         401         |
| `POST /api/v1/auth/logout`      | Valid Cookie       | Allowed | Allowed | Allowed | 200 (clears cookie) |
| `GET /api/v1/auth/me`           | Authenticated      | Allowed | Allowed | Allowed |         401         |
| `GET /api/v1/auth/admin-only`   | `admin`            | **200** |   403   |   403   |         401         |
| `GET /api/v1/auth/analyst-only` | `admin`, `analyst` | **200** | **200** |   403   |         401         |
| `GET /api/v1/auth/auditor-only` | `admin`, `auditor` | **200** |   403   | **200** |         401         |

---

## 5. Database Schema & Least-Privilege Grants

The implementation utilizes the pre-existing `users` and `refresh_tokens` tables established in `migrations/003_identity_policy.sql`. In accordance with migration immutability, `migrations/009_roles_grants.sql` remains intact as frozen in P3. A dedicated migration [`migrations/010_p7_dashboard_auth_grants.sql`](file:///c:/Users/ACER/Desktop/CLOUD_SECURITY_PROJECT/migrations/010_p7_dashboard_auth_grants.sql) provisions the runtime `sug_api` role with least-privilege permissions:

```sql
GRANT SELECT ON users TO sug_api;
GRANT UPDATE (failed_logins, locked_until, last_login_at) ON users TO sug_api;
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO sug_api;
```

`sug_api` cannot modify user roles, user emails, or password hashes, and cannot delete records from either table.

---

## 6. Audit Events

All authentication lifecycle events are logged to the tamper-evident `audit_events` table via `audit_append()`:

| Action                       | Actor Type         | Key Details Logged                 | Security Invariants               |
| :--------------------------- | :----------------- | :--------------------------------- | :-------------------------------- |
| `user.login_success`         | `user`             | `email`, `role`                    | No passwords or token values      |
| `user.login_failure`         | `user` / `service` | `email`, `reason`, `failed_logins` | Zero oracle, timing-safe          |
| `user.locked_out`            | `user`             | `email`, `failed_logins` (5)       | Logged at lockout boundary        |
| `user.token_rotated`         | `user`             | `user_id`                          | Only SHA-256 hashed in DB         |
| `user.token_replay_detected` | `user`             | `compromised_token_id`             | Triggers revocation of all tokens |
| `user.logged_out`            | `user`             | `user_id`                          | Session revoked                   |
