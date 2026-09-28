-- Up Migration
-- Phase P7: Least-privilege permissions for dashboard user authentication and refresh token rotation

-- sug_api needs to authenticate users and track failed attempts/lockout
GRANT SELECT ON users TO sug_api;
GRANT UPDATE (failed_logins, locked_until, last_login_at) ON users TO sug_api;

-- sug_api needs to manage refresh token lifecycles (create, lookup by hash, rotate, revoke)
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO sug_api;

-- Down Migration
REVOKE SELECT, INSERT, UPDATE ON refresh_tokens FROM sug_api;
REVOKE UPDATE (failed_logins, locked_until, last_login_at) ON users FROM sug_api;
REVOKE SELECT ON users FROM sug_api;
