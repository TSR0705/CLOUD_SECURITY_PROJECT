-- Up Migration
-- Phase P8: Security Policy Engine & Upload Session Pinning / Single-Use Claim State

-- 1. Pin exact immutable policy version and SHA-256 hash to upload sessions
ALTER TABLE upload_sessions
    ADD COLUMN IF NOT EXISTS policy_version integer,
    ADD COLUMN IF NOT EXISTS policy_hash bytea CHECK (policy_hash IS NULL OR octet_length(policy_hash) = 32),
    ADD COLUMN IF NOT EXISTS is_claimed boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS claimed_at timestamptz;

CREATE INDEX IF NOT EXISTS upload_sessions_claim_idx ON upload_sessions(id, application_id) WHERE is_claimed = false;

-- 2. Least-privilege grants for sug_api to manage versioned policies and application active policy pointers
GRANT INSERT ON security_policies TO sug_api;
GRANT SELECT, UPDATE (active_policy_id) ON applications TO sug_api;

-- Down Migration
REVOKE INSERT ON security_policies FROM sug_api;
REVOKE UPDATE (active_policy_id) ON applications FROM sug_api;
REVOKE SELECT ON applications FROM sug_api;

DROP INDEX IF EXISTS upload_sessions_claim_idx;

ALTER TABLE upload_sessions
    DROP COLUMN IF EXISTS claimed_at,
    DROP COLUMN IF EXISTS is_claimed,
    DROP COLUMN IF EXISTS policy_hash,
    DROP COLUMN IF EXISTS policy_version;
