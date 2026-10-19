-- Up Migration
-- Phase P22: Service Privilege Separation & Least-Privilege IAM Boundaries (ADR-0004)
-- Enforces strict boundary: sug_scanner, sug_replicator, sug_promoter, and sug_api
-- have only their minimal required privileges.

-- 1. Revoke direct INSERT on audit_checkpoints from sug_replicator.
-- Checkpoints are generated exclusively via audit_checkpoint_create() SECURITY DEFINER function.
REVOKE INSERT ON audit_checkpoints FROM sug_replicator;

-- 2. Explicitly reaffirm least-privilege guarantees for all roles:
-- Ensure sug_scanner has zero write grants on clean objects, security decisions, files, or audit checkpoints.
REVOKE ALL ON security_decisions FROM sug_scanner;
REVOKE ALL ON promotion_jobs FROM sug_scanner;
REVOKE ALL ON cloud_objects FROM sug_scanner;
REVOKE ALL ON files FROM sug_scanner;
REVOKE ALL ON audit_checkpoints FROM sug_scanner;
REVOKE ALL ON users FROM sug_scanner;
REVOKE ALL ON api_keys FROM sug_scanner;
REVOKE ALL ON refresh_tokens FROM sug_scanner;
REVOKE ALL ON applications FROM sug_scanner;

-- Down Migration
GRANT INSERT ON audit_checkpoints TO sug_replicator;
