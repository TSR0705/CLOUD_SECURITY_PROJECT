-- Up Migration
-- Phase P21: Least-privilege permissions for audit event queries and checkpoint management
GRANT SELECT ON audit_events TO sug_api;
GRANT SELECT, INSERT ON audit_checkpoints TO sug_api;

-- Down Migration
REVOKE SELECT, INSERT ON audit_checkpoints FROM sug_api;
REVOKE SELECT ON audit_events FROM sug_api;
