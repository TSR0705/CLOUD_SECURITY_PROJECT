-- Up Migration
-- Create the six database roles if they do not already exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sug_api') THEN
        CREATE ROLE sug_api WITH LOGIN PASSWORD 'sug_api_dev_password';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sug_scanner') THEN
        CREATE ROLE sug_scanner WITH LOGIN PASSWORD 'sug_scanner_dev_password';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sug_promoter') THEN
        CREATE ROLE sug_promoter WITH LOGIN PASSWORD 'sug_promoter_dev_password';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sug_replicator') THEN
        CREATE ROLE sug_replicator WITH LOGIN PASSWORD 'sug_replicator_dev_password';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sug_auditor') THEN
        CREATE ROLE sug_auditor WITH LOGIN PASSWORD 'sug_auditor_dev_password';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sug_admin') THEN
        CREATE ROLE sug_admin WITH LOGIN PASSWORD 'sug_dev_password';
    END IF;
END
$$;

-- Revoke default public schema privileges
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;

-- Grant schema usage to the 6 roles
GRANT USAGE ON SCHEMA public TO sug_admin, sug_api, sug_scanner, sug_promoter, sug_replicator, sug_auditor;

-- Row Level Security policies on cloud_objects
DROP POLICY IF EXISTS cloud_objects_admin_policy ON cloud_objects;
CREATE POLICY cloud_objects_admin_policy ON cloud_objects
    FOR ALL
    TO sug_admin, sug_api, sug_promoter, sug_auditor
    USING (true)
    WITH CHECK (true);

DROP POLICY IF EXISTS cloud_objects_replicator_select_policy ON cloud_objects;
CREATE POLICY cloud_objects_replicator_select_policy ON cloud_objects
    FOR SELECT
    TO sug_replicator
    USING (true);

DROP POLICY IF EXISTS cloud_objects_replicator_insert_policy ON cloud_objects;
CREATE POLICY cloud_objects_replicator_insert_policy ON cloud_objects
    FOR INSERT
    TO sug_replicator
    WITH CHECK (zone = 'replica');

-- sug_api grants
GRANT SELECT, INSERT, UPDATE ON upload_sessions, files TO sug_api;
GRANT INSERT ON file_versions, scan_jobs TO sug_api;
GRANT SELECT ON security_policies, api_keys, security_decisions, scan_results, cloud_objects TO sug_api;
GRANT EXECUTE ON FUNCTION audit_append(text, text, text, jsonb, jsonb) TO sug_api;

-- sug_scanner grants
GRANT SELECT ON file_versions, upload_sessions, security_policies TO sug_scanner;
GRANT SELECT, UPDATE ON scan_jobs TO sug_scanner;
GRANT INSERT ON scan_results TO sug_scanner;
GRANT EXECUTE ON FUNCTION audit_append(text, text, text, jsonb, jsonb) TO sug_scanner;

-- sug_promoter grants
GRANT SELECT ON scan_results, file_versions, security_policies, upload_sessions, files, security_decisions, promotion_jobs, cloud_objects TO sug_promoter;
GRANT INSERT ON security_decisions, promotion_jobs, cloud_objects, replication_jobs TO sug_promoter;
GRANT UPDATE ON promotion_jobs TO sug_promoter;
GRANT UPDATE (status) ON files TO sug_promoter;
GRANT EXECUTE ON FUNCTION audit_append(text, text, text, jsonb, jsonb) TO sug_promoter;

-- sug_replicator grants
GRANT SELECT ON cloud_objects, audit_events TO sug_replicator;
GRANT SELECT, UPDATE ON replication_jobs TO sug_replicator;
GRANT INSERT ON cloud_objects, audit_checkpoints TO sug_replicator;
GRANT EXECUTE ON FUNCTION audit_append(text, text, text, jsonb, jsonb) TO sug_replicator;

-- sug_auditor grants (strictly read-only, non-sensitive columns)
GRANT SELECT ON applications, security_policies, upload_sessions, files, file_versions,
                cloud_objects, scan_jobs, scan_results, security_decisions, promotion_jobs,
                replication_jobs, audit_events, audit_checkpoints TO sug_auditor;
GRANT SELECT (id, email, role, is_active, failed_logins, locked_until, created_at, last_login_at) ON users TO sug_auditor;
GRANT SELECT (id, application_id, key_prefix, scopes, created_by, created_at, expires_at, revoked_at, last_used_at) ON api_keys TO sug_auditor;

-- sug_admin grants
GRANT ALL ON ALL TABLES IN SCHEMA public TO sug_admin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO sug_admin;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO sug_admin;

-- Down Migration
DROP POLICY IF EXISTS cloud_objects_replicator_insert_policy ON cloud_objects;
DROP POLICY IF EXISTS cloud_objects_replicator_select_policy ON cloud_objects;
DROP POLICY IF EXISTS cloud_objects_admin_policy ON cloud_objects;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sug_admin, sug_api, sug_scanner, sug_promoter, sug_replicator, sug_auditor;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sug_admin, sug_api, sug_scanner, sug_promoter, sug_replicator, sug_auditor;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM sug_admin, sug_api, sug_scanner, sug_promoter, sug_replicator, sug_auditor;
REVOKE USAGE ON SCHEMA public FROM sug_admin, sug_api, sug_scanner, sug_promoter, sug_replicator, sug_auditor;
