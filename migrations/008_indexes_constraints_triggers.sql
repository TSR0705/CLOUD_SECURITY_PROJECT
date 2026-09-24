-- Up Migration
-- Attach forbid_mutation triggers to the 6 append-only evidence tables
CREATE TRIGGER audit_events_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

CREATE TRIGGER audit_checkpoints_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

CREATE TRIGGER scan_results_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON scan_results
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

CREATE TRIGGER security_decisions_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON security_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

CREATE TRIGGER security_policies_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON security_policies
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

CREATE TRIGGER file_versions_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON file_versions
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- Enable Row Level Security on cloud_objects
ALTER TABLE cloud_objects ENABLE ROW LEVEL SECURITY;

-- Down Migration
DROP TRIGGER IF EXISTS file_versions_immutable ON file_versions;
DROP TRIGGER IF EXISTS security_policies_immutable ON security_policies;
DROP TRIGGER IF EXISTS security_decisions_immutable ON security_decisions;
DROP TRIGGER IF EXISTS scan_results_immutable ON scan_results;
DROP TRIGGER IF EXISTS audit_checkpoints_immutable ON audit_checkpoints;
DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events;
ALTER TABLE cloud_objects DISABLE ROW LEVEL SECURITY;
