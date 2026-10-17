-- Up Migration
-- Phase P17: Least-privilege permissions for scan findings retrieval and scanner idempotency

-- sug_api needs to query scan jobs and associated file versions to verify application ownership
GRANT SELECT ON scan_jobs, file_versions TO sug_api;

-- sug_scanner needs to check existing findings for idempotent execution
GRANT SELECT ON scan_results TO sug_scanner;

-- Immutability enforcement on scan_jobs.file_version_id
CREATE OR REPLACE FUNCTION forbid_scan_job_file_version_mutation()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.file_version_id IS DISTINCT FROM NEW.file_version_id THEN
        RAISE EXCEPTION 'scan_jobs.file_version_id is immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS scan_jobs_file_version_immutable ON scan_jobs;
CREATE TRIGGER scan_jobs_file_version_immutable
    BEFORE UPDATE ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION forbid_scan_job_file_version_mutation();

-- Referential integrity & artifact identity verification on scan_results insertion
CREATE OR REPLACE FUNCTION verify_scan_result_identity()
RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    job_fv_id uuid;
BEGIN
    SELECT file_version_id INTO job_fv_id FROM scan_jobs WHERE id = NEW.scan_job_id;
    IF job_fv_id IS NULL OR job_fv_id != NEW.file_version_id THEN
        RAISE EXCEPTION 'scan_results.file_version_id does not match scan_jobs.file_version_id';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS scan_results_identity_check ON scan_results;
CREATE TRIGGER scan_results_identity_check
    BEFORE INSERT ON scan_results
    FOR EACH ROW EXECUTE FUNCTION verify_scan_result_identity();

-- Down Migration
DROP TRIGGER IF EXISTS scan_results_identity_check ON scan_results;
DROP FUNCTION IF EXISTS verify_scan_result_identity();
DROP TRIGGER IF EXISTS scan_jobs_file_version_immutable ON scan_jobs;
DROP FUNCTION IF EXISTS forbid_scan_job_file_version_mutation();
REVOKE SELECT ON scan_results FROM sug_scanner;
REVOKE SELECT ON scan_jobs, file_versions FROM sug_api;
