-- Up Migration
-- Phase P17: Least-privilege permissions for scan findings retrieval and scanner idempotency

-- sug_api needs to query scan jobs and associated file versions to verify application ownership
GRANT SELECT ON scan_jobs, file_versions TO sug_api;

-- sug_scanner needs to check existing findings for idempotent execution
GRANT SELECT ON scan_results TO sug_scanner;

-- Down Migration
REVOKE SELECT ON scan_results FROM sug_scanner;
REVOKE SELECT ON scan_jobs, file_versions FROM sug_api;
