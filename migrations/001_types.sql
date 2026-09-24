-- Up Migration
CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'auditor');
CREATE TYPE session_status AS ENUM ('CREATED', 'UPLOADING', 'UPLOADED', 'FAILED', 'EXPIRED');
CREATE TYPE file_status AS ENUM (
    'QUARANTINED', 'SCANNING', 'SCANNED', 'PROMOTING', 'PROMOTED',
    'BLOCKED', 'IN_REVIEW', 'ERROR', 'DELETED'
);
CREATE TYPE job_status AS ENUM ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'DEAD');
CREATE TYPE decision_type AS ENUM ('ALLOW', 'BLOCK', 'QUARANTINE', 'ERROR');
CREATE TYPE finding_outcome AS ENUM ('PASS', 'FAIL', 'SUSPICIOUS', 'ERROR', 'SKIPPED');
CREATE TYPE severity_level AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
CREATE TYPE confidence_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CONFIRMED');
CREATE TYPE cloud_provider AS ENUM ('minio', 'aws', 'gcp');
CREATE TYPE storage_zone AS ENUM ('quarantine', 'clean', 'replica', 'audit');

-- Down Migration
DROP TYPE IF EXISTS storage_zone;
DROP TYPE IF EXISTS cloud_provider;
DROP TYPE IF EXISTS confidence_level;
DROP TYPE IF EXISTS severity_level;
DROP TYPE IF EXISTS finding_outcome;
DROP TYPE IF EXISTS decision_type;
DROP TYPE IF EXISTS job_status;
DROP TYPE IF EXISTS file_status;
DROP TYPE IF EXISTS session_status;
DROP TYPE IF EXISTS user_role;
