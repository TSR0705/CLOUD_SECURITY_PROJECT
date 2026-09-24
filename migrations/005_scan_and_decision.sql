-- Up Migration
CREATE TABLE scan_jobs (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    file_version_id  uuid NOT NULL REFERENCES file_versions(id),
    status           job_status NOT NULL DEFAULT 'QUEUED',
    attempts         integer NOT NULL DEFAULT 0,
    max_attempts     integer NOT NULL DEFAULT 3,
    run_after        timestamptz NOT NULL DEFAULT now(),
    locked_by        text,
    locked_at        timestamptz,
    last_error       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz
);

CREATE INDEX scan_jobs_queue_idx ON scan_jobs(run_after) WHERE status = 'QUEUED';
CREATE UNIQUE INDEX scan_jobs_one_active_idx ON scan_jobs(file_version_id)
    WHERE status IN ('QUEUED', 'RUNNING');

CREATE TABLE scan_results (
    id                          uuid PRIMARY KEY DEFAULT uuidv7(),
    scan_job_id                 uuid NOT NULL REFERENCES scan_jobs(id),
    file_version_id             uuid NOT NULL REFERENCES file_versions(id),
    check_id                    text NOT NULL,
    engine                      text NOT NULL,
    engine_version              text,
    signature_version           text,
    outcome                     finding_outcome NOT NULL,
    reason_code                 text,
    severity                    severity_level NOT NULL DEFAULT 'INFO',
    confidence                  confidence_level NOT NULL DEFAULT 'CONFIRMED',
    evidence                    jsonb NOT NULL DEFAULT '{}',
    scanned_storage_version_id  text NOT NULL,
    scanned_sha256              bytea NOT NULL CHECK (octet_length(scanned_sha256) = 32),
    scanned_size                bigint NOT NULL,
    duration_ms                 integer,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scan_job_id, check_id)
);

CREATE INDEX scan_results_fv_idx ON scan_results(file_version_id);

CREATE TABLE security_decisions (
    id                        uuid PRIMARY KEY DEFAULT uuidv7(),
    file_version_id           uuid NOT NULL REFERENCES file_versions(id),
    scan_job_id               uuid REFERENCES scan_jobs(id),
    policy_id                 uuid NOT NULL REFERENCES security_policies(id),
    decision                  decision_type NOT NULL,
    primary_reason            text NOT NULL,
    severity                  severity_level NOT NULL,
    confidence                confidence_level NOT NULL,
    risk_score                smallint NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    policy_result             text NOT NULL,
    scanner_result            text NOT NULL,
    integrity_result          text NOT NULL,
    authorization_result      text NOT NULL,
    bound_bucket              text NOT NULL,
    bound_key                 text NOT NULL,
    bound_storage_version_id  text NOT NULL,
    bound_sha256              bytea NOT NULL CHECK (octet_length(bound_sha256) = 32),
    bound_size                bigint NOT NULL,
    record                    jsonb NOT NULL,
    engine_version            text NOT NULL,
    decided_by                text NOT NULL,
    supersedes_id             uuid REFERENCES security_decisions(id),
    created_at                timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX security_decisions_fv_idx ON security_decisions(file_version_id, created_at DESC);
CREATE INDEX security_decisions_type_idx ON security_decisions(decision, created_at DESC);

-- Down Migration
DROP TABLE IF EXISTS security_decisions;
DROP TABLE IF EXISTS scan_results;
DROP TABLE IF EXISTS scan_jobs;
