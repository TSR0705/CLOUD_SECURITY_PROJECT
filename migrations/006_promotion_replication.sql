-- Up Migration
CREATE TABLE promotion_jobs (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    decision_id  uuid NOT NULL UNIQUE REFERENCES security_decisions(id),
    status       job_status NOT NULL DEFAULT 'QUEUED',
    attempts     integer NOT NULL DEFAULT 0,
    run_after    timestamptz NOT NULL DEFAULT now(),
    locked_by    text,
    locked_at    timestamptz,
    last_error   text,
    outcome      text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);

CREATE TABLE replication_jobs (
    id                      uuid PRIMARY KEY DEFAULT uuidv7(),
    source_cloud_object_id  uuid NOT NULL REFERENCES cloud_objects(id),
    target_provider         cloud_provider NOT NULL,
    target_bucket           text NOT NULL,
    status                  job_status NOT NULL DEFAULT 'QUEUED',
    attempts                integer NOT NULL DEFAULT 0,
    max_attempts            integer NOT NULL DEFAULT 10,
    run_after               timestamptz NOT NULL DEFAULT now(),
    locked_by               text,
    locked_at               timestamptz,
    last_error              text,
    verified_at             timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    finished_at             timestamptz,
    UNIQUE (source_cloud_object_id, target_provider, target_bucket)
);

-- Down Migration
DROP TABLE IF EXISTS replication_jobs;
DROP TABLE IF EXISTS promotion_jobs;
