-- Up Migration
CREATE TABLE upload_sessions (
    id                 uuid PRIMARY KEY DEFAULT uuidv7(),
    application_id     uuid NOT NULL REFERENCES applications(id),
    api_key_id         uuid NOT NULL REFERENCES api_keys(id),
    policy_id          uuid NOT NULL REFERENCES security_policies(id),
    client_ref         text CHECK (length(client_ref) <= 128),
    original_filename  text NOT NULL CHECK (length(original_filename) BETWEEN 1 AND 255),
    declared_mime      text NOT NULL CHECK (length(declared_mime) <= 127),
    declared_size      bigint NOT NULL CHECK (declared_size > 0),
    declared_sha256    bytea CHECK (declared_sha256 IS NULL OR octet_length(declared_sha256) = 32),
    status             session_status NOT NULL DEFAULT 'CREATED',
    token_jti          uuid NOT NULL UNIQUE,
    expires_at         timestamptz NOT NULL,
    client_ip          inet,
    created_at         timestamptz NOT NULL DEFAULT now(),
    completed_at       timestamptz
);

CREATE INDEX upload_sessions_app_created_idx ON upload_sessions(application_id, created_at DESC);
CREATE INDEX upload_sessions_expiry_idx ON upload_sessions(expires_at) WHERE status = 'CREATED';

CREATE TABLE files (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    application_id      uuid NOT NULL REFERENCES applications(id),
    upload_session_id   uuid NOT NULL UNIQUE REFERENCES upload_sessions(id),
    display_filename    text NOT NULL,              -- sanitised; never used in a path or key
    status              file_status NOT NULL DEFAULT 'QUARANTINED',
    current_version_id  uuid,                       -- FK added below
    created_at          timestamptz NOT NULL DEFAULT now(),
    deleted_at          timestamptz
);

CREATE INDEX files_app_status_idx ON files(application_id, status, created_at DESC);

CREATE TABLE file_versions (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    file_id             uuid NOT NULL REFERENCES files(id),
    version_no          integer NOT NULL DEFAULT 1 CHECK (version_no > 0),
    provider            cloud_provider NOT NULL,
    bucket              text NOT NULL,
    object_key          text NOT NULL,
    storage_version_id  text NOT NULL CHECK (storage_version_id <> '' AND storage_version_id <> 'null'),
    etag                text,
    size_bytes          bigint NOT NULL CHECK (size_bytes > 0),
    sha256_ingest       bytea NOT NULL CHECK (octet_length(sha256_ingest) = 32),
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (file_id, version_no),
    UNIQUE (provider, bucket, object_key, storage_version_id)
);

ALTER TABLE files ADD CONSTRAINT files_current_version_fk
    FOREIGN KEY (current_version_id) REFERENCES file_versions(id);

CREATE TABLE cloud_objects (
    id                  uuid PRIMARY KEY DEFAULT uuidv7(),
    file_version_id     uuid NOT NULL REFERENCES file_versions(id),
    zone                storage_zone NOT NULL,
    provider            cloud_provider NOT NULL,
    bucket              text NOT NULL,
    object_key          text NOT NULL,
    storage_version_id  text NOT NULL,              -- S3 version ID or GCS generation
    etag                text,
    crc32c              text,
    size_bytes          bigint NOT NULL,
    sha256_plain        bytea CHECK (sha256_plain  IS NULL OR octet_length(sha256_plain)  = 32),
    sha256_cipher       bytea CHECK (sha256_cipher IS NULL OR octet_length(sha256_cipher) = 32),
    kek_id              text,
    enc_alg             text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, bucket, object_key, storage_version_id),
    UNIQUE (file_version_id, zone, provider)
);

-- Down Migration
ALTER TABLE files DROP CONSTRAINT IF EXISTS files_current_version_fk;
DROP TABLE IF EXISTS cloud_objects;
DROP TABLE IF EXISTS file_versions;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS upload_sessions;
