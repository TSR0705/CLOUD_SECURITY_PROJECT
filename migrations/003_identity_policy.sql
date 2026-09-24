-- Up Migration
CREATE TABLE users (
    id             uuid PRIMARY KEY DEFAULT uuidv7(),
    email          citext NOT NULL UNIQUE,
    password_hash  text   NOT NULL,                 -- argon2id encoded string
    role           user_role NOT NULL,
    is_active      boolean NOT NULL DEFAULT true,
    failed_logins  integer NOT NULL DEFAULT 0,
    locked_until   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz
);

CREATE TABLE applications (
    id                uuid PRIMARY KEY DEFAULT uuidv7(),
    name              text NOT NULL UNIQUE CHECK (length(name) BETWEEN 3 AND 64),
    owner_user_id     uuid NOT NULL REFERENCES users(id),
    active_policy_id  uuid,                         -- FK added after security_policies exists
    webhook_url       text CHECK (webhook_url IS NULL OR webhook_url LIKE 'https://%'),
    webhook_secret    bytea,                        -- HMAC key, encrypted with the KEK
    is_active         boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    application_id  uuid NOT NULL REFERENCES applications(id),
    key_prefix      char(8) NOT NULL UNIQUE,        -- public lookup handle
    key_hmac        bytea NOT NULL CHECK (octet_length(key_hmac) = 32),
    scopes          text[] NOT NULL DEFAULT '{upload,read}',
    created_by      uuid NOT NULL REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,
    revoked_at      timestamptz,
    last_used_at    timestamptz
);

CREATE INDEX api_keys_app_idx ON api_keys(application_id) WHERE revoked_at IS NULL;

CREATE TABLE security_policies (
    id               uuid PRIMARY KEY DEFAULT uuidv7(),
    application_id   uuid NOT NULL REFERENCES applications(id),
    version          integer NOT NULL CHECK (version > 0),
    document         jsonb NOT NULL,                -- validated by zod before insert
    document_sha256  bytea NOT NULL CHECK (octet_length(document_sha256) = 32),
    created_by       uuid NOT NULL REFERENCES users(id),
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

ALTER TABLE applications ADD CONSTRAINT applications_policy_fk
    FOREIGN KEY (active_policy_id) REFERENCES security_policies(id);

CREATE TABLE refresh_tokens (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id      uuid NOT NULL REFERENCES users(id),
    token_hash   bytea NOT NULL UNIQUE,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    replaced_by  uuid REFERENCES refresh_tokens(id)
);

-- Down Migration
ALTER TABLE applications DROP CONSTRAINT IF EXISTS applications_policy_fk;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS security_policies;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS users;
