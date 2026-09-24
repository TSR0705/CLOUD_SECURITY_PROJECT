-- Up Migration
CREATE TABLE audit_events (
    seq              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id               uuid NOT NULL UNIQUE DEFAULT uuidv7(),
    occurred_at      timestamptz NOT NULL DEFAULT now(),
    actor_type       text NOT NULL CHECK (actor_type IN ('api_key', 'user', 'service')),
    actor_id         text NOT NULL,
    action           text NOT NULL,
    application_id   uuid,
    file_id          uuid,
    file_version_id  uuid,
    decision_id      uuid,
    request_id       uuid,
    ip               inet,
    details          jsonb NOT NULL DEFAULT '{}',
    prev_hash        bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    event_hash       bytea NOT NULL UNIQUE CHECK (octet_length(event_hash) = 32)
);

CREATE INDEX audit_events_file_idx   ON audit_events(file_id);
CREATE INDEX audit_events_action_idx ON audit_events(action, occurred_at DESC);

CREATE TABLE audit_checkpoints (
    id              uuid PRIMARY KEY DEFAULT uuidv7(),
    last_seq        bigint NOT NULL UNIQUE,
    chain_hash      bytea NOT NULL CHECK (octet_length(chain_hash) = 32),
    signature       bytea NOT NULL,
    s3_version_id   text,
    gcs_generation  text,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION audit_append(
    p_actor_type text,
    p_actor_id text,
    p_action text,
    p_refs jsonb,
    p_details jsonb
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_prev bytea;
    v_hash bytea;
    v_seq bigint;
    v_now timestamptz := clock_timestamp();
    v_refs jsonb := COALESCE(p_refs, '{}'::jsonb);
    v_details jsonb := COALESCE(p_details, '{}'::jsonb);
BEGIN
    PERFORM pg_advisory_xact_lock(7426001);
    SELECT event_hash INTO v_prev FROM audit_events ORDER BY seq DESC LIMIT 1;
    v_prev := COALESCE(v_prev, decode(repeat('00', 32), 'hex'));
    v_hash := digest(v_prev || convert_to(
                p_actor_type || '|' || p_actor_id || '|' || p_action || '|' ||
                v_now::text || '|' || v_refs::text || '|' || v_details::text, 'UTF8'), 'sha256');
    INSERT INTO audit_events(occurred_at, actor_type, actor_id, action, application_id, file_id,
                             file_version_id, decision_id, request_id, ip, details, prev_hash, event_hash)
    VALUES (v_now, p_actor_type, p_actor_id, p_action,
            (v_refs->>'application_id')::uuid, (v_refs->>'file_id')::uuid,
            (v_refs->>'file_version_id')::uuid, (v_refs->>'decision_id')::uuid,
            (v_refs->>'request_id')::uuid, (v_refs->>'ip')::inet, v_details, v_prev, v_hash)
    RETURNING seq INTO v_seq;
    RETURN v_seq;
END;
$$;

-- Down Migration
DROP FUNCTION IF EXISTS audit_append(text, text, text, jsonb, jsonb);
DROP TABLE IF EXISTS audit_checkpoints;
DROP TABLE IF EXISTS audit_events;
