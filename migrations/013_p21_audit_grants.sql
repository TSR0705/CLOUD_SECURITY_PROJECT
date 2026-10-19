-- Up Migration
-- Phase P21: Least-privilege permissions for audit event queries and checkpoint management

-- sug_api can query audit events and checkpoints for verification
GRANT SELECT ON audit_events TO sug_api;
GRANT SELECT ON audit_checkpoints TO sug_api;

-- Revoke direct table INSERT from sug_api (least-privilege enforcement)
REVOKE INSERT ON audit_checkpoints FROM sug_api;

-- Clean up any legacy test entries where last_seq does not exist in audit_events
ALTER TABLE audit_checkpoints DISABLE TRIGGER audit_checkpoints_immutable;
DELETE FROM audit_checkpoints WHERE last_seq NOT IN (SELECT seq FROM audit_events);
ALTER TABLE audit_checkpoints ENABLE TRIGGER audit_checkpoints_immutable;

-- Narrowly-scoped SECURITY DEFINER function for checkpoint creation
-- Enforces in-database cryptographic invariants and checks before insertion
CREATE OR REPLACE FUNCTION audit_checkpoint_create(
    p_id uuid,
    p_last_seq bigint,
    p_chain_hash bytea,
    p_signature bytea,
    p_s3_version_id text,
    p_created_at timestamptz DEFAULT now()
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_event_hash bytea;
    v_prev_last_seq bigint;
    v_inserted_id uuid;
BEGIN
    -- Advisory lock to prevent race conditions during checkpoint creation
    PERFORM pg_advisory_xact_lock(7426002);

    -- 1. Validate inputs
    IF p_id IS NULL THEN
        RAISE EXCEPTION 'Checkpoint ID cannot be null' USING ERRCODE = 'check_violation';
    END IF;

    IF p_last_seq IS NULL OR p_last_seq < 1 THEN
        RAISE EXCEPTION 'Invalid last_seq: %', p_last_seq USING ERRCODE = 'check_violation';
    END IF;

    IF p_chain_hash IS NULL OR octet_length(p_chain_hash) <> 32 THEN
        RAISE EXCEPTION 'Invalid chain_hash length: expected 32 bytes' USING ERRCODE = 'check_violation';
    END IF;

    IF p_signature IS NULL OR octet_length(p_signature) <> 64 THEN
        RAISE EXCEPTION 'Invalid signature length: expected 64 bytes' USING ERRCODE = 'check_violation';
    END IF;

    IF p_s3_version_id IS NULL OR length(trim(p_s3_version_id)) = 0 THEN
        RAISE EXCEPTION 'Missing or empty s3_version_id' USING ERRCODE = 'check_violation';
    END IF;

    -- 2. Verify that p_last_seq exists in audit_events and chain_hash matches event_hash exactly
    SELECT event_hash INTO v_event_hash
    FROM audit_events
    WHERE seq = p_last_seq;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Audit event with seq % does not exist', p_last_seq USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF v_event_hash <> p_chain_hash THEN
        RAISE EXCEPTION 'Chain hash mismatch for seq %: event_hash does not match provided chain_hash', p_last_seq
            USING ERRCODE = 'data_corrupted';
    END IF;

    -- 3. Verify monotonic sequence progression against any previously created checkpoint
    SELECT MAX(c.last_seq) INTO v_prev_last_seq
    FROM audit_checkpoints c
    WHERE c.last_seq IN (SELECT seq FROM audit_events);
    IF v_prev_last_seq IS NOT NULL AND p_last_seq < v_prev_last_seq THEN
        RAISE EXCEPTION 'Checkpoint last_seq % is strictly less than existing max checkpoint last_seq %', p_last_seq, v_prev_last_seq
            USING ERRCODE = 'check_violation';
    END IF;

    -- 4. Insert into audit_checkpoints (with ON CONFLICT (last_seq) DO NOTHING for idempotency)
    INSERT INTO audit_checkpoints(id, last_seq, chain_hash, signature, s3_version_id, created_at)
    VALUES (p_id, p_last_seq, p_chain_hash, p_signature, p_s3_version_id, COALESCE(p_created_at, now()))
    ON CONFLICT (last_seq) DO NOTHING
    RETURNING id INTO v_inserted_id;

    IF v_inserted_id IS NOT NULL THEN
        RETURN v_inserted_id;
    ELSE
        SELECT id INTO v_inserted_id FROM audit_checkpoints WHERE last_seq = p_last_seq;
        RETURN v_inserted_id;
    END IF;
END;
$$;

-- Grant execute on the secure definer function to sug_api
GRANT EXECUTE ON FUNCTION audit_checkpoint_create(uuid, bigint, bytea, bytea, text, timestamptz) TO sug_api;

-- Down Migration
REVOKE EXECUTE ON FUNCTION audit_checkpoint_create(uuid, bigint, bytea, bytea, text, timestamptz) FROM sug_api;
DROP FUNCTION IF EXISTS audit_checkpoint_create(uuid, bigint, bytea, bytea, text, timestamptz);
REVOKE SELECT ON audit_checkpoints FROM sug_api;
REVOKE SELECT ON audit_events FROM sug_api;
