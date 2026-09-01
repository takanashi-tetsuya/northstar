-- Durable REST operation runtime. 0057 deliberately introduced only the
-- journal shell; no released worker wrote rows before this migration. Refuse
-- to reinterpret hand-written/in-development rows under stronger semantics.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM api_operation_journal) THEN
        RAISE EXCEPTION
            'api_operation_journal is not empty; audit and remove legacy development rows before applying operation runtime semantics';
    END IF;
END $$;

CREATE TABLE api_operation_kinds (
    kind VARCHAR(128) PRIMARY KEY CHECK (octet_length(kind) BETWEEN 1 AND 128),
    supports_targets BOOLEAN NOT NULL,
    supports_cancel BOOLEAN NOT NULL,
    authorization_policy VARCHAR(32) NOT NULL CHECK (
        authorization_policy IN ('reauthorize_until_effect','committed_consequence')
    ),
    UNIQUE(kind,authorization_policy),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO api_operation_kinds
    (kind,supports_targets,supports_cancel,authorization_policy) VALUES
    ('admin.user_session_cleanup', TRUE,  FALSE, 'committed_consequence'),
    ('admin.tls_reload',           TRUE,  TRUE,  'reauthorize_until_effect'),
    ('admin.panic_disconnect',     TRUE,  TRUE,  'reauthorize_until_effect'),
    ('admin.session_kick',         TRUE,  TRUE,  'reauthorize_until_effect'),
    ('admin.broadcast',            TRUE,  TRUE,  'reauthorize_until_effect'),
    ('admin.muc_destroy',          TRUE,  FALSE, 'committed_consequence'),
    ('admin.island_converge',      TRUE,  FALSE, 'committed_consequence');

CREATE FUNCTION reject_api_operation_kind_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'built-in API operation kinds are immutable'
        USING ERRCODE='object_not_in_prerequisite_state';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER reject_api_operation_kind_update_delete
BEFORE UPDATE OR DELETE ON api_operation_kinds
FOR EACH ROW EXECUTE FUNCTION reject_api_operation_kind_mutation();

ALTER TABLE api_operation_journal
    RENAME COLUMN lease_owner TO worker_id;

-- 0057 used unnamed status/completion checks. Replace them without relying on
-- PostgreSQL's generated constraint names so the upgrade is deterministic.
DO $$
DECLARE constraint_name TEXT;
BEGIN
    FOR constraint_name IN
        SELECT conname FROM pg_constraint
        WHERE conrelid='api_operation_journal'::regclass AND contype='c'
          AND pg_get_constraintdef(oid) LIKE '%status%pending%running%succeeded%failed%canceled%'
    LOOP
        EXECUTE format('ALTER TABLE api_operation_journal DROP CONSTRAINT %I', constraint_name);
    END LOOP;
END $$;

ALTER TABLE api_operation_journal
    ADD COLUMN actor_subject_id UUID,
    ADD COLUMN authorization_policy VARCHAR(32),
    ADD COLUMN payload_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 20,
    ADD COLUMN deadline_at TIMESTAMPTZ NOT NULL DEFAULT
        (clock_timestamp() + INTERVAL '24 hours'),
    ADD COLUMN lease_token UUID,
    ADD COLUMN cancel_requested_at TIMESTAMPTZ,
    ADD COLUMN cancel_requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN point_of_no_return_at TIMESTAMPTZ,
    ADD COLUMN last_error_at TIMESTAMPTZ;

UPDATE api_operation_journal
SET actor_subject_id=actor_id,
    authorization_policy='reauthorize_until_effect';

ALTER TABLE api_operation_journal
    ALTER COLUMN actor_subject_id SET NOT NULL,
    ALTER COLUMN actor_auth_generation SET NOT NULL,
    ALTER COLUMN authorization_policy SET NOT NULL,
    ADD CONSTRAINT api_operation_status_check CHECK (
        status IN ('pending','running','succeeded','failed','canceled','indeterminate')
    ),
    ADD CONSTRAINT api_operation_kind_fk
        FOREIGN KEY(kind) REFERENCES api_operation_kinds(kind),
    ADD CONSTRAINT api_operation_kind_policy_fk
        FOREIGN KEY(kind,authorization_policy)
        REFERENCES api_operation_kinds(kind,authorization_policy),
    ADD CONSTRAINT api_operation_authorization_policy_check CHECK (
        authorization_policy IN ('reauthorize_until_effect','committed_consequence')
    ),
    ADD CONSTRAINT api_operation_payload_version_check CHECK (
        payload_version BETWEEN 1 AND 32767
    ),
    ADD CONSTRAINT api_operation_payload_size_check CHECK (
        octet_length(payload::text) <= 262144
    ),
    ADD CONSTRAINT api_operation_result_size_check CHECK (
        result IS NULL OR octet_length(result::text) <= 1048576
    ),
    ADD CONSTRAINT api_operation_error_code_check CHECK (
        error_code IS NULL OR octet_length(error_code) BETWEEN 1 AND 128
    ),
    ADD CONSTRAINT api_operation_attempt_budget_check CHECK (
        max_attempts BETWEEN 1 AND 1000 AND attempts BETWEEN 0 AND max_attempts
    ),
    ADD CONSTRAINT api_operation_deadline_check CHECK (
        deadline_at > created_at
        AND next_attempt_at <= deadline_at
        AND (lease_expires_at IS NULL OR lease_expires_at <= deadline_at)
    ),
    ADD CONSTRAINT api_operation_cancel_actor_check CHECK (
        cancel_requested_by IS NULL OR cancel_requested_at IS NOT NULL
    ),
    ADD CONSTRAINT api_operation_idempotency_liveness_check CHECK (
        status IN ('succeeded','failed','canceled','indeterminate') OR idempotency_id IS NOT NULL
    ),
    ADD CONSTRAINT api_operation_strict_lease_state_check CHECK (
        (status='pending'
            AND worker_id IS NULL
            AND lease_token IS NULL
            AND lease_expires_at IS NULL
            AND completed_at IS NULL)
        OR
        (status='running'
            AND worker_id IS NOT NULL
            AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND completed_at IS NULL)
        OR
        (status IN ('succeeded','failed','canceled','indeterminate')
            AND worker_id IS NULL
            AND lease_token IS NULL
            AND lease_expires_at IS NULL
            AND completed_at IS NOT NULL)
    ),
    ADD CONSTRAINT api_operation_terminal_semantics_check CHECK (
        (status <> 'succeeded' OR error_code IS NULL)
        AND (status <> 'failed' OR error_code IS NOT NULL)
        AND (status <> 'indeterminate' OR (
            error_code IS NOT NULL AND point_of_no_return_at IS NOT NULL
        ))
        AND (status <> 'canceled' OR (
            cancel_requested_at IS NOT NULL
            AND point_of_no_return_at IS NULL
        ))
        AND (point_of_no_return_at IS NULL OR status IN ('running','succeeded','failed','indeterminate'))
        AND (completed_at IS NULL OR completed_at >= created_at)
        AND (point_of_no_return_at IS NULL OR point_of_no_return_at >= created_at)
        AND (last_error_at IS NULL OR last_error_at >= created_at)
    );

DROP INDEX api_operation_due_idx;
CREATE INDEX api_operation_due_idx
    ON api_operation_journal(next_attempt_at,created_at,id)
    WHERE status='pending';
CREATE INDEX api_operation_expired_lease_idx
    ON api_operation_journal(lease_expires_at,id)
    WHERE status='running';
CREATE INDEX api_operation_deadline_idx
    ON api_operation_journal(deadline_at,id)
    WHERE status IN ('pending','running');

-- Singleton controls must serialize, while resource-scoped controls may only
-- have one active intent per immutable target epoch. Broadcasts deliberately
-- remain queueable.
CREATE UNIQUE INDEX api_operation_active_singleton_key
    ON api_operation_journal(kind)
    WHERE status IN ('pending','running','indeterminate')
      AND kind IN ('admin.tls_reload','admin.panic_disconnect','admin.island_converge');
CREATE UNIQUE INDEX api_operation_active_resource_key
    ON api_operation_journal(kind,target)
    WHERE status IN ('pending','running','indeterminate')
      AND kind IN ('admin.user_session_cleanup','admin.session_kick','admin.muc_destroy');

CREATE TABLE api_operation_targets (
    id UUID PRIMARY KEY,
    operation_id UUID NOT NULL REFERENCES api_operation_journal(id) ON DELETE CASCADE,
    target_key TEXT NOT NULL CHECK (octet_length(target_key) BETWEEN 1 AND 4096),
    ordinal BIGINT NOT NULL CHECK (ordinal >= 0),
    status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending','running','succeeded','failed','canceled','indeterminate')
    ),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (
        octet_length(payload::text) <= 65536
    ),
    result JSONB CHECK (
        result IS NULL OR octet_length(result::text) <= 1048576
    ),
    error_code VARCHAR(128) CHECK (
        error_code IS NULL OR octet_length(error_code) BETWEEN 1 AND 128
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 20 CHECK (max_attempts BETWEEN 1 AND 1000),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    deadline_at TIMESTAMPTZ NOT NULL,
    worker_id UUID,
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    cancel_requested_at TIMESTAMPTZ,
    point_of_no_return_at TIMESTAMPTZ,
    last_error_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    UNIQUE(operation_id,target_key),
    UNIQUE(operation_id,ordinal),
    CHECK (attempts <= max_attempts),
    CHECK (deadline_at > created_at
        AND next_attempt_at <= deadline_at
        AND (lease_expires_at IS NULL OR lease_expires_at <= deadline_at)),
    CHECK (
        (status='pending'
            AND worker_id IS NULL
            AND lease_token IS NULL
            AND lease_expires_at IS NULL
            AND completed_at IS NULL)
        OR
        (status='running'
            AND worker_id IS NOT NULL
            AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND completed_at IS NULL)
        OR
        (status IN ('succeeded','failed','canceled','indeterminate')
            AND worker_id IS NULL
            AND lease_token IS NULL
            AND lease_expires_at IS NULL
            AND completed_at IS NOT NULL)
    ),
    CHECK (
        (status <> 'succeeded' OR error_code IS NULL)
        AND (status <> 'failed' OR error_code IS NOT NULL)
        AND (status <> 'indeterminate' OR (
            error_code IS NOT NULL AND point_of_no_return_at IS NOT NULL
        ))
        AND (status <> 'canceled' OR (
            cancel_requested_at IS NOT NULL
            AND point_of_no_return_at IS NULL
        ))
        AND (point_of_no_return_at IS NULL OR status IN ('running','succeeded','failed','indeterminate'))
        AND (completed_at IS NULL OR completed_at >= created_at)
        AND (point_of_no_return_at IS NULL OR point_of_no_return_at >= created_at)
        AND (last_error_at IS NULL OR last_error_at >= created_at)
    )
);

CREATE INDEX api_operation_target_due_idx
    ON api_operation_targets(operation_id,next_attempt_at,ordinal,id)
    WHERE status='pending';
CREATE INDEX api_operation_target_expired_lease_idx
    ON api_operation_targets(operation_id,lease_expires_at,id)
    WHERE status='running';

-- Defence in depth: application validation is intentionally duplicated in
-- PostgreSQL so a future worker, maintenance script, or compromised API node
-- cannot persist credentials or an unversioned/unknown operation shape.
CREATE FUNCTION api_json_contains_secret_key(document JSONB) RETURNS BOOLEAN AS $$
DECLARE
    entry RECORD;
    normalized TEXT;
BEGIN
    IF jsonb_typeof(document) = 'object' THEN
        FOR entry IN SELECT key,value FROM jsonb_each(document) LOOP
            normalized := replace(lower(entry.key),'-','_');
            IF normalized LIKE '%password%'
               OR normalized LIKE '%secret%'
               OR normalized LIKE '%private_key%'
               OR normalized LIKE '%bearer%'
               OR normalized IN ('token','authorization','cookie')
               OR api_json_contains_secret_key(entry.value)
            THEN
                RETURN TRUE;
            END IF;
        END LOOP;
    ELSIF jsonb_typeof(document) = 'array' THEN
        FOR entry IN SELECT value FROM jsonb_array_elements(document) LOOP
            IF api_json_contains_secret_key(entry.value) THEN
                RETURN TRUE;
            END IF;
        END LOOP;
    END IF;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION validate_api_operation_payload() RETURNS TRIGGER AS $$
DECLARE
    allowed TEXT[];
    required TEXT[];
    field TEXT;
BEGIN
    IF NEW.payload_version <> 1 OR jsonb_typeof(NEW.payload) <> 'object' THEN
        RAISE EXCEPTION 'unsupported operation payload version or type'
            USING ERRCODE='check_violation';
    END IF;
    IF api_json_contains_secret_key(NEW.payload) THEN
        RAISE EXCEPTION 'operation payload contains a credential-like key'
            USING ERRCODE='check_violation';
    END IF;

    CASE NEW.kind
        WHEN 'admin.user_session_cleanup' THEN
            allowed := ARRAY['user_id','auth_generation']; required := allowed;
        WHEN 'admin.tls_reload' THEN
            allowed := ARRAY[]::TEXT[]; required := allowed;
        WHEN 'admin.panic_disconnect' THEN
            allowed := ARRAY['reason']; required := ARRAY[]::TEXT[];
        WHEN 'admin.session_kick' THEN
            allowed := ARRAY['user_id','auth_generation','connection_id']; required := allowed;
        WHEN 'admin.broadcast' THEN
            allowed := ARRAY['message']; required := allowed;
        WHEN 'admin.muc_destroy' THEN
            allowed := ARRAY['room_jid','reason','alternate_jid']; required := ARRAY['room_jid'];
        WHEN 'admin.island_converge' THEN
            allowed := ARRAY['mode','epoch']; required := allowed;
        ELSE
            RAISE EXCEPTION 'unsupported operation kind'
                USING ERRCODE='check_violation';
    END CASE;

    IF EXISTS (SELECT 1 FROM jsonb_object_keys(NEW.payload) AS keys(key) WHERE NOT key=ANY(allowed))
       OR EXISTS (SELECT 1 FROM unnest(required) AS keys(key) WHERE NOT NEW.payload ? key)
    THEN
        RAISE EXCEPTION 'operation payload fields do not match its kind'
            USING ERRCODE='check_violation';
    END IF;

    IF NEW.payload ? 'user_id' THEN
        PERFORM (NEW.payload->>'user_id')::UUID;
    END IF;
    IF NEW.payload ? 'auth_generation' AND
       (jsonb_typeof(NEW.payload->'auth_generation') <> 'number'
        OR (NEW.payload->>'auth_generation')::BIGINT < 0) THEN
        RAISE EXCEPTION 'invalid auth_generation' USING ERRCODE='check_violation';
    END IF;
    IF NEW.payload ? 'epoch' AND
       (jsonb_typeof(NEW.payload->'epoch') <> 'number'
        OR (NEW.payload->>'epoch')::BIGINT < 0) THEN
        RAISE EXCEPTION 'invalid epoch' USING ERRCODE='check_violation';
    END IF;
    FOREACH field IN ARRAY ARRAY['reason','connection_id','message','room_jid','alternate_jid','mode'] LOOP
        IF NEW.payload ? field AND
           (jsonb_typeof(NEW.payload->field) <> 'string'
            OR octet_length(NEW.payload->>field) < CASE WHEN field IN ('reason','alternate_jid') THEN 0 ELSE 1 END
            OR octet_length(NEW.payload->>field) > CASE WHEN field='message' THEN 32768 ELSE 4096 END)
        THEN
            RAISE EXCEPTION 'invalid operation string field'
                USING ERRCODE='check_violation';
        END IF;
    END LOOP;
    RETURN NEW;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION 'operation payload contains an invalid typed value'
        USING ERRCODE='check_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER validate_api_operation_payload_write
BEFORE INSERT OR UPDATE OF kind,payload_version,payload ON api_operation_journal
FOR EACH ROW EXECUTE FUNCTION validate_api_operation_payload();

CREATE FUNCTION validate_api_operation_target_payload() RETURNS TRIGGER AS $$
BEGIN
    IF jsonb_typeof(NEW.payload) <> 'object' OR api_json_contains_secret_key(NEW.payload) THEN
        RAISE EXCEPTION 'operation target payload is invalid or contains credentials'
            USING ERRCODE='check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER validate_api_operation_target_payload_write
BEFORE INSERT OR UPDATE OF payload ON api_operation_targets
FOR EACH ROW EXECUTE FUNCTION validate_api_operation_target_payload();

CREATE FUNCTION guard_api_operation_mutation() RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.request_id,NEW.actor_subject_id,NEW.actor_auth_generation,
        NEW.authorization_policy,NEW.kind,NEW.target,NEW.payload_version,
        NEW.payload,NEW.max_attempts,NEW.deadline_at,NEW.created_at)
       IS DISTINCT FROM
       (OLD.request_id,OLD.actor_subject_id,OLD.actor_auth_generation,
        OLD.authorization_policy,OLD.kind,OLD.target,OLD.payload_version,
        OLD.payload,OLD.max_attempts,OLD.deadline_at,OLD.created_at)
    THEN
        RAISE EXCEPTION 'authorized operation intent is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF OLD.point_of_no_return_at IS NOT NULL
       AND NEW.point_of_no_return_at IS DISTINCT FROM OLD.point_of_no_return_at THEN
        RAISE EXCEPTION 'operation point of no return is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF OLD.cancel_requested_at IS NOT NULL
       AND NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at THEN
        RAISE EXCEPTION 'operation cancellation time is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF OLD.cancel_requested_by IS NOT NULL
       AND NEW.cancel_requested_by IS DISTINCT FROM OLD.cancel_requested_by THEN
        RAISE EXCEPTION 'operation cancellation actor is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF OLD.completed_at IS NOT NULL
       AND NEW.completed_at IS DISTINCT FROM OLD.completed_at THEN
        RAISE EXCEPTION 'operation completion time is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status='pending' AND NEW.status IN ('running','failed','canceled')) OR
        (OLD.status='running' AND NEW.status IN ('pending','succeeded','failed','canceled','indeterminate')) OR
        (OLD.status='indeterminate' AND NEW.status IN ('succeeded','failed'))
    ) THEN
        RAISE EXCEPTION 'invalid operation state transition'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF OLD.status IN ('succeeded','failed','canceled') AND
       (NEW.result,NEW.error_code,NEW.last_error_at)
       IS DISTINCT FROM (OLD.result,OLD.error_code,OLD.last_error_at)
    THEN
        RAISE EXCEPTION 'terminal operation outcome is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER guard_api_operation_update
BEFORE UPDATE ON api_operation_journal
FOR EACH ROW EXECUTE FUNCTION guard_api_operation_mutation();

CREATE FUNCTION guard_api_operation_target_mutation() RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.operation_id,NEW.target_key,NEW.ordinal,NEW.payload,
        NEW.max_attempts,NEW.deadline_at,NEW.created_at)
       IS DISTINCT FROM
       (OLD.operation_id,OLD.target_key,OLD.ordinal,OLD.payload,
        OLD.max_attempts,OLD.deadline_at,OLD.created_at)
    THEN
        RAISE EXCEPTION 'authorized operation target intent is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF OLD.point_of_no_return_at IS NOT NULL
       AND NEW.point_of_no_return_at IS DISTINCT FROM OLD.point_of_no_return_at THEN
        RAISE EXCEPTION 'target point of no return is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF OLD.cancel_requested_at IS NOT NULL
       AND NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at THEN
        RAISE EXCEPTION 'target cancellation time is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF OLD.completed_at IS NOT NULL
       AND NEW.completed_at IS DISTINCT FROM OLD.completed_at THEN
        RAISE EXCEPTION 'target completion time is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status='pending' AND NEW.status IN ('running','failed','canceled')) OR
        (OLD.status='running' AND NEW.status IN ('pending','succeeded','failed','canceled','indeterminate')) OR
        (OLD.status='indeterminate' AND NEW.status IN ('succeeded','failed'))
    ) THEN
        RAISE EXCEPTION 'invalid operation target state transition'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    IF OLD.status IN ('succeeded','failed','canceled') AND
       (NEW.result,NEW.error_code,NEW.last_error_at)
       IS DISTINCT FROM (OLD.result,OLD.error_code,OLD.last_error_at)
    THEN
        RAISE EXCEPTION 'terminal operation target outcome is immutable'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER guard_api_operation_target_update
BEFORE UPDATE ON api_operation_targets
FOR EACH ROW EXECUTE FUNCTION guard_api_operation_target_mutation();

-- The ordinary idempotency cleanup may expire completed operations, but must
-- never detach an active operation from the exact request which authorized it.
CREATE FUNCTION preserve_nonterminal_operation_idempotency() RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM api_operation_journal
        WHERE idempotency_id=OLD.id AND status IN ('pending','running','indeterminate')
    ) THEN
        RETURN NULL;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER preserve_nonterminal_operation_idempotency_delete
BEFORE DELETE ON api_idempotency_records
FOR EACH ROW EXECUTE FUNCTION preserve_nonterminal_operation_idempotency();
