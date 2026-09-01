-- REST control-plane durability and stable pagination primitives.
-- Raw Idempotency-Key values and replayable bearer/token responses must never
-- be stored. Application code stores a keyed scope digest and AEAD ciphertext.

ALTER TABLE abuse_pow_challenges
    ADD COLUMN key_id VARCHAR(32) NOT NULL DEFAULT 'legacy-current'
        CHECK (octet_length(key_id) BETWEEN 8 AND 32);

CREATE TABLE api_idempotency_records (
    id UUID PRIMARY KEY,
    scope_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(scope_hash) = 32),
    principal_hash BYTEA NOT NULL CHECK (octet_length(principal_hash) = 32),
    scope_key_id VARCHAR(32) NOT NULL CHECK (octet_length(scope_key_id) BETWEEN 8 AND 32),
    request_actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ownership_actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    principal_kind VARCHAR(16) NOT NULL CHECK (
        principal_kind IN ('anonymous','user','admin','upload')
    ),
    method VARCHAR(8) NOT NULL CHECK (method IN ('POST','PUT','PATCH','DELETE')),
    route TEXT NOT NULL CHECK (octet_length(route) BETWEEN 1 AND 512),
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    request_id UUID NOT NULL UNIQUE,
    state VARCHAR(16) NOT NULL CHECK (state IN ('started','completed')),
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    guard_verified_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts BETWEEN 1 AND 1000),
    response_status SMALLINT CHECK (response_status BETWEEN 100 AND 599),
    response_key_id VARCHAR(32) CHECK (
        response_key_id IS NULL OR octet_length(response_key_id) BETWEEN 8 AND 32
    ),
    response_nonce BYTEA CHECK (
        response_nonce IS NULL OR octet_length(response_nonce) = 12
    ),
    response_ciphertext BYTEA,
    replay_session_id UUID,
    replay_session_token_hash BYTEA CHECK (
        replay_session_token_hash IS NULL OR octet_length(replay_session_token_hash) = 32
    ),
    replay_auth_generation BIGINT CHECK (
        replay_auth_generation IS NULL OR replay_auth_generation >= 0
    ),
    replay_session_expires_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK (guard_verified_at IS NULL OR guard_verified_at >= created_at),
    CHECK (
        (replay_session_id IS NULL)
        = (replay_session_token_hash IS NULL)
        AND (replay_session_id IS NULL)
        = (replay_auth_generation IS NULL)
        AND (replay_session_id IS NULL)
        = (replay_session_expires_at IS NULL)
    ),
    CHECK (
        (state = 'started'
            AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND response_status IS NULL
            AND response_key_id IS NULL
            AND response_nonce IS NULL
            AND response_ciphertext IS NULL
            AND completed_at IS NULL)
        OR
        (state = 'completed'
            AND lease_token IS NULL
            AND lease_expires_at IS NULL
            AND response_status IS NOT NULL
            AND response_key_id IS NOT NULL
            AND response_nonce IS NOT NULL
            AND response_ciphertext IS NOT NULL
            AND completed_at IS NOT NULL)
    )
);

CREATE INDEX api_idempotency_expiry_idx
    ON api_idempotency_records (expires_at, id);
CREATE INDEX api_idempotency_started_principal_idx
    ON api_idempotency_records (principal_hash, lease_expires_at, id)
    WHERE state = 'started';
CREATE INDEX api_idempotency_principal_expiry_idx
    ON api_idempotency_records (principal_hash, expires_at, id);

-- A trigger-maintained singleton makes the global admission waterline atomic
-- across processes and catches cascaded deletes as well as worker cleanup.
CREATE TABLE api_idempotency_capacity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    active_records BIGINT NOT NULL DEFAULT 0 CHECK (active_records >= 0)
);
INSERT INTO api_idempotency_capacity(singleton,active_records) VALUES(TRUE,0);

CREATE FUNCTION maintain_api_idempotency_capacity() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE api_idempotency_capacity
        SET active_records=active_records+1 WHERE singleton=TRUE;
        RETURN NEW;
    END IF;
    UPDATE api_idempotency_capacity
    SET active_records=active_records-1 WHERE singleton=TRUE;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER api_idempotency_capacity_insert
AFTER INSERT ON api_idempotency_records
FOR EACH ROW EXECUTE FUNCTION maintain_api_idempotency_capacity();
CREATE TRIGGER api_idempotency_capacity_delete
AFTER DELETE ON api_idempotency_records
FOR EACH ROW EXECUTE FUNCTION maintain_api_idempotency_capacity();
CREATE INDEX api_idempotency_request_actor_idx
    ON api_idempotency_records (request_actor_id, created_at DESC, id DESC)
    WHERE request_actor_id IS NOT NULL;
CREATE INDEX api_idempotency_owner_idx
    ON api_idempotency_records (ownership_actor_id, created_at DESC, id DESC)
    WHERE ownership_actor_id IS NOT NULL;

-- External effects are committed as durable intent before a worker performs
-- them. A unique idempotency link prevents duplicate operations on retries.
CREATE TABLE api_operation_journal (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL,
    idempotency_id UUID UNIQUE REFERENCES api_idempotency_records(id) ON DELETE SET NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_auth_generation BIGINT CHECK (actor_auth_generation IS NULL OR actor_auth_generation >= 0),
    kind VARCHAR(128) NOT NULL CHECK (octet_length(kind) BETWEEN 1 AND 128),
    target TEXT CHECK (target IS NULL OR octet_length(target) <= 4096),
    status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending','running','succeeded','failed','canceled')
    ),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB,
    error_code VARCHAR(128),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_owner UUID,
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (
        (status IN ('pending','running') AND completed_at IS NULL)
        OR (status IN ('succeeded','failed','canceled') AND completed_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX api_operation_request_idx
    ON api_operation_journal (request_id);
CREATE INDEX api_operation_due_idx
    ON api_operation_journal (next_attempt_at, created_at, id)
    WHERE status IN ('pending','running');
CREATE INDEX api_operation_actor_idx
    ON api_operation_journal (actor_id, created_at DESC, id DESC)
    WHERE actor_id IS NOT NULL;

ALTER TABLE audit_log
    ADD COLUMN request_id UUID,
    ADD COLUMN operation_id UUID;
CREATE INDEX audit_log_request_idx ON audit_log(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX audit_log_operation_idx ON audit_log(operation_id) WHERE operation_id IS NOT NULL;

-- Preserve all historical evidence while making its order and archive
-- identity unique within a report. Existing data is deterministically
-- re-numbered; an impossible over-20 legacy report fails migration rather
-- than discarding moderation evidence.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM abuse_report_evidence
        GROUP BY report_id HAVING COUNT(*) > 20
    ) THEN
        RAISE EXCEPTION 'cannot enforce report evidence uniqueness: a report contains more than 20 evidence rows';
    END IF;
END $$;

WITH ranked AS (
    SELECT id,
           (ROW_NUMBER() OVER (
               PARTITION BY report_id ORDER BY position, created_at, id
           ) - 1)::INTEGER AS new_position
    FROM abuse_report_evidence
)
UPDATE abuse_report_evidence AS evidence
SET position = ranked.new_position
FROM ranked
WHERE evidence.id = ranked.id
  AND evidence.position IS DISTINCT FROM ranked.new_position;

ALTER TABLE abuse_report_evidence
    ADD CONSTRAINT abuse_report_evidence_report_position_key
        UNIQUE (report_id, position);

-- A legacy client could select the same archive row more than once. Keep the
-- copied evidence/digest, but retain the live archive FK only on the first
-- occurrence so the new identity constraint does not discard evidence.
WITH duplicate_archives AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY report_id, archive_id ORDER BY position, created_at, id
           ) AS occurrence
    FROM abuse_report_evidence
    WHERE archive_id IS NOT NULL
)
UPDATE abuse_report_evidence AS evidence
SET archive_id = NULL
FROM duplicate_archives
WHERE evidence.id = duplicate_archives.id
  AND duplicate_archives.occurrence > 1;

CREATE UNIQUE INDEX abuse_report_evidence_report_archive_key
    ON abuse_report_evidence (report_id, archive_id)
    WHERE archive_id IS NOT NULL;

-- PostgreSQL char_length and Rust `str::chars().count()` both count Unicode
-- code points. NOT VALID preserves an upgrade path for legacy rows while the
-- constraints are still enforced for every new or changed API record.
ALTER TABLE abuse_reports
    ADD CONSTRAINT abuse_reports_description_length_check
    CHECK (char_length(description) <= 4000 AND octet_length(description) <= 16000) NOT VALID;
ALTER TABLE abuse_appeals
    ADD CONSTRAINT abuse_appeals_reason_length_check
    CHECK (
        char_length(reason) BETWEEN 20 AND 4000
        AND octet_length(reason) <= 16000
    ) NOT VALID;
ALTER TABLE abuse_report_evidence
    ADD CONSTRAINT abuse_report_evidence_body_length_check
    CHECK (
        char_length(body_text) BETWEEN 1 AND 8000
        AND octet_length(body_text) <= 32000
    ) NOT VALID,
    ADD CONSTRAINT abuse_report_evidence_client_id_bytes_check
    CHECK (client_message_id IS NULL OR octet_length(client_message_id) <= 512) NOT VALID;

-- Upload PUT ownership becomes a renewable lease rather than a process-local
-- boolean. Completion metadata lets an authenticated retry distinguish an
-- already committed identical object from a conflicting replay.
ALTER TABLE upload_slots
    ADD COLUMN claim_token UUID,
    ADD COLUMN claim_expires_at TIMESTAMPTZ,
    ADD COLUMN upload_attempts BIGINT NOT NULL DEFAULT 0 CHECK (upload_attempts >= 0),
    ADD COLUMN content_sha256 BYTEA CHECK (
        content_sha256 IS NULL OR octet_length(content_sha256) = 32
    ),
    ADD COLUMN completed_at TIMESTAMPTZ,
    ADD COLUMN replay_count BIGINT NOT NULL DEFAULT 0 CHECK (replay_count >= 0),
    ADD COLUMN last_replayed_at TIMESTAMPTZ,
    ADD CONSTRAINT upload_slots_claim_pair_check CHECK (
        (claim_token IS NULL) = (claim_expires_at IS NULL)
    ),
    ADD CONSTRAINT upload_slots_completion_check CHECK (
        (content_sha256 IS NULL) = (completed_at IS NULL)
        AND (uploaded OR content_sha256 IS NULL)
    );

CREATE INDEX upload_slots_claim_expiry_idx
    ON upload_slots (claim_expires_at, id)
    WHERE claim_token IS NOT NULL AND NOT uploaded;

-- Deterministic keyset order for every REST collection. Existing archive and
-- room-history indexes already include (created_at,id).
CREATE INDEX users_api_page_idx ON users (created_at DESC, id DESC);
CREATE INDEX api_sessions_api_page_idx ON api_sessions (created_at DESC, id DESC);
CREATE INDEX invitation_tokens_api_page_idx
    ON invitation_tokens (created_at DESC, id DESC);
CREATE INDEX abuse_reports_api_page_idx
    ON abuse_reports (created_at DESC, id DESC);
CREATE INDEX abuse_reports_status_api_page_idx
    ON abuse_reports (status, created_at DESC, id DESC);
CREATE INDEX muc_rooms_api_page_idx ON muc_rooms (created_at DESC, id DESC);
