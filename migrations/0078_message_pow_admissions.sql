-- Crash-recoverable message PoW admission.
--
-- Only keyed digests are retained here: neither a plaintext stanza nor an
-- unkeyed content hash is written to this anti-abuse table.  XEP-0359
-- origin-id is the preferred retry identity; clients without one fall back to
-- their one-use challenge UUID.  Rows are deliberately time bounded and the
-- application removes them in small batches.

CREATE TABLE abuse_message_admission_capacity (
    shard SMALLINT PRIMARY KEY CHECK (shard BETWEEN 0 AND 63),
    active_records INTEGER NOT NULL DEFAULT 0
        CHECK (active_records BETWEEN 0 AND 32768)
);

INSERT INTO abuse_message_admission_capacity (shard)
SELECT generate_series(0, 63)::SMALLINT;

CREATE TABLE abuse_message_admissions (
    admission_key BYTEA PRIMARY KEY,
    key_id VARCHAR(64) NOT NULL,
    actor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    capacity_shard SMALLINT NOT NULL
        REFERENCES abuse_message_admission_capacity(shard),
    payload_mac BYTEA NOT NULL,
    proof_challenge_id UUID,
    state VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'accepted')),
    lease_token UUID NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    CONSTRAINT abuse_message_admission_key_size
        CHECK (octet_length(admission_key) = 32),
    CONSTRAINT abuse_message_payload_mac_size
        CHECK (octet_length(payload_mac) = 32),
    CONSTRAINT abuse_message_admission_state_time
        CHECK ((state = 'pending' AND accepted_at IS NULL)
            OR (state = 'accepted' AND accepted_at IS NOT NULL)),
    CONSTRAINT abuse_message_admission_lease_time
        CHECK (lease_expires_at >= created_at)
);

CREATE UNIQUE INDEX abuse_message_admission_proof_key
    ON abuse_message_admissions (proof_challenge_id)
    WHERE proof_challenge_id IS NOT NULL;
CREATE INDEX abuse_message_admission_actor_capacity
    ON abuse_message_admissions (actor_id, expires_at, admission_key);
CREATE INDEX abuse_message_admission_shard_expiry
    ON abuse_message_admissions (capacity_shard, expires_at, admission_key);
CREATE INDEX abuse_message_admission_expiry
    ON abuse_message_admissions (expires_at, admission_key);

-- The insert path increments its chosen shard explicitly while holding that
-- row lock.  Every deletion, including account CASCADE and bounded retention
-- cleanup, releases the slot through this trigger in the same transaction.
CREATE FUNCTION release_abuse_message_admission_capacity() RETURNS TRIGGER AS $$
BEGIN
    UPDATE abuse_message_admission_capacity
       SET active_records = GREATEST(active_records - 1, 0)
     WHERE shard = OLD.capacity_shard;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER abuse_message_admission_capacity_delete
AFTER DELETE ON abuse_message_admissions
FOR EACH ROW EXECUTE FUNCTION release_abuse_message_admission_capacity();
