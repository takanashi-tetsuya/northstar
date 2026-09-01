-- Long-lived, privacy-preserving XEP-0359/fallback identity tombstones for
-- temporary offline delivery. While content remains queued, the marker lives
-- through the configured offline retention plus a safety day. After delivery,
-- the trigger below replaces that deadline with an exact 30-day replay grace.

CREATE TABLE offline_message_admission_capacity (
    shard SMALLINT PRIMARY KEY CHECK (shard BETWEEN 0 AND 63),
    active_records INTEGER NOT NULL DEFAULT 0
        CHECK (active_records BETWEEN 0 AND 32768)
);

INSERT INTO offline_message_admission_capacity (shard)
SELECT generate_series(0, 63)::SMALLINT;

CREATE TABLE offline_message_admissions (
    identity_digest BYTEA PRIMARY KEY,
    payload_key_id VARCHAR(64) NOT NULL,
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    offline_message_id UUID UNIQUE,
    capacity_shard SMALLINT NOT NULL
        REFERENCES offline_message_admission_capacity(shard),
    payload_mac BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ,
    CONSTRAINT offline_message_admission_identity_size
        CHECK (octet_length(identity_digest) = 32),
    CONSTRAINT offline_message_admission_payload_size
        CHECK (octet_length(payload_mac) = 32),
    CONSTRAINT offline_message_admission_expiry_order
        CHECK (expires_at IS NULL OR expires_at >= created_at),
    CONSTRAINT offline_message_admission_queue_fk
        FOREIGN KEY (offline_message_id) REFERENCES offline_messages(id)
        ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX offline_message_admission_recipient_capacity
    ON offline_message_admissions (recipient_id, expires_at, identity_digest);
CREATE INDEX offline_message_admission_shard_expiry
    ON offline_message_admissions (capacity_shard, expires_at, identity_digest)
    WHERE expires_at IS NOT NULL;
CREATE INDEX offline_message_admission_expiry
    ON offline_message_admissions (expires_at, identity_digest)
    WHERE expires_at IS NOT NULL;

CREATE FUNCTION release_offline_message_admission_capacity() RETURNS TRIGGER AS $$
BEGIN
    UPDATE offline_message_admission_capacity
       SET active_records = GREATEST(active_records - 1, 0)
     WHERE shard = OLD.capacity_shard;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER offline_message_admission_capacity_delete
AFTER DELETE ON offline_message_admissions
FOR EACH ROW EXECUTE FUNCTION release_offline_message_admission_capacity();

-- Unlimited offline retention is allowed while content is still queued, but
-- an already delivered message must not leave an immortal capacity record.
-- Once the content row is acknowledged, replace (rather than extend) the
-- queue-retention deadline with one exact, bounded 30-day replay grace.
CREATE FUNCTION detach_delivered_offline_message_admission() RETURNS TRIGGER AS $$
BEGIN
    UPDATE offline_message_admissions
       SET offline_message_id = NULL,
           expires_at = clock_timestamp() + INTERVAL '30 days'
     WHERE offline_message_id = OLD.id;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER offline_message_admission_delivery_delete
BEFORE DELETE ON offline_messages
FOR EACH ROW EXECUTE FUNCTION detach_delivered_offline_message_admission();
