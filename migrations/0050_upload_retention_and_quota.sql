-- Active per-account reservations are counted by user and expiry. This also
-- keeps quota checks and retention cleanup bounded as the table grows.
CREATE INDEX upload_slots_user_expiry_idx
    ON upload_slots(user_id, expires_at);

-- Account deletion cascades upload_slots, but the immutable object lives
-- outside PostgreSQL. Queue every object key in the same deletion transaction
-- so a transient storage failure cannot create an untracked orphan.
CREATE TABLE upload_cleanup_queue (
    object_id UUID PRIMARY KEY,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX upload_cleanup_queue_order_idx
    ON upload_cleanup_queue(queued_at, object_id);
