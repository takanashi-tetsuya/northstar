-- Stable administrator keyset pages. Partial indexes keep the operational
-- queue hot paths small while these general indexes serve audit/history reads.
CREATE INDEX api_operation_admin_page_idx
    ON api_operation_journal(created_at DESC,id DESC);

CREATE INDEX api_operation_admin_status_page_idx
    ON api_operation_journal(status,created_at DESC,id DESC);

CREATE INDEX api_operation_admin_kind_page_idx
    ON api_operation_journal(kind,created_at DESC,id DESC);

CREATE INDEX api_operation_target_admin_page_idx
    ON api_operation_targets(operation_id,created_at DESC,id DESC);

-- A destroy request becomes authoritative in the same transaction as the
-- operation journal row. The tombstone prevents a room-create race from
-- resurrecting the address before/after the asynchronous DELETE.
CREATE TABLE api_muc_destroy_intents (
    room_jid TEXT PRIMARY KEY CHECK (octet_length(room_jid) BETWEEN 3 AND 4096),
    localpart TEXT NOT NULL,
    operation_id UUID NOT NULL UNIQUE REFERENCES api_operation_journal(id) ON DELETE RESTRICT,
    applied_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION reject_tombstoned_muc_room() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'northstar:muc-room:' || NEW.localpart, 0
    ));
    IF EXISTS (
        SELECT 1 FROM api_muc_destroy_intents
        WHERE localpart=NEW.localpart
    ) THEN
        RAISE EXCEPTION 'MUC room address is tombstoned by a durable destroy operation'
            USING ERRCODE='object_not_in_prerequisite_state';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER reject_tombstoned_muc_room_insert_update
BEFORE INSERT OR UPDATE OF localpart ON muc_rooms
FOR EACH ROW EXECUTE FUNCTION reject_tombstoned_muc_room();
