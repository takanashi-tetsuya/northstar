-- XEP-0425 moderation metadata. The stanza column is atomically replaced by
-- a tombstone so MAM and join history can no longer expose retracted payloads.
ALTER TABLE muc_messages
    ADD COLUMN retracted_at TIMESTAMPTZ,
    ADD COLUMN retracted_by VARCHAR(3071),
    ADD COLUMN retraction_reason TEXT;

CREATE INDEX muc_messages_retracted_idx
    ON muc_messages(room_id, retracted_at)
    WHERE retracted_at IS NOT NULL;
