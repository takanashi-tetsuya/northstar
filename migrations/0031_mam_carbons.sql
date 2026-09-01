-- Preserve the resource-qualified peer for XEP-0313 `with` matching while
-- keeping the existing bare peer column efficient for ordinary conversations.
ALTER TABLE message_archive
    ADD COLUMN peer_full_jid VARCHAR(3071);

UPDATE message_archive SET peer_full_jid = peer_jid WHERE peer_full_jid IS NULL;

ALTER TABLE message_archive
    ALTER COLUMN peer_full_jid SET NOT NULL;

CREATE INDEX message_archive_owner_time_id_idx
    ON message_archive(owner_id, created_at, id);
CREATE INDEX message_archive_owner_peer_full_time_id_idx
    ON message_archive(owner_id, peer_full_jid, created_at, id);
CREATE INDEX message_archive_owner_peer_bare_time_id_idx
    ON message_archive(owner_id, lower(peer_jid), created_at, id);
CREATE INDEX muc_messages_room_sender_full_time_id_idx
    ON muc_messages(room_id, sender_jid, created_at, id);
CREATE INDEX muc_messages_room_sender_bare_time_id_idx
    ON muc_messages(room_id, lower(split_part(sender_jid, '/', 1)), created_at, id);
