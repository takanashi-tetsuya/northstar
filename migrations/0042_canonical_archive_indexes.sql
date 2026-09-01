-- RFC 7622 canonical bare JIDs are stored in peer_jid/sender_jid.  Comparing
-- them case-insensitively would incorrectly merge distinct resourceparts if a
-- future query were widened and prevents PostgreSQL from using exact keys.
DROP INDEX IF EXISTS message_archive_owner_peer_bare_time_id_idx;
DROP INDEX IF EXISTS muc_messages_room_sender_bare_time_id_idx;

CREATE INDEX message_archive_owner_peer_bare_time_id_idx
    ON message_archive(owner_id, peer_jid, created_at, id);
CREATE INDEX muc_messages_room_sender_bare_time_id_idx
    ON muc_messages(room_id, split_part(sender_jid, '/', 1), created_at, id);
