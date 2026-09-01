CREATE INDEX idx_muc_messages_room_sender_created_id
    ON muc_messages(room_id, sender_jid, created_at, id);
