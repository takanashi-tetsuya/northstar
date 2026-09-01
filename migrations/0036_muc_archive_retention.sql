-- no-transaction
-- Keep this as one statement; see migration 0035.
CREATE INDEX CONCURRENTLY IF NOT EXISTS muc_messages_retention_idx
    ON muc_messages (created_at, id);
