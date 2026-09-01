-- no-transaction
-- Keep this as one statement; see migration 0035.
CREATE INDEX CONCURRENTLY IF NOT EXISTS offline_messages_retention_idx
    ON offline_messages (created_at, id);
