-- no-transaction
-- Personal MAM retention is a global chronological scan. The existing archive
-- indexes begin with owner IDs and therefore cannot bound this sweep. A SQLx
-- non-transaction migration must contain exactly one concurrent index build:
-- PostgreSQL otherwise treats the multi-statement query as an implicit
-- transaction block. IF NOT EXISTS makes a retry safe if SQLx loses its
-- connection after the index build but before recording the migration.
CREATE INDEX CONCURRENTLY IF NOT EXISTS message_archive_retention_idx
    ON message_archive (created_at, id);
