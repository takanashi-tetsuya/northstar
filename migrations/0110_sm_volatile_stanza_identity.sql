-- A process-local MUC suffix can survive a PostgreSQL timeout whose commit
-- result is unknown.  Retrying by position or payload is unsafe: unrelated
-- SM traffic may advance the queue, while two legitimate stanzas may have
-- identical XML.  This opaque source identity makes the append transaction
-- idempotent without exposing implementation metadata on the XMPP wire.

ALTER TABLE sm_resume_stanzas
    ADD COLUMN volatile_source_id UUID;

CREATE UNIQUE INDEX sm_resume_stanza_volatile_source_owner
    ON sm_resume_stanzas (session_id, volatile_source_id)
    WHERE volatile_source_id IS NOT NULL;
