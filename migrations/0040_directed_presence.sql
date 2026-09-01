-- Preserve RFC 6121 directed-presence authorization across XEP-0198 stream
-- resumption. A suspended stream is still the same presence session, so its
-- temporary recipients must neither lose probe authorization nor miss the
-- final unavailable notification.
ALTER TABLE sm_resume_sessions
    ADD COLUMN directed_presence JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(directed_presence) = 'array');

ALTER TABLE sm_resume_sessions
    ADD COLUMN last_presence TEXT
        CHECK (last_presence IS NULL OR octet_length(last_presence) BETWEEN 1 AND 1048576);
