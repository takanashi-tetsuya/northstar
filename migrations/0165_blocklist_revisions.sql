-- Existing lists start at revision zero. Journal retention matches the
-- roster journal: keep the last 10,000 committed changes per account.
CREATE TABLE blocklist_revisions (
    owner_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK (revision > 0)
);

CREATE TABLE blocklist_change_log (
    owner_id UUID NOT NULL REFERENCES blocklist_revisions(owner_id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK (revision > 0),
    action TEXT NOT NULL CHECK (action IN ('block', 'unblock', 'unblock-all')),
    patterns TEXT[] NOT NULL CHECK (cardinality(patterns) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (owner_id, revision)
);
