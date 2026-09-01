CREATE TABLE roster_change_log (
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    contact_jid VARCHAR(3071) NOT NULL,
    display_name VARCHAR(255),
    subscription VARCHAR(16),
    ask VARCHAR(16),
    removed BOOLEAN NOT NULL DEFAULT FALSE,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_id, version)
);

CREATE INDEX roster_change_log_owner_contact_version_idx
    ON roster_change_log(owner_id, contact_jid, version DESC);
