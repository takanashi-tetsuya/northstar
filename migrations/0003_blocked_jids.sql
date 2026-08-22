CREATE TABLE blocked_jids (
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_jid VARCHAR(3071) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_id, blocked_jid)
);

CREATE INDEX blocked_jids_owner_idx ON blocked_jids(owner_id);
