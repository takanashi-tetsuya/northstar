CREATE TABLE federated_presence_pending (
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    from_jid VARCHAR(3071) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (recipient_id, from_jid)
);
