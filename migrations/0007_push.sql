CREATE TABLE push_subscriptions (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_jid VARCHAR(3071) NOT NULL,
    node VARCHAR(1024) NOT NULL,
    options TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, service_jid, node)
);
