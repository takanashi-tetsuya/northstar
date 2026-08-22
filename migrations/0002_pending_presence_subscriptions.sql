CREATE TABLE pending_presence_subscriptions (
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (requester_id, recipient_id),
    CHECK (requester_id <> recipient_id)
);

CREATE INDEX pending_presence_subscriptions_recipient_idx
    ON pending_presence_subscriptions(recipient_id, created_at);
