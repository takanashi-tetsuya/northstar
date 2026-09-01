-- XEP-0357 is intentionally a small PubSub profile, but a production server
-- still needs bounded subscriptions, cross-node notification coalescing and
-- durable IQ correlation.  These columns never contain message content.
-- Older builds accepted full service JIDs and an empty node even though a
-- XEP-0060 publish cannot target either shape safely.  Disable those legacy
-- entries rather than silently broadening a full-resource authorization.
DELETE FROM push_subscriptions
WHERE POSITION('/' IN service_jid) > 0 OR node = '';

ALTER TABLE push_subscriptions
    ADD COLUMN next_notification_at TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
    ADD COLUMN consecutive_failures SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN last_success_at TIMESTAMPTZ,
    ADD CONSTRAINT push_subscriptions_failure_bound
        CHECK (consecutive_failures BETWEEN 0 AND 16),
    ADD CONSTRAINT push_subscriptions_bare_service
        CHECK (POSITION('/' IN service_jid) = 0),
    ADD CONSTRAINT push_subscriptions_nonempty_node
        CHECK (node <> '');

CREATE TABLE push_enable_rate_limits (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000000)
);

CREATE TABLE push_delivery_attempts (
    request_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    service_jid VARCHAR(3071) NOT NULL,
    node VARCHAR(1024) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id, service_jid, node)
        REFERENCES push_subscriptions(user_id, service_jid, node)
        ON DELETE CASCADE
);

CREATE INDEX idx_push_delivery_attempts_expiry
    ON push_delivery_attempts(expires_at);
