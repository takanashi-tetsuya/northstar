-- RFC 6121 offline delivery is drained by a background worker only after the
-- resource's availability/resumption response has reached the transport.
-- Short, expiring claims prevent concurrent resources from replaying the same
-- row without holding a PostgreSQL transaction open across socket backpressure.

ALTER TABLE offline_messages
    ADD COLUMN delivery_claim_id UUID,
    ADD COLUMN delivery_claim_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT offline_message_delivery_claim_pair CHECK (
        (delivery_claim_id IS NULL) = (delivery_claim_expires_at IS NULL)
    );

CREATE INDEX offline_messages_replay_claim_idx
    ON offline_messages (recipient_id, created_at, id, delivery_claim_expires_at);
