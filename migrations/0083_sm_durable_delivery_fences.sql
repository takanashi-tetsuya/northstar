-- Bind durable C2S spool ownership to the exact XEP-0198 sequence entry.
-- A transport write is not a client acknowledgement: the offline row remains
-- recoverable until `<a/>` (or `<resume h=...>`) removes the corresponding SM
-- queue entry and spool row in one transaction.

ALTER TABLE offline_messages
    ADD CONSTRAINT offline_messages_recipient_id_id_key
        UNIQUE (recipient_id, id);

ALTER TABLE sm_resume_stanzas
    ADD COLUMN delivery_recipient_id UUID,
    ADD COLUMN delivery_message_id UUID,
    ADD COLUMN delivery_claim_id UUID,
    ADD CONSTRAINT sm_resume_stanza_delivery_shape CHECK (
        (delivery_recipient_id IS NULL
         AND delivery_message_id IS NULL
         AND delivery_claim_id IS NULL)
        OR
        (delivery_recipient_id IS NOT NULL
         AND delivery_message_id IS NOT NULL)
    ),
    ADD CONSTRAINT sm_resume_stanza_delivery_fk
        FOREIGN KEY (delivery_recipient_id, delivery_message_id)
        REFERENCES offline_messages(recipient_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE UNIQUE INDEX sm_resume_stanza_delivery_owner
    ON sm_resume_stanzas (delivery_message_id)
    WHERE delivery_message_id IS NOT NULL;

CREATE INDEX sm_resume_stanza_delivery_session
    ON sm_resume_stanzas (session_id, delivery_message_id)
    WHERE delivery_message_id IS NOT NULL;

-- BOSH without XEP-0198 has a protocol-level acknowledgement for complete
-- HTTP responses.  Fence the same spool row to the exact response RID; a
-- duplicate request replays cached bytes, while `ack=N` completes all fenced
-- responses through N.  There is intentionally no durable BOSH session row:
-- an actor crash lets this short lease expire and makes the message eligible
-- for the next ordinary offline replay.
CREATE TABLE bosh_delivery_fences (
    message_id UUID PRIMARY KEY,
    recipient_id UUID NOT NULL,
    session_id UUID NOT NULL,
    response_rid BIGINT NOT NULL CHECK (response_rid >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT bosh_delivery_fence_message_fk
        FOREIGN KEY (recipient_id, message_id)
        REFERENCES offline_messages(recipient_id, id)
        -- CASCADE is reserved for explicit parent/account destruction. Every
        -- ordinary retention, TTL and quota cleanup query excludes a fence
        -- while holding the offline row; response ACK deletes through the
        -- exact session/RID owner.
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX bosh_delivery_fence_session_ack
    ON bosh_delivery_fences (session_id, response_rid);
CREATE INDEX bosh_delivery_fence_expiry
    ON bosh_delivery_fences (expires_at, message_id);
