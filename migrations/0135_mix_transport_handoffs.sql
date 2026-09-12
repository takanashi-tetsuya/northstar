-- Give durable MIX recipient rows an explicit, typed recoverability owner.
--
-- A MIX delivery has a different authority shape from an offline C2S message:
-- its source is a leased `mix_delivery_recipients` row, not an
-- `(recipient_id, message_id)` pair.  Reusing `bosh_delivery_fences` would
-- collapse those two authorities and let a BOSH acknowledgement operate on a
-- row it cannot identify.  Keep MIX ownership in its own table and let the
-- runtime validate the exact lease token at every hand-off boundary.

ALTER TABLE sm_resume_stanzas
    ADD COLUMN mix_delivery_id UUID,
    ADD COLUMN mix_delivery_lease_token UUID,
    ADD CONSTRAINT sm_resume_stanza_mix_delivery_fk
        FOREIGN KEY (mix_delivery_id)
        REFERENCES mix_delivery_recipients(delivery_id)
        -- The owning XEP-0198 entry must be removed or acknowledged before a
        -- MIX row can be deleted.  This turns accidental source deletion into
        -- a transaction failure instead of an invisible lost acknowledgement.
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE sm_resume_stanzas
    DROP CONSTRAINT sm_resume_stanza_delivery_shape,
    ADD CONSTRAINT sm_resume_stanza_delivery_shape CHECK (
        -- Volatile/control stanza: no durable source.
        (
            delivery_recipient_id IS NULL
            AND delivery_message_id IS NULL
            AND delivery_claim_id IS NULL
            AND mix_delivery_id IS NULL
            AND mix_delivery_lease_token IS NULL
        )
        OR
        -- Traditional C2S source.  A replay claim is optional by design but
        -- cannot be mixed with a MIX recipient lease.
        (
            delivery_recipient_id IS NOT NULL
            AND delivery_message_id IS NOT NULL
            AND mix_delivery_id IS NULL
            AND mix_delivery_lease_token IS NULL
        )
        OR
        -- Durable MIX source.  The database code verifies this lease token
        -- against the exact claimed recipient before persisting the queue.
        (
            delivery_recipient_id IS NULL
            AND delivery_message_id IS NULL
            AND delivery_claim_id IS NULL
            AND mix_delivery_id IS NOT NULL
            AND mix_delivery_lease_token IS NOT NULL
        )
    );

CREATE UNIQUE INDEX sm_resume_stanza_mix_delivery_owner
    ON sm_resume_stanzas (mix_delivery_id)
    WHERE mix_delivery_id IS NOT NULL;

CREATE INDEX sm_resume_stanza_mix_delivery_session
    ON sm_resume_stanzas (session_id, mix_delivery_id)
    WHERE mix_delivery_id IS NOT NULL;

-- A BOSH actor needs a durable hand-off before it can expose a response, but
-- it may receive the MIX item before a request RID is available.  A NULL RID
-- is that short pending state.  It cannot be acknowledged, renewed as a
-- response, or live beyond the same immutable five-minute ownership window.
CREATE TABLE mix_bosh_delivery_fences (
    delivery_id UUID PRIMARY KEY
        REFERENCES mix_delivery_recipients(delivery_id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    lease_token UUID NOT NULL,
    session_id UUID NOT NULL,
    response_rid BIGINT,
    first_owned_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    bound_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (response_rid IS NULL OR response_rid >= 0),
    CHECK ((response_rid IS NULL) = (bound_at IS NULL)),
    CHECK (expires_at <= first_owned_at + INTERVAL '5 minutes')
);

CREATE INDEX mix_bosh_delivery_fence_session_ack
    ON mix_bosh_delivery_fences (session_id, response_rid)
    WHERE response_rid IS NOT NULL;
CREATE INDEX mix_bosh_delivery_fence_expiry
    ON mix_bosh_delivery_fences (expires_at, delivery_id);
CREATE INDEX mix_bosh_delivery_fence_session_age
    ON mix_bosh_delivery_fences (session_id, first_owned_at, response_rid);

COMMENT ON TABLE mix_bosh_delivery_fences IS
    'Typed BOSH ownership for leased MIX recipient rows; BOSH ACK consumes only a bound exact source lease';
COMMENT ON COLUMN sm_resume_stanzas.mix_delivery_id IS
    'Exact durable MIX recipient source owned by this XEP-0198 queue entry';
COMMENT ON COLUMN sm_resume_stanzas.mix_delivery_lease_token IS
    'Lease token verified before the queue takes ownership of a durable MIX recipient source';
