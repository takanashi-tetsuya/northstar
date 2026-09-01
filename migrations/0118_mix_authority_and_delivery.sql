-- MIX business replay identity.
--
-- Client origin/action IDs are scoped by the authenticated canonical actor
-- and channel.  Only a purpose-separated keyed semantic commitment is kept;
-- the table is not a second plaintext archive.  The authoritative server ID
-- is immutable and is reused by an exact retry.

CREATE TABLE mix_business_intents (
    channel_id UUID NOT NULL REFERENCES mix_channels(id) ON DELETE CASCADE,
    actor_jid VARCHAR(3071) NOT NULL,
    client_id VARCHAR(1024) NOT NULL,
    operation VARCHAR(16) NOT NULL CHECK (operation IN ('message', 'retraction')),
    semantic_key_id VARCHAR(16) NOT NULL,
    semantic_mac BYTEA NOT NULL CHECK (octet_length(semantic_mac) = 32),
    authoritative_id UUID NOT NULL,
    target_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (channel_id, actor_jid, client_id, operation),
    UNIQUE (channel_id, authoritative_id),
    CHECK (octet_length(actor_jid) BETWEEN 3 AND 3071
       AND actor_jid = lower(actor_jid)
       AND position('@' IN actor_jid) > 1
       AND position('/' IN actor_jid) = 0),
    CHECK (octet_length(client_id) BETWEEN 1 AND 1024),
    CHECK (semantic_key_id ~ '^[A-Za-z0-9_-]{16}$'),
    CHECK ((operation = 'message' AND target_id IS NULL)
        OR (operation = 'retraction' AND target_id IS NOT NULL))
);

CREATE INDEX mix_business_intents_created_idx
    ON mix_business_intents(created_at, channel_id);

CREATE OR REPLACE FUNCTION reject_mix_business_intent_identity_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.channel_id IS DISTINCT FROM OLD.channel_id
       OR NEW.actor_jid IS DISTINCT FROM OLD.actor_jid
       OR NEW.client_id IS DISTINCT FROM OLD.client_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.semantic_key_id IS DISTINCT FROM OLD.semantic_key_id
       OR NEW.semantic_mac IS DISTINCT FROM OLD.semantic_mac
       OR NEW.authoritative_id IS DISTINCT FROM OLD.authoritative_id
       OR NEW.target_id IS DISTINCT FROM OLD.target_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'MIX business replay identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_mix_business_intents_immutable
BEFORE UPDATE ON mix_business_intents
FOR EACH ROW EXECUTE FUNCTION reject_mix_business_intent_identity_update();

COMMENT ON TABLE mix_business_intents IS
    'Keyed, immutable MIX message/retraction replay identities; no stanza plaintext';

-- Immutable causal recipient snapshots.  Network I/O never occurs while a
-- channel mutation transaction is open; a supervised worker leases these
-- rows and retries the exact committed stanza.  Personal MAM projection is
-- performed by that worker before live routing when archive=true.
CREATE TABLE mix_delivery_outbox (
    delivery_id UUID PRIMARY KEY,
    event_id UUID NOT NULL,
    channel_id UUID NOT NULL REFERENCES mix_channels(id) ON DELETE CASCADE,
    recipient_participant_id UUID NOT NULL,
    recipient_jid VARCHAR(3071) NOT NULL,
    stanza TEXT NOT NULL,
    authoritative_stanza_id UUID,
    archive BOOLEAN NOT NULL,
    encrypted BOOLEAN NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 20),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + INTERVAL '7 days',
    UNIQUE (event_id, recipient_jid),
    CHECK (octet_length(recipient_jid) BETWEEN 3 AND 3071),
    CHECK (octet_length(stanza) BETWEEN 1 AND 2097152),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
    CHECK (archive = (authoritative_stanza_id IS NOT NULL)),
    CHECK (expires_at > created_at)
);

CREATE INDEX mix_delivery_outbox_due_idx
    ON mix_delivery_outbox(next_attempt_at, created_at, delivery_id)
    WHERE lease_token IS NULL;
CREATE INDEX mix_delivery_outbox_order_idx
    ON mix_delivery_outbox(recipient_jid, created_at, delivery_id);
CREATE INDEX mix_delivery_outbox_lease_idx
    ON mix_delivery_outbox(lease_until)
    WHERE lease_token IS NOT NULL;

CREATE OR REPLACE FUNCTION reject_mix_delivery_outbox_identity_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
       OR NEW.event_id IS DISTINCT FROM OLD.event_id
       OR NEW.channel_id IS DISTINCT FROM OLD.channel_id
       OR NEW.recipient_participant_id IS DISTINCT FROM OLD.recipient_participant_id
       OR NEW.recipient_jid IS DISTINCT FROM OLD.recipient_jid
       OR NEW.stanza IS DISTINCT FROM OLD.stanza
       OR NEW.authoritative_stanza_id IS DISTINCT FROM OLD.authoritative_stanza_id
       OR NEW.archive IS DISTINCT FROM OLD.archive
       OR NEW.encrypted IS DISTINCT FROM OLD.encrypted
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'MIX delivery outbox causal snapshot is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_mix_delivery_outbox_immutable
BEFORE UPDATE ON mix_delivery_outbox
FOR EACH ROW EXECUTE FUNCTION reject_mix_delivery_outbox_identity_update();
