-- Normalize MIX delivery authority so one causal stanza is stored once and
-- recipients remain compact, independently leased projections.  This also
-- replaces the scan-and-wait capacity check introduced by migration 0118.

ALTER TABLE mix_channels
    ADD COLUMN revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0);

-- Replay identities are security fences, not permanent history.  Finite
-- retention lets a retired MAC generation leave service after every active
-- replay window has closed instead of being pinned by immutable rows forever.
ALTER TABLE mix_business_intents
    ADD COLUMN expires_at TIMESTAMPTZ NOT NULL
        DEFAULT clock_timestamp() + INTERVAL '14 days',
    ADD CHECK (expires_at > created_at);
CREATE INDEX mix_business_intents_expiry_idx
    ON mix_business_intents(expires_at, semantic_key_id);

DROP TRIGGER trg_mix_business_intents_immutable ON mix_business_intents;
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
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'MIX business replay identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_mix_business_intents_immutable
BEFORE UPDATE ON mix_business_intents
FOR EACH ROW EXECUTE FUNCTION reject_mix_business_intent_identity_update();

CREATE TABLE mix_delivery_events (
    event_id UUID PRIMARY KEY,
    channel_id UUID NOT NULL,
    channel_jid VARCHAR(3071) NOT NULL,
    stanza_template TEXT NOT NULL,
    authoritative_stanza_id UUID,
    archive BOOLEAN NOT NULL,
    encrypted BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + INTERVAL '7 days',
    CHECK (octet_length(stanza_template) BETWEEN 1 AND 2097152),
    CHECK (octet_length(channel_jid) BETWEEN 3 AND 3071),
    CHECK (archive = (authoritative_stanza_id IS NOT NULL)),
    CHECK (expires_at > created_at)
);

CREATE TABLE mix_delivery_recipients (
    delivery_id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES mix_delivery_events(event_id) ON DELETE CASCADE,
    recipient_participant_id UUID NOT NULL,
    recipient_jid VARCHAR(3071) NOT NULL,
    delivery_sequence BIGINT NOT NULL CHECK (delivery_sequence > 0),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 20),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (event_id, recipient_jid),
    UNIQUE (recipient_jid, delivery_sequence),
    CHECK (octet_length(recipient_jid) BETWEEN 3 AND 3071),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);

CREATE INDEX mix_delivery_recipients_due_idx
    ON mix_delivery_recipients(next_attempt_at, created_at, delivery_id)
    WHERE lease_token IS NULL;
CREATE INDEX mix_delivery_recipients_order_idx
    ON mix_delivery_recipients(recipient_jid, delivery_sequence);
CREATE INDEX mix_delivery_recipients_lease_idx
    ON mix_delivery_recipients(lease_until)
    WHERE lease_token IS NOT NULL;

CREATE TABLE mix_delivery_recipient_sequences (
    recipient_jid VARCHAR(3071) PRIMARY KEY,
    next_sequence BIGINT NOT NULL CHECK (next_sequence > 0),
    CHECK (octet_length(recipient_jid) BETWEEN 3 AND 3071)
);

-- Admission serializes producers with one non-blocking fence, while release
-- updates one of 64 independently fenced buckets. This keeps the aggregate
-- limit exact without making concurrent delivery ACKs contend on one row.
CREATE TABLE mix_delivery_capacity (
    bucket SMALLINT PRIMARY KEY CHECK (bucket BETWEEN 0 AND 63),
    queued_rows BIGINT NOT NULL DEFAULT 0 CHECK (queued_rows >= 0),
    queued_bytes BIGINT NOT NULL DEFAULT 0 CHECK (queued_bytes >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO mix_delivery_capacity(bucket)
SELECT generate_series(0,63)::smallint;

CREATE TABLE mix_delivery_dead_letters (
    dead_letter_id UUID PRIMARY KEY,
    delivery_id UUID NOT NULL,
    event_id UUID NOT NULL,
    channel_id UUID NOT NULL,
    channel_jid VARCHAR(3071) NOT NULL,
    recipient_participant_id UUID NOT NULL,
    recipient_jid VARCHAR(3071) NOT NULL,
    delivery_sequence BIGINT NOT NULL,
    stanza_template TEXT NOT NULL,
    authoritative_stanza_id UUID,
    archive BOOLEAN NOT NULL,
    encrypted BOOLEAN NOT NULL,
    attempt_count INTEGER NOT NULL,
    terminal_reason VARCHAR(64) NOT NULL,
    last_error TEXT,
    original_created_at TIMESTAMPTZ NOT NULL,
    original_expires_at TIMESTAMPTZ NOT NULL,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (delivery_id),
    CHECK (octet_length(recipient_jid) BETWEEN 3 AND 3071),
    CHECK (octet_length(channel_jid) BETWEEN 3 AND 3071),
    CHECK (octet_length(stanza_template) BETWEEN 1 AND 2097152),
    CHECK (octet_length(terminal_reason) BETWEEN 1 AND 64),
    CHECK (archive = (authoritative_stanza_id IS NOT NULL))
);
CREATE INDEX mix_delivery_dead_letters_failed_idx
    ON mix_delivery_dead_letters(failed_at, dead_letter_id);
CREATE INDEX mix_delivery_dead_letters_recipient_idx
    ON mix_delivery_dead_letters(recipient_jid, failed_at DESC);

-- Exact terminal responses for authenticated federated mutation IQs.  The
-- request digest prevents an IQ id from being reused with changed semantics;
-- response admission is committed by the same mutation transaction.
CREATE TABLE mix_federated_iq_results (
    authenticated_domain VARCHAR(1023) NOT NULL,
    actor_jid VARCHAR(3071) NOT NULL,
    request_id VARCHAR(1024) NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    response TEXT NOT NULL CHECK (octet_length(response) BETWEEN 1 AND 2097152),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + INTERVAL '7 days',
    PRIMARY KEY (authenticated_domain, actor_jid, request_id),
    CHECK (octet_length(authenticated_domain) BETWEEN 1 AND 1023
       AND authenticated_domain=lower(authenticated_domain)
       AND position('@' IN authenticated_domain)=0
       AND position('/' IN authenticated_domain)=0),
    CHECK (octet_length(actor_jid) BETWEEN 3 AND 3071
       AND position('@' IN actor_jid)>1),
    CHECK (octet_length(request_id) BETWEEN 1 AND 1024),
    CHECK (expires_at > created_at)
);
CREATE INDEX mix_federated_iq_results_expiry_idx
    ON mix_federated_iq_results(expires_at);

-- Preserve any rows admitted while migration 0118 was active.  Re-addressing
-- is performed by the worker with the typed root-attribute rewriter, so the
-- first exact stanza is a safe template for every recipient of the event.
INSERT INTO mix_delivery_events(
    event_id, channel_id, channel_jid, stanza_template, authoritative_stanza_id,
    archive, encrypted, created_at, expires_at
)
SELECT DISTINCT ON (outbox.event_id)
       outbox.event_id, outbox.channel_id,
       channel.localpart || '@' || channel.service_domain,
       outbox.stanza, outbox.authoritative_stanza_id,
       outbox.archive, outbox.encrypted, outbox.created_at, outbox.expires_at
  FROM mix_delivery_outbox outbox
  JOIN mix_channels channel ON channel.id=outbox.channel_id
 ORDER BY outbox.event_id, outbox.created_at, outbox.delivery_id;

INSERT INTO mix_delivery_recipients(
    delivery_id, event_id, recipient_participant_id, recipient_jid,
    delivery_sequence, attempt_count, next_attempt_at, lease_token,
    lease_until, last_error, created_at
)
SELECT delivery_id, event_id, recipient_participant_id, recipient_jid,
       ROW_NUMBER() OVER (
           PARTITION BY recipient_jid ORDER BY created_at, delivery_id
       ),
       attempt_count, next_attempt_at, lease_token, lease_until, last_error,
       created_at
  FROM mix_delivery_outbox;

INSERT INTO mix_delivery_recipient_sequences(recipient_jid, next_sequence)
SELECT recipient_jid, MAX(delivery_sequence) + 1
  FROM mix_delivery_recipients
 GROUP BY recipient_jid;

UPDATE mix_delivery_capacity capacity
   SET queued_rows = COALESCE((
           SELECT COUNT(*) FROM mix_delivery_recipients recipient
            WHERE (get_byte(uuid_send(recipient.delivery_id),0) % 64)=capacity.bucket
       ),0),
       queued_bytes = COALESCE((
           SELECT SUM(octet_length(recipient.recipient_jid) + 128)
             FROM mix_delivery_recipients recipient
            WHERE (get_byte(uuid_send(recipient.delivery_id),0) % 64)=capacity.bucket
       ),0) + COALESCE((
           SELECT SUM(octet_length(event.stanza_template))
             FROM mix_delivery_events event
            WHERE (get_byte(uuid_send(event.event_id),0) % 64)=capacity.bucket
       ),0),
       updated_at = clock_timestamp()
;

-- Capacity release belongs to the database authority, including cascades from
-- channel deletion.  Capturing the migration's current search_path keeps
-- isolated-schema deployments correct without hard-coding `public`.
CREATE FUNCTION northstar_mix_delivery_recipient_capacity_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
    capacity_bucket pg_catalog.int2 :=
        (get_byte(uuid_send(OLD.delivery_id),0) % 64)::pg_catalog.int2;
BEGIN
    IF NOT pg_try_advisory_xact_lock(
        hashtextextended('mix-delivery-capacity-v2:' || capacity_bucket::pg_catalog.text,0)
    ) THEN
        RAISE EXCEPTION 'MIX delivery capacity ledger is busy' USING ERRCODE='55P03';
    END IF;
    UPDATE mix_delivery_capacity
       SET queued_rows=queued_rows-1,
           queued_bytes=queued_bytes-octet_length(OLD.recipient_jid)-128,
           updated_at=clock_timestamp()
     WHERE bucket=capacity_bucket AND queued_rows>=1
       AND queued_bytes>=octet_length(OLD.recipient_jid)+128;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MIX delivery capacity ledger underflow';
    END IF;
    RETURN OLD;
END;
$$;

CREATE FUNCTION northstar_mix_delivery_event_capacity_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path FROM CURRENT
AS $$
DECLARE
    capacity_bucket pg_catalog.int2 :=
        (get_byte(uuid_send(OLD.event_id),0) % 64)::pg_catalog.int2;
BEGIN
    IF NOT pg_try_advisory_xact_lock(
        hashtextextended('mix-delivery-capacity-v2:' || capacity_bucket::pg_catalog.text,0)
    ) THEN
        RAISE EXCEPTION 'MIX delivery capacity ledger is busy' USING ERRCODE='55P03';
    END IF;
    UPDATE mix_delivery_capacity
       SET queued_bytes=queued_bytes-octet_length(OLD.stanza_template),
           updated_at=clock_timestamp()
     WHERE bucket=capacity_bucket
       AND queued_bytes>=octet_length(OLD.stanza_template);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MIX delivery capacity ledger underflow';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_mix_delivery_recipient_capacity_delete
AFTER DELETE ON mix_delivery_recipients
FOR EACH ROW EXECUTE FUNCTION northstar_mix_delivery_recipient_capacity_delete();

CREATE TRIGGER trg_mix_delivery_event_capacity_delete
AFTER DELETE ON mix_delivery_events
FOR EACH ROW EXECUTE FUNCTION northstar_mix_delivery_event_capacity_delete();

DROP TABLE mix_delivery_outbox;
DROP FUNCTION IF EXISTS reject_mix_delivery_outbox_identity_update();

COMMENT ON TABLE mix_delivery_events IS
    'One immutable causal MIX stanza template per event; recipient addressing is applied by a validated XML root rewrite';
COMMENT ON TABLE mix_delivery_recipients IS
    'Compact, ordered and independently fenced MIX recipient delivery projections';
COMMENT ON TABLE mix_delivery_dead_letters IS
    'Bounded terminal MIX delivery evidence and explicit operator recovery source';
