-- Durable XEP-0060/XEP-0163 notification projection.
--
-- Every row is an immutable recipient snapshot written by the same database
-- transaction as the mutation which caused it.  Redis and process memory may
-- wake a dispatcher, but neither is an authority for whether delivery is due.

CREATE TABLE pubsub_event_streams (
    ordering_key TEXT PRIMARY KEY,
    next_sequence BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (octet_length(ordering_key) BETWEEN 1 AND 2048),
    CHECK (next_sequence > 0)
);

CREATE TABLE pubsub_event_outbox_capacity (
    shard SMALLINT PRIMARY KEY CHECK (shard BETWEEN 0 AND 63),
    queued_rows BIGINT NOT NULL DEFAULT 0 CHECK (queued_rows >= 0),
    queued_bytes BIGINT NOT NULL DEFAULT 0 CHECK (queued_bytes >= 0),
    CHECK (queued_rows <= 10000),
    CHECK (queued_bytes <= 67108864)
);

INSERT INTO pubsub_event_outbox_capacity(shard)
SELECT generate_series(0, 63)
ON CONFLICT DO NOTHING;

CREATE TABLE pubsub_event_outbox_domain_capacity (
    target_domain TEXT NOT NULL,
    capacity_shard SMALLINT NOT NULL CHECK (capacity_shard BETWEEN 0 AND 63),
    queued_rows BIGINT NOT NULL DEFAULT 0 CHECK (queued_rows >= 0),
    -- 781 * 64 = 49,984: a hard per-domain bound without making every
    -- publisher contend on one shared target-domain row.
    CHECK (queued_rows <= 781),
    CHECK (octet_length(target_domain) BETWEEN 1 AND 255),
    PRIMARY KEY (target_domain, capacity_shard)
);

CREATE TABLE pubsub_event_outbox (
    delivery_id UUID PRIMARY KEY,
    event_id UUID NOT NULL,
    ordering_key TEXT NOT NULL,
    event_sequence BIGINT NOT NULL CHECK (event_sequence > 0),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('pubsub', 'pep')),
    source_node TEXT NOT NULL,
    delivery_kind TEXT NOT NULL CHECK (
        delivery_kind IN ('pubsub-children', 'pubsub-digest', 'pubsub-direct', 'pep-stanza')
    ),
    recipient_jid TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    payload_xml TEXT NOT NULL,
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    show_values TEXT[],
    subscription_node_id UUID,
    digest_frequency_ms INTEGER,
    security_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    coalesce_key TEXT,
    capacity_shard SMALLINT NOT NULL CHECK (capacity_shard BETWEEN 0 AND 63),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (octet_length(ordering_key) BETWEEN 1 AND 2048),
    CHECK (octet_length(source_node) BETWEEN 1 AND 1024),
    CHECK (octet_length(recipient_jid) BETWEEN 1 AND 3071),
    CHECK (octet_length(target_domain) BETWEEN 1 AND 255),
    CHECK (octet_length(payload_xml) BETWEEN 1 AND 4194304),
    CHECK (show_values IS NULL OR cardinality(show_values) BETWEEN 1 AND 8),
    CHECK ((delivery_kind = 'pubsub-digest') =
           (subscription_node_id IS NOT NULL AND digest_frequency_ms IS NOT NULL)),
    CHECK (digest_frequency_ms IS NULL OR digest_frequency_ms BETWEEN 1000 AND 86400000),
    CHECK (coalesce_key IS NULL OR (
        NOT security_sensitive
        AND lower(source_node) NOT LIKE '%omemo%'
        AND lower(source_node) NOT LIKE '%axolotl%'
        AND lower(source_node) NOT LIKE '%device-list%'
        AND lower(source_node) NOT LIKE '%devices%'
        AND lower(source_node) NOT LIKE '%bundle%'
        AND lower(source_node) NOT LIKE '%prekeys%'
        AND lower(source_node) NOT LIKE '%signed-pre-key%'
        AND octet_length(coalesce_key) BETWEEN 1 AND 2048
    )),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
    CHECK (expires_at > created_at),
    UNIQUE (ordering_key, event_sequence, delivery_id),
    UNIQUE (event_id, delivery_id)
);

CREATE INDEX idx_pubsub_event_outbox_due
    ON pubsub_event_outbox(next_attempt_at, created_at, delivery_id)
    WHERE lease_token IS NULL;
CREATE INDEX idx_pubsub_event_outbox_lease
    ON pubsub_event_outbox(lease_until)
    WHERE lease_token IS NOT NULL;
CREATE INDEX idx_pubsub_event_outbox_order
    ON pubsub_event_outbox(ordering_key, event_sequence, delivery_id);
CREATE INDEX idx_pubsub_event_outbox_domain
    ON pubsub_event_outbox(target_domain, next_attempt_at, created_at);
CREATE INDEX idx_pubsub_event_outbox_expiry
    ON pubsub_event_outbox(expires_at);

CREATE TABLE pubsub_event_dead_letters (
    delivery_id UUID PRIMARY KEY,
    event_id UUID NOT NULL,
    ordering_key TEXT NOT NULL,
    event_sequence BIGINT NOT NULL,
    source_kind TEXT NOT NULL,
    source_node TEXT NOT NULL,
    delivery_kind TEXT NOT NULL,
    recipient_jid TEXT NOT NULL,
    target_domain TEXT NOT NULL,
    payload_digest BYTEA NOT NULL CHECK (octet_length(payload_digest) = 32),
    attempt_count INTEGER NOT NULL,
    terminal_reason TEXT NOT NULL,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    dead_lettered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    purge_after TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() + INTERVAL '30 days'
);

CREATE INDEX idx_pubsub_event_dead_letters_purge
    ON pubsub_event_dead_letters(purge_after);
CREATE INDEX idx_pubsub_event_streams_cleanup
    ON pubsub_event_streams(updated_at);

CREATE OR REPLACE FUNCTION account_pubsub_event_outbox_capacity()
RETURNS TRIGGER AS $$
DECLARE
    payload_bytes BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        payload_bytes := octet_length(NEW.payload_xml);
        UPDATE pubsub_event_outbox_capacity
           SET queued_rows = queued_rows + 1,
               queued_bytes = queued_bytes + payload_bytes
         WHERE shard = NEW.capacity_shard;
        INSERT INTO pubsub_event_outbox_domain_capacity(target_domain, capacity_shard, queued_rows)
        VALUES (NEW.target_domain, NEW.capacity_shard, 1)
        ON CONFLICT (target_domain, capacity_shard) DO UPDATE
            SET queued_rows = pubsub_event_outbox_domain_capacity.queued_rows + 1;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        payload_bytes := octet_length(OLD.payload_xml);
        UPDATE pubsub_event_outbox_capacity
           SET queued_rows = queued_rows - 1,
               queued_bytes = queued_bytes - payload_bytes
         WHERE shard = OLD.capacity_shard;
        UPDATE pubsub_event_outbox_domain_capacity
         SET queued_rows = queued_rows - 1
         WHERE target_domain = OLD.target_domain
           AND capacity_shard = OLD.capacity_shard;
        DELETE FROM pubsub_event_outbox_domain_capacity
         WHERE target_domain = OLD.target_domain
           AND capacity_shard = OLD.capacity_shard
           AND queued_rows = 0;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'pubsub event outbox identity is immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_pubsub_event_outbox_capacity_insert
BEFORE INSERT ON pubsub_event_outbox
FOR EACH ROW EXECUTE FUNCTION account_pubsub_event_outbox_capacity();

CREATE TRIGGER trg_pubsub_event_outbox_capacity_delete
AFTER DELETE ON pubsub_event_outbox
FOR EACH ROW EXECUTE FUNCTION account_pubsub_event_outbox_capacity();

CREATE OR REPLACE FUNCTION reject_pubsub_event_outbox_identity_update()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
       OR NEW.event_id IS DISTINCT FROM OLD.event_id
       OR NEW.ordering_key IS DISTINCT FROM OLD.ordering_key
       OR NEW.event_sequence IS DISTINCT FROM OLD.event_sequence
       OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
       OR NEW.source_node IS DISTINCT FROM OLD.source_node
       OR NEW.delivery_kind IS DISTINCT FROM OLD.delivery_kind
       OR NEW.recipient_jid IS DISTINCT FROM OLD.recipient_jid
       OR NEW.target_domain IS DISTINCT FROM OLD.target_domain
       OR NEW.payload_xml IS DISTINCT FROM OLD.payload_xml
       OR NEW.payload_digest IS DISTINCT FROM OLD.payload_digest
       OR NEW.show_values IS DISTINCT FROM OLD.show_values
       OR NEW.subscription_node_id IS DISTINCT FROM OLD.subscription_node_id
       OR NEW.digest_frequency_ms IS DISTINCT FROM OLD.digest_frequency_ms
       OR NEW.security_sensitive IS DISTINCT FROM OLD.security_sensitive
       OR NEW.coalesce_key IS DISTINCT FROM OLD.coalesce_key
       OR NEW.capacity_shard IS DISTINCT FROM OLD.capacity_shard
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'pubsub event outbox delivery snapshot is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_pubsub_event_outbox_immutable
BEFORE UPDATE ON pubsub_event_outbox
FOR EACH ROW EXECUTE FUNCTION reject_pubsub_event_outbox_identity_update();

-- New digest fragments originate from the durable event outbox.  Their
-- recipient/options snapshot remains valid even if a later unsubscribe or
-- node deletion commits; that later mutation does not retroactively revoke an
-- earlier accepted event.  Legacy rows retain a NULL source_delivery_id.
ALTER TABLE pubsub_digest_queue
    DROP CONSTRAINT IF EXISTS pubsub_digest_queue_subscription_node_id_fkey;
ALTER TABLE pubsub_digest_queue
    ADD COLUMN source_delivery_id UUID,
    ADD COLUMN show_values TEXT[],
    ADD CONSTRAINT pubsub_digest_queue_snapshot_binding CHECK (
        (source_delivery_id IS NULL AND show_values IS NULL)
        OR (source_delivery_id IS NOT NULL AND cardinality(show_values) BETWEEN 1 AND 8)
    );
CREATE UNIQUE INDEX idx_pubsub_digest_queue_source_delivery
    ON pubsub_digest_queue(source_delivery_id)
    WHERE source_delivery_id IS NOT NULL;
