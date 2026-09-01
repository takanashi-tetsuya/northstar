-- Bind every durable PEP delivery to database identities and an explicit
-- authorization policy.  Historical rows cannot be reconstructed from XML,
-- `from`, or an ordering-key convention without creating a confused-deputy
-- boundary, so they are marked unverifiable and the dispatcher drops them
-- fail-closed.  Every post-migration producer must populate the full subject.

ALTER TABLE pubsub_event_outbox
    ADD COLUMN pep_sender_account_id UUID,
    ADD COLUMN pep_sender_bare_jid TEXT,
    ADD COLUMN pep_sender_connection_id UUID,
    ADD COLUMN pep_recipient_account_id UUID,
    ADD COLUMN pep_recipient_is_local BOOLEAN,
    ADD COLUMN pep_event_kind TEXT,
    ADD COLUMN pep_authorization_mode TEXT,
    ADD COLUMN pep_legacy_unverifiable BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE pubsub_event_outbox
   SET pep_legacy_unverifiable=TRUE
 WHERE delivery_kind='pep-stanza';

ALTER TABLE pubsub_event_outbox
    ADD CONSTRAINT pubsub_event_outbox_pep_sender_fk
        FOREIGN KEY (pep_sender_account_id) REFERENCES users(id) ON DELETE CASCADE,
    ADD CONSTRAINT pubsub_event_outbox_pep_recipient_fk
        FOREIGN KEY (pep_recipient_account_id) REFERENCES users(id) ON DELETE CASCADE,
    ADD CONSTRAINT pubsub_event_outbox_pep_subject_check CHECK (
        (
            delivery_kind='pep-stanza'
            AND source_kind='pep'
            AND (
                (
                    pep_legacy_unverifiable
                    AND pep_sender_account_id IS NULL
                    AND pep_sender_bare_jid IS NULL
                    AND pep_sender_connection_id IS NULL
                    AND pep_recipient_account_id IS NULL
                    AND pep_recipient_is_local IS NULL
                    AND pep_event_kind IS NULL
                    AND pep_authorization_mode IS NULL
                )
                OR
                (
                    NOT pep_legacy_unverifiable
                    AND pep_sender_account_id IS NOT NULL
                    AND pep_sender_bare_jid IS NOT NULL
                    AND pep_recipient_is_local IS NOT NULL
                    AND (
                        (pep_recipient_is_local AND pep_recipient_account_id IS NOT NULL)
                        OR
                        (NOT pep_recipient_is_local AND pep_recipient_account_id IS NULL)
                    )
                    AND pep_event_kind IN (
                        'publish','last-item','retract','purge','delete','configuration',
                        'subscription-state','affiliation-state'
                    )
                    AND pep_authorization_mode IN ('causal-audience','live-node-access')
                    AND octet_length(pep_sender_bare_jid) BETWEEN 3 AND 3071
                    AND (
                        pep_event_kind NOT IN (
                            'retract','purge','delete','configuration',
                            'subscription-state','affiliation-state'
                        )
                        OR pep_authorization_mode='causal-audience'
                    )
                    AND (
                        NOT security_sensitive
                        OR pep_event_kind NOT IN ('publish','last-item')
                        OR pep_authorization_mode='live-node-access'
                    )
                )
            )
        )
        OR
        (
            delivery_kind<>'pep-stanza'
            AND source_kind<>'pep'
            AND NOT pep_legacy_unverifiable
            AND pep_sender_account_id IS NULL
            AND pep_sender_bare_jid IS NULL
            AND pep_sender_connection_id IS NULL
            AND pep_recipient_account_id IS NULL
            AND pep_recipient_is_local IS NULL
            AND pep_event_kind IS NULL
            AND pep_authorization_mode IS NULL
        )
    );

CREATE INDEX idx_pubsub_event_outbox_pep_sender
    ON pubsub_event_outbox(pep_sender_account_id)
    WHERE pep_sender_account_id IS NOT NULL;
CREATE INDEX idx_pubsub_event_outbox_pep_recipient
    ON pubsub_event_outbox(pep_recipient_account_id)
    WHERE pep_recipient_account_id IS NOT NULL;

ALTER TABLE pubsub_event_dead_letters
    ADD COLUMN pep_sender_account_id UUID,
    ADD COLUMN pep_sender_bare_jid TEXT,
    ADD COLUMN pep_sender_connection_id UUID,
    ADD COLUMN pep_recipient_account_id UUID,
    ADD COLUMN pep_recipient_is_local BOOLEAN,
    ADD COLUMN pep_event_kind TEXT,
    ADD COLUMN pep_authorization_mode TEXT,
    ADD COLUMN pep_legacy_unverifiable BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE pubsub_event_dead_letters
   SET pep_legacy_unverifiable=TRUE
 WHERE delivery_kind='pep-stanza';

-- Lease, retry and error bookkeeping may change.  The authorization subject is
-- an immutable part of the delivery snapshot and must never be rewritten by a
-- worker after the originating mutation commits.
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
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.pep_sender_account_id IS DISTINCT FROM OLD.pep_sender_account_id
       OR NEW.pep_sender_bare_jid IS DISTINCT FROM OLD.pep_sender_bare_jid
       OR NEW.pep_sender_connection_id IS DISTINCT FROM OLD.pep_sender_connection_id
       OR NEW.pep_recipient_account_id IS DISTINCT FROM OLD.pep_recipient_account_id
       OR NEW.pep_recipient_is_local IS DISTINCT FROM OLD.pep_recipient_is_local
       OR NEW.pep_event_kind IS DISTINCT FROM OLD.pep_event_kind
       OR NEW.pep_authorization_mode IS DISTINCT FROM OLD.pep_authorization_mode
       OR NEW.pep_legacy_unverifiable IS DISTINCT FROM OLD.pep_legacy_unverifiable THEN
        RAISE EXCEPTION 'pubsub event outbox delivery snapshot is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp;
