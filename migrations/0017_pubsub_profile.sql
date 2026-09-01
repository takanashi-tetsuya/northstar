ALTER TABLE pubsub_nodes
    ADD COLUMN title TEXT,
    ADD COLUMN description TEXT,
    ADD COLUMN deliver_payloads BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN notify_delete BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN notify_retract BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN persist_items BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN send_last_published_item VARCHAR(32) NOT NULL DEFAULT 'on_sub'
        CHECK (send_last_published_item IN ('never', 'on_sub', 'on_sub_and_presence')),
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE pubsub_affiliations
    DROP CONSTRAINT IF EXISTS pubsub_affiliations_affiliation_check;

ALTER TABLE pubsub_affiliations
    ADD CONSTRAINT pubsub_affiliations_affiliation_check
    CHECK (affiliation IN ('owner', 'publisher', 'publish-only', 'member', 'outcast', 'none'));

ALTER TABLE pubsub_subscriptions
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX idx_pubsub_affiliations_jid ON pubsub_affiliations(jid);
CREATE INDEX idx_pubsub_subscriptions_node_state ON pubsub_subscriptions(node_id, state);
