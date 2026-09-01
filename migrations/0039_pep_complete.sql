-- Complete the durable parts of XEP-0163 PEP.  Automatic subscriptions are
-- derived from roster + available verified capabilities and intentionally are
-- not persisted; explicit XEP-0060 subscriptions are durable here.

ALTER TABLE pep_nodes
    DROP CONSTRAINT IF EXISTS pep_nodes_access_model_check;

ALTER TABLE pep_nodes
    ADD CONSTRAINT pep_nodes_access_model_check
        CHECK (access_model IN ('open', 'presence', 'roster', 'whitelist')),
    ADD COLUMN deliver_notifications BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN roster_groups_allowed TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN access_whitelist TEXT[] NOT NULL DEFAULT '{}';

CREATE TABLE pep_subscriptions (
    owner_id UUID NOT NULL,
    node TEXT NOT NULL,
    subscriber_jid TEXT NOT NULL,
    subid TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'subscribed'
        CHECK (state IN ('subscribed', 'pending')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_id, node, subscriber_jid),
    FOREIGN KEY (owner_id, node)
        REFERENCES pep_nodes(owner_id, node) ON DELETE CASCADE,
    CHECK (octet_length(subscriber_jid) BETWEEN 1 AND 3071),
    CHECK (octet_length(subid) BETWEEN 1 AND 128)
);

CREATE INDEX pep_subscriptions_subscriber_idx
    ON pep_subscriptions(subscriber_jid, owner_id, node);
