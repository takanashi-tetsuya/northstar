CREATE TABLE pubsub_nodes (
    id UUID PRIMARY KEY,
    node TEXT NOT NULL UNIQUE CHECK (length(node) BETWEEN 1 AND 1024),
    creator_jid TEXT NOT NULL,
    access_model VARCHAR(16) NOT NULL DEFAULT 'open'
        CHECK (access_model IN ('open', 'authorize', 'whitelist')),
    publish_model VARCHAR(16) NOT NULL DEFAULT 'publishers'
        CHECK (publish_model IN ('open', 'publishers', 'subscribers')),
    max_items INTEGER NOT NULL DEFAULT 100 CHECK (max_items BETWEEN 1 AND 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE pubsub_items (
    id UUID PRIMARY KEY,
    node_id UUID NOT NULL REFERENCES pubsub_nodes(id) ON DELETE CASCADE,
    item_id TEXT NOT NULL CHECK (length(item_id) BETWEEN 1 AND 1024),
    publisher_jid TEXT NOT NULL,
    xml_payload TEXT NOT NULL CHECK (octet_length(xml_payload) <= 1048576),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (node_id, item_id)
);

CREATE TABLE pubsub_affiliations (
    node_id UUID NOT NULL REFERENCES pubsub_nodes(id) ON DELETE CASCADE,
    jid TEXT NOT NULL,
    affiliation VARCHAR(16) NOT NULL
        CHECK (affiliation IN ('owner', 'publisher', 'member', 'outcast', 'none')),
    PRIMARY KEY (node_id, jid)
);

CREATE TABLE pubsub_subscriptions (
    node_id UUID NOT NULL REFERENCES pubsub_nodes(id) ON DELETE CASCADE,
    jid TEXT NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'subscribed'
        CHECK (state IN ('subscribed', 'pending', 'unconfigured')),
    PRIMARY KEY (node_id, jid)
);

CREATE INDEX idx_pubsub_items_node_created ON pubsub_items(node_id, created_at DESC);
CREATE INDEX idx_pubsub_subscriptions_jid ON pubsub_subscriptions(jid);
