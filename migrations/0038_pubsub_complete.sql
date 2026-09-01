-- XEP-0060 subscription configuration and the collection graph defined by
-- XEP-0248.  Collection edges are deliberately separate from the node row so
-- the graph can be checked and updated transactionally.

ALTER TABLE pubsub_nodes
    ADD COLUMN node_type TEXT NOT NULL DEFAULT 'leaf'
        CHECK (node_type IN ('leaf', 'collection')),
    ADD COLUMN deliver_notifications BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN notify_config BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN notify_sub BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN language TEXT,
    ADD COLUMN payload_type TEXT,
    ADD COLUMN max_payload_size INTEGER NOT NULL DEFAULT 1048576
        CHECK (max_payload_size BETWEEN 0 AND 1048576),
    ADD COLUMN children_max INTEGER NOT NULL DEFAULT 1000
        CHECK (children_max BETWEEN 0 AND 1000),
    ADD COLUMN children_association_policy TEXT NOT NULL DEFAULT 'owner'
        CHECK (children_association_policy IN ('owner', 'whitelist', 'all')),
    ADD COLUMN children_association_whitelist TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE pubsub_subscriptions
    ADD COLUMN subid TEXT,
    ADD COLUMN deliver BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN digest BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN digest_frequency INTEGER NOT NULL DEFAULT 86400000
        CHECK (digest_frequency BETWEEN 1000 AND 86400000),
    ADD COLUMN expire TIMESTAMPTZ,
    ADD COLUMN include_body BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN show_values TEXT[] NOT NULL
        DEFAULT ARRAY['away', 'chat', 'dnd', 'online', 'xa']::TEXT[],
    ADD COLUMN subscription_type TEXT NOT NULL DEFAULT 'items'
        CHECK (subscription_type IN ('items', 'nodes', 'all')),
    -- NULL means the XEP-0248 value "all".
    ADD COLUMN subscription_depth INTEGER
        CHECK (subscription_depth IS NULL OR subscription_depth >= 0),
    ADD COLUMN last_notification_at TIMESTAMPTZ;

ALTER TABLE pubsub_subscriptions
    ADD CONSTRAINT pubsub_subscription_show_values_valid CHECK (
        cardinality(show_values) BETWEEN 1 AND 5
        AND show_values <@ ARRAY['away', 'chat', 'dnd', 'online', 'xa']::TEXT[]
    );

UPDATE pubsub_subscriptions
SET subid = md5(node_id::TEXT || ':' || jid)
WHERE subid IS NULL;

ALTER TABLE pubsub_subscriptions
    ALTER COLUMN subid SET NOT NULL;

CREATE UNIQUE INDEX idx_pubsub_subscriptions_subid
    ON pubsub_subscriptions(subid);
CREATE INDEX idx_pubsub_subscriptions_expire
    ON pubsub_subscriptions(expire)
    WHERE expire IS NOT NULL;

CREATE TABLE pubsub_collection_members (
    collection_node_id UUID NOT NULL REFERENCES pubsub_nodes(id) ON DELETE CASCADE,
    child_node_id UUID NOT NULL REFERENCES pubsub_nodes(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (collection_node_id, child_node_id),
    CHECK (collection_node_id <> child_node_id)
);

CREATE INDEX idx_pubsub_collection_members_child
    ON pubsub_collection_members(child_node_id);

CREATE TABLE pubsub_node_redirects (
    node TEXT PRIMARY KEY,
    uri TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
    CHECK (octet_length(node) BETWEEN 1 AND 1024),
    CHECK (octet_length(uri) BETWEEN 1 AND 2048)
);

CREATE INDEX idx_pubsub_node_redirects_expire
    ON pubsub_node_redirects(expires_at);

-- Digest entries are durable.  The delivery worker combines all due event
-- fragments for one subscription into a single headline stanza and deletes
-- them only after routing has accepted the message.
CREATE TABLE pubsub_digest_queue (
    id UUID PRIMARY KEY,
    subscription_node_id UUID NOT NULL REFERENCES pubsub_nodes(id) ON DELETE CASCADE,
    subscriber_jid TEXT NOT NULL,
    event_xml TEXT NOT NULL,
    deliver_after TIMESTAMPTZ NOT NULL,
    claimed_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (octet_length(event_xml) BETWEEN 1 AND 4194304)
);

CREATE INDEX idx_pubsub_digest_queue_due
    ON pubsub_digest_queue(deliver_after, subscriber_jid);

CREATE OR REPLACE FUNCTION check_pubsub_collection_edge()
RETURNS TRIGGER AS $$
DECLARE
    parent_kind TEXT;
    parent_limit INTEGER;
    child_count BIGINT;
    cycle_exists BOOLEAN;
BEGIN
    SELECT node_type, children_max
      INTO parent_kind, parent_limit
      FROM pubsub_nodes
     WHERE id = NEW.collection_node_id
     FOR UPDATE;

    IF parent_kind IS DISTINCT FROM 'collection' THEN
        RAISE EXCEPTION 'pubsub collection parent must be a collection node'
            USING ERRCODE = '23514';
    END IF;

    SELECT COUNT(*) INTO child_count
      FROM pubsub_collection_members
     WHERE collection_node_id = NEW.collection_node_id;
    IF child_count >= parent_limit THEN
        RAISE EXCEPTION 'pubsub collection child limit exceeded'
            USING ERRCODE = '23514';
    END IF;

    WITH RECURSIVE descendants(id) AS (
        SELECT child_node_id
          FROM pubsub_collection_members
         WHERE collection_node_id = NEW.child_node_id
        UNION
        SELECT edge.child_node_id
          FROM pubsub_collection_members edge
          JOIN descendants d ON edge.collection_node_id = d.id
    )
    SELECT EXISTS(
        SELECT 1 FROM descendants WHERE id = NEW.collection_node_id
    ) INTO cycle_exists;

    IF cycle_exists THEN
        RAISE EXCEPTION 'pubsub collection cycle'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER pubsub_collection_edge_guard
BEFORE INSERT OR UPDATE ON pubsub_collection_members
FOR EACH ROW EXECUTE FUNCTION check_pubsub_collection_edge();
