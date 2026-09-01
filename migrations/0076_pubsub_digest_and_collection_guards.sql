-- These statements were developed after migration 0046 had already shipped.
-- Keep this forward-only migration idempotent for development schemas which
-- briefly ran an intermediate 0046 containing the digest index.
CREATE INDEX IF NOT EXISTS idx_pubsub_digest_queue_subscriber
    ON pubsub_digest_queue(subscriber_jid);

-- Serialize and validate the collection DAG at the database boundary too.
-- Application code reports clean XEP errors before insertion; this trigger is
-- the final guard for concurrent writers and maintenance SQL.
CREATE OR REPLACE FUNCTION check_pubsub_collection_edge()
RETURNS TRIGGER AS $$
DECLARE
    parent_kind TEXT;
    parent_limit INTEGER;
    child_count BIGINT;
    cycle_exists BOOLEAN;
    depth_exceeded BOOLEAN;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0));

    IF NEW.collection_node_id = NEW.child_node_id THEN
        RAISE EXCEPTION 'pubsub collection cycle' USING ERRCODE = '23514';
    END IF;

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
        SELECT child_node_id FROM pubsub_collection_members
         WHERE collection_node_id = NEW.child_node_id
        UNION
        SELECT edge.child_node_id FROM pubsub_collection_members edge
          JOIN descendants d ON edge.collection_node_id = d.id
    )
    SELECT EXISTS(SELECT 1 FROM descendants WHERE id = NEW.collection_node_id)
      INTO cycle_exists;
    IF cycle_exists THEN
        RAISE EXCEPTION 'pubsub collection cycle' USING ERRCODE = '23514';
    END IF;

    WITH RECURSIVE
    ancestors(id, depth) AS (
        SELECT NEW.collection_node_id, 0
        UNION
        SELECT edge.collection_node_id, a.depth + 1
          FROM ancestors a
          JOIN pubsub_collection_members edge ON edge.child_node_id = a.id
         WHERE a.depth < 64
    ),
    descendants(id, depth) AS (
        SELECT NEW.child_node_id, 0
        UNION
        SELECT edge.child_node_id, d.depth + 1
          FROM descendants d
          JOIN pubsub_collection_members edge ON edge.collection_node_id = d.id
         WHERE d.depth < 64
    )
    SELECT COALESCE((SELECT MAX(depth) FROM ancestors), 0)
         + 1
         + COALESCE((SELECT MAX(depth) FROM descendants), 0) > 64
      INTO depth_exceeded;
    IF depth_exceeded THEN
        RAISE EXCEPTION 'pubsub collection depth exceeds 64'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger
         WHERE tgname = 'pubsub_collection_edge_guard'
           AND tgrelid = 'pubsub_collection_members'::regclass
           AND NOT tgisinternal
    ) THEN
        CREATE TRIGGER pubsub_collection_edge_guard
        BEFORE INSERT OR UPDATE ON pubsub_collection_members
        FOR EACH ROW EXECUTE FUNCTION check_pubsub_collection_edge();
    END IF;
END;
$$;
