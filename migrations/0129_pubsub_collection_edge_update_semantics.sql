-- A collection edge has two identities: (collection_node_id, child_node_id).
-- Updating metadata such as created_at must not consume an additional child
-- slot.  The old trigger ran for every UPDATE and counted the existing edge as
-- though it were a new insertion, so a first association at children_max = 1
-- was rolled back when the runtime stamped its authoritative event time.
--
-- Keep the database guard authoritative for INSERTs and actual key moves.  A
-- key move is evaluated against the prospective graph: its old edge is removed
-- from quota, cycle, and depth calculations before the new edge is considered.

CREATE OR REPLACE FUNCTION check_pubsub_collection_edge()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    parent_kind TEXT;
    parent_limit INTEGER;
    child_count BIGINT;
    cycle_exists BOOLEAN;
    depth_exceeded BOOLEAN;
    old_collection_id UUID;
    old_child_id UUID;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        old_collection_id := OLD.collection_node_id;
        old_child_id := OLD.child_node_id;
        -- A trigger may be invoked by `UPDATE OF` even when a caller assigns
        -- the same identities.  That is a metadata/no-op update, not a new
        -- graph edge and therefore cannot consume quota.
        IF old_collection_id = NEW.collection_node_id
           AND old_child_id = NEW.child_node_id THEN
            RETURN NEW;
        END IF;
    END IF;

    -- The application preflights this path for XMPP errors; this global lock
    -- remains the final database authority for direct SQL and concurrent
    -- writers.
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

    -- On a key move the old edge is still visible to a BEFORE UPDATE trigger.
    -- Excluding it makes the count describe the prospective graph rather than
    -- falsely treating a replacement as an additional child.
    SELECT COUNT(*) INTO child_count
      FROM pubsub_collection_members edge
     WHERE edge.collection_node_id = NEW.collection_node_id
       AND (
            old_collection_id IS NULL
            OR (edge.collection_node_id, edge.child_node_id)
               IS DISTINCT FROM (old_collection_id, old_child_id)
       );
    IF child_count >= parent_limit THEN
        RAISE EXCEPTION 'pubsub collection child limit exceeded'
            USING ERRCODE = '23514';
    END IF;

    -- Treat a key move as remove-old/add-new for graph checks as well.  This
    -- prevents both false cycle/depth rejections and a raw-SQL move bypass.
    WITH RECURSIVE graph_edges(collection_node_id, child_node_id) AS (
        SELECT edge.collection_node_id, edge.child_node_id
          FROM pubsub_collection_members edge
         WHERE old_collection_id IS NULL
            OR (edge.collection_node_id, edge.child_node_id)
               IS DISTINCT FROM (old_collection_id, old_child_id)
    ), descendants(id) AS (
        SELECT child_node_id
          FROM graph_edges
         WHERE collection_node_id = NEW.child_node_id
        UNION
        SELECT edge.child_node_id
          FROM graph_edges edge
          JOIN descendants descendant ON edge.collection_node_id = descendant.id
    )
    SELECT EXISTS(SELECT 1 FROM descendants WHERE id = NEW.collection_node_id)
      INTO cycle_exists;
    IF cycle_exists THEN
        RAISE EXCEPTION 'pubsub collection cycle' USING ERRCODE = '23514';
    END IF;

    WITH RECURSIVE graph_edges(collection_node_id, child_node_id) AS (
        SELECT edge.collection_node_id, edge.child_node_id
          FROM pubsub_collection_members edge
         WHERE old_collection_id IS NULL
            OR (edge.collection_node_id, edge.child_node_id)
               IS DISTINCT FROM (old_collection_id, old_child_id)
    ), ancestors(id, depth) AS (
        SELECT NEW.collection_node_id, 0
        UNION
        SELECT edge.collection_node_id, ancestor.depth + 1
          FROM ancestors ancestor
          JOIN graph_edges edge ON edge.child_node_id = ancestor.id
         WHERE ancestor.depth < 64
    ), descendants(id, depth) AS (
        SELECT NEW.child_node_id, 0
        UNION
        SELECT edge.child_node_id, descendant.depth + 1
          FROM descendants descendant
          JOIN graph_edges edge ON edge.collection_node_id = descendant.id
         WHERE descendant.depth < 64
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
$$;

-- Do not run graph validation for timestamp-only updates.  The function still
-- has its no-op guard so future trigger maintenance cannot reintroduce the
-- quota bug by broadening this UPDATE column list accidentally.
DROP TRIGGER IF EXISTS pubsub_collection_edge_guard ON pubsub_collection_members;
CREATE TRIGGER pubsub_collection_edge_guard
BEFORE INSERT OR UPDATE OF collection_node_id, child_node_id
ON pubsub_collection_members
FOR EACH ROW EXECUTE FUNCTION check_pubsub_collection_edge();
