-- Transport-bound completion for multi-stanza clustered MUC events.
-- The parent outbox row remains authoritative; these rows only remember
-- which ordinal crossed a durable transport ownership/write boundary.
-- Resolve prerequisites through the exact migration schema before creating
-- either foreign key. A damaged isolated migration must not silently bind to
-- same-named relations left behind in a shared fallback schema.
DO $cluster_muc_delivery_prerequisites$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
BEGIN
    IF migration_schema IS NULL
       OR migration_schema = 'information_schema'
       OR pg_catalog.left(migration_schema, 3) = 'pg_' THEN
        RAISE EXCEPTION 'unsafe migration schema for cluster MUC delivery receipts: %',
            migration_schema
            USING ERRCODE = '3F000';
    END IF;
    IF pg_catalog.to_regclass(pg_catalog.format(
           '%I.%I', migration_schema, 'cluster_muc_event_outbox'
       )) IS NULL
       OR pg_catalog.to_regclass(pg_catalog.format(
           '%I.%I', migration_schema, 'cluster_muc_occupancies'
       )) IS NULL THEN
        RAISE EXCEPTION 'cluster MUC delivery prerequisites are absent from migration schema %',
            migration_schema
            USING ERRCODE = '42P01';
    END IF;
END;
$cluster_muc_delivery_prerequisites$;

CREATE TABLE cluster_muc_event_delivery_items (
    delivery_id UUID NOT NULL REFERENCES cluster_muc_event_outbox(delivery_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 64),
    stable_id TEXT NOT NULL CHECK (octet_length(stable_id) BETWEEN 1 AND 128),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (delivery_id, ordinal),
    UNIQUE (delivery_id, stable_id)
);

COMMENT ON TABLE cluster_muc_event_delivery_items IS
'Per-ordinal transport completion. Completion means SM/BOSH/suspended storage owns the stanza or a non-SM/federation socket write completed; it never means mere mpsc admission.';

CREATE TABLE cluster_muc_delivery_handoffs (
 delivery_id UUID NOT NULL REFERENCES cluster_muc_event_outbox(delivery_id) ON DELETE CASCADE,
 handoff_version BIGINT NOT NULL CHECK(handoff_version>=1),
 previous_node_id TEXT NOT NULL, previous_connection_uuid UUID NOT NULL,
 previous_connection_epoch BIGINT NOT NULL, new_node_id TEXT NOT NULL,
 new_connection_uuid UUID NOT NULL, new_connection_epoch BIGINT NOT NULL,
 audience_snapshot JSONB NOT NULL CHECK(jsonb_typeof(audience_snapshot)='object'
   AND octet_length(audience_snapshot::TEXT)<=16384),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(delivery_id,handoff_version),
 UNIQUE(delivery_id,new_node_id,new_connection_uuid,new_connection_epoch)
);

-- The only permitted mutation of an immutable audience projection is an
-- exact SM ownership handoff. It retains delivery/event identity and ordinal
-- progress while moving unfinished rows to the newly authoritative node.
CREATE OR REPLACE FUNCTION northstar_transfer_cluster_muc_outbox(
    p_room_id UUID,
    p_room_epoch UUID,
    p_occupant_incarnation UUID,
    p_old_connection_uuid UUID,
    p_old_connection_epoch BIGINT,
    p_new_connection_uuid UUID,
    p_new_connection_epoch BIGINT,
    p_new_node TEXT
) RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE moved BIGINT;
BEGIN
    PERFORM 1 FROM cluster_muc_occupancies o
       WHERE o.room_id=p_room_id AND o.room_epoch=p_room_epoch
        AND o.occupant_incarnation=p_occupant_incarnation
        AND o.connection_uuid=p_new_connection_uuid AND o.connection_epoch=p_new_connection_epoch
        AND o.owner_node_id=p_new_node AND o.state IN('active','suspended')
        AND o.lease_until>clock_timestamp()
       FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'cluster MUC handoff destination is not authoritative';
    END IF;
    -- Serialize on the exact old delivery tuple before appending an immutable
    -- version. A concurrent/stale handoff therefore observes no eligible row
    -- after the winner commits and cannot manufacture an unused snapshot.
    PERFORM 1 FROM cluster_muc_event_outbox d
     WHERE d.room_id=p_room_id AND d.room_epoch=p_room_epoch
       AND d.recipient_occupant_incarnation=p_occupant_incarnation
       AND d.recipient_connection_uuid=p_old_connection_uuid
       AND d.recipient_connection_epoch=p_old_connection_epoch
     ORDER BY d.delivery_id FOR UPDATE;
    INSERT INTO cluster_muc_delivery_handoffs(
      delivery_id,handoff_version,previous_node_id,previous_connection_uuid,
      previous_connection_epoch,new_node_id,new_connection_uuid,new_connection_epoch,audience_snapshot)
    SELECT d.delivery_id,COALESCE(h.handoff_version,0)+1,d.target_node_id,
      d.recipient_connection_uuid,d.recipient_connection_epoch,p_new_node,
      p_new_connection_uuid,p_new_connection_epoch,
      jsonb_build_object(
       'room_id',o.room_id,'room_epoch',o.room_epoch,'identity_kind',o.identity_kind,
       'local_user_id',o.local_user_id,'bare_jid',o.bare_jid,'full_jid',o.full_jid,
       'nick',o.nick,'authenticated_domain',o.authenticated_domain,'owner_node_id',o.owner_node_id,
       'occupant_incarnation',o.occupant_incarnation,'occupancy_epoch',o.occupancy_epoch,
       'connection_uuid',o.connection_uuid,'connection_epoch',o.connection_epoch,
       'sm_session_id',o.sm_session_id,'role',o.role,'affiliation',o.affiliation)
    FROM cluster_muc_event_outbox d
    JOIN cluster_muc_occupancies o ON o.room_id=d.room_id AND o.room_epoch=d.room_epoch
      AND o.occupant_incarnation=d.recipient_occupant_incarnation
      AND o.connection_uuid=p_new_connection_uuid AND o.connection_epoch=p_new_connection_epoch
      AND o.owner_node_id=p_new_node AND o.state IN('active','suspended')
      AND o.lease_until>clock_timestamp()
    LEFT JOIN LATERAL (
      SELECT MAX(history.handoff_version) AS handoff_version
      FROM cluster_muc_delivery_handoffs history WHERE history.delivery_id=d.delivery_id
    ) h ON TRUE
    WHERE d.room_id=p_room_id AND d.room_epoch=p_room_epoch
      AND d.recipient_occupant_incarnation=p_occupant_incarnation
      AND d.recipient_connection_uuid=p_old_connection_uuid
      AND d.recipient_connection_epoch=p_old_connection_epoch
    ON CONFLICT(delivery_id,new_node_id,new_connection_uuid,new_connection_epoch) DO NOTHING;
    UPDATE cluster_muc_event_outbox
       SET target_node_id=p_new_node,
           recipient_connection_uuid=p_new_connection_uuid,
           recipient_connection_epoch=p_new_connection_epoch,
           claim_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()
     WHERE room_id=p_room_id AND room_epoch=p_room_epoch
       AND recipient_occupant_incarnation=p_occupant_incarnation
       AND recipient_connection_uuid=p_old_connection_uuid
       AND recipient_connection_epoch=p_old_connection_epoch;
    GET DIAGNOSTICS moved = ROW_COUNT;
    RETURN moved;
END $$;

CREATE OR REPLACE FUNCTION fence_cluster_muc_outbox_identity()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF (NEW.target_node_id,NEW.recipient_connection_uuid,NEW.recipient_connection_epoch)
       IS DISTINCT FROM
       (OLD.target_node_id,OLD.recipient_connection_uuid,OLD.recipient_connection_epoch) THEN
      IF ROW(NEW.delivery_id,NEW.operation_id,NEW.room_id,NEW.room_epoch,
               NEW.event_sequence,NEW.event_id,NEW.audience_kind,
               NEW.recipient_full_jid,NEW.recipient_nick,
               NEW.recipient_occupant_incarnation,NEW.recipient_occupancy_epoch,
               NEW.payload,NEW.payload_digest,NEW.capacity_shard,NEW.created_at,NEW.expires_at)
           IS DISTINCT FROM
           ROW(OLD.delivery_id,OLD.operation_id,OLD.room_id,OLD.room_epoch,
               OLD.event_sequence,OLD.event_id,OLD.audience_kind,
               OLD.recipient_full_jid,OLD.recipient_nick,
               OLD.recipient_occupant_incarnation,OLD.recipient_occupancy_epoch,
               OLD.payload,OLD.payload_digest,OLD.capacity_shard,OLD.created_at,OLD.expires_at) THEN
        RAISE EXCEPTION 'cluster MUC handoff changed immutable delivery identity';
      END IF;
      PERFORM 1 FROM cluster_muc_delivery_handoffs h
       JOIN cluster_muc_occupancies o ON o.room_id=NEW.room_id AND o.room_epoch=NEW.room_epoch
        AND o.occupant_incarnation=NEW.recipient_occupant_incarnation
        AND o.connection_uuid=NEW.recipient_connection_uuid
        AND o.connection_epoch=NEW.recipient_connection_epoch
        AND o.owner_node_id=NEW.target_node_id AND o.state IN('active','suspended')
        AND o.lease_until>clock_timestamp()
       WHERE h.delivery_id=OLD.delivery_id
        AND h.handoff_version=(SELECT MAX(latest.handoff_version)
          FROM cluster_muc_delivery_handoffs latest WHERE latest.delivery_id=OLD.delivery_id)
        AND (h.previous_node_id,h.previous_connection_uuid,h.previous_connection_epoch)
          IS NOT DISTINCT FROM
            (OLD.target_node_id,OLD.recipient_connection_uuid,OLD.recipient_connection_epoch)
        AND (h.new_node_id,h.new_connection_uuid,h.new_connection_epoch)
          IS NOT DISTINCT FROM
            (NEW.target_node_id,NEW.recipient_connection_uuid,NEW.recipient_connection_epoch);
      IF NOT FOUND THEN
        RAISE EXCEPTION 'cluster MUC handoff has no exact authoritative history';
      END IF;
      RETURN NEW;
    END IF;
    IF ROW(NEW.delivery_id,NEW.operation_id,NEW.room_id,NEW.room_epoch,
           NEW.event_sequence,NEW.event_id,NEW.audience_kind,NEW.target_node_id,
           NEW.recipient_full_jid,NEW.recipient_nick,NEW.recipient_occupant_incarnation,
           NEW.recipient_occupancy_epoch,NEW.recipient_connection_uuid,
           NEW.recipient_connection_epoch,NEW.payload,NEW.payload_digest,
           NEW.capacity_shard,NEW.created_at,NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.delivery_id,OLD.operation_id,OLD.room_id,OLD.room_epoch,
           OLD.event_sequence,OLD.event_id,OLD.audience_kind,OLD.target_node_id,
           OLD.recipient_full_jid,OLD.recipient_nick,OLD.recipient_occupant_incarnation,
           OLD.recipient_occupancy_epoch,OLD.recipient_connection_uuid,
           OLD.recipient_connection_epoch,OLD.payload,OLD.payload_digest,
           OLD.capacity_shard,OLD.created_at,OLD.expires_at) THEN
        RAISE EXCEPTION 'cluster MUC outbox delivery identity is immutable';
    END IF;
    RETURN NEW;
END $$;

-- These SECURITY DEFINER functions must resolve application relations in the
-- schema where this migration installed them, not in a shared `public` schema
-- and not through the caller's search_path. Capture the migration schema once
-- and persist a fixed, catalog-first path on each function. `pg_temp` is last
-- so a caller cannot shadow either built-ins or application relations.
DO $migration_schema_capture$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
BEGIN
    IF migration_schema IS NULL
       OR migration_schema = 'information_schema'
       OR pg_catalog.left(migration_schema, 3) = 'pg_' THEN
        RAISE EXCEPTION 'unsafe migration schema for cluster MUC SECURITY DEFINER functions: %',
            migration_schema
            USING ERRCODE = '3F000';
    END IF;

    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.northstar_transfer_cluster_muc_outbox('
        'pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,pg_catalog.uuid,'
        'pg_catalog.int8,pg_catalog.uuid,pg_catalog.int8,pg_catalog.text) '
        'SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,
        migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.fence_cluster_muc_outbox_identity() '
        'SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,
        migration_schema
    );
END;
$migration_schema_capture$;

REVOKE ALL ON TABLE cluster_muc_delivery_handoffs FROM PUBLIC;
REVOKE ALL ON FUNCTION northstar_transfer_cluster_muc_outbox(UUID,UUID,UUID,UUID,BIGINT,UUID,BIGINT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION fence_cluster_muc_outbox_identity() FROM PUBLIC;
