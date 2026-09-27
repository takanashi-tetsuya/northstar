-- A committed local direct spool write leaves one coalesced, durable wake for
-- each stable node ID. A UUID revision, not a timestamp or sequence cursor,
-- fences an ACK against another node's late-committing producer.
CREATE TABLE direct_spool_wake_outbox (
    xmpp_domain TEXT NOT NULL CHECK (octet_length(xmpp_domain) BETWEEN 1 AND 255),
    node_id VARCHAR(128) NOT NULL CHECK (node_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    revision UUID NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    claim_token UUID,
    claim_instance_uuid UUID,
    claim_instance_epoch BIGINT,
    claim_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (xmpp_domain,node_id,recipient_id),
    CHECK ((claim_token IS NULL AND claim_instance_uuid IS NULL
            AND claim_instance_epoch IS NULL AND claim_until IS NULL)
        OR (claim_token IS NOT NULL AND claim_instance_uuid IS NOT NULL
            AND claim_instance_epoch >= 1 AND claim_until IS NOT NULL))
);
CREATE INDEX direct_spool_wake_due_idx
    ON direct_spool_wake_outbox (xmpp_domain,node_id,next_attempt_at,recipient_id);
CREATE INDEX direct_spool_wake_stale_idx
    ON direct_spool_wake_outbox (updated_at,xmpp_domain,node_id,recipient_id);
-- Route enumeration is lexical and bounded by recipient. The prior live index
-- places lease_until before full_jid, so it cannot serve this cursor order.
CREATE INDEX cluster_session_routes_direct_spool_page_idx
    ON cluster_session_routes (namespace,bare_jid,full_jid);

CREATE FUNCTION northstar_record_direct_spool_wake(p_domain TEXT,p_recipient UUID)
RETURNS BIGINT LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $record_direct_spool_wake$
DECLARE affected BIGINT;
BEGIN
    IF p_domain IS NULL OR octet_length(p_domain) NOT BETWEEN 1 AND 255
       OR p_recipient IS NULL THEN
        RAISE EXCEPTION 'invalid direct spool wake recipient' USING ERRCODE='22023';
    END IF;
    -- The repository takes this shared transaction lock before key/instance
    -- row locks. Reacquiring it here verifies the claim serialization contract
    -- without weakening concurrent producers.
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(4741070036074865762);
    -- Admission fails before the message COMMIT if fanout would exceed the
    -- reviewed bound; its offline row and any wake changes roll back together.
    IF (SELECT pg_catalog.count(*) FROM (
            SELECT 1 FROM cluster_node_instances AS instance
             WHERE instance.xmpp_domain=p_domain
               AND instance.lease_until>clock_timestamp()
             LIMIT 257
        ) AS bounded_nodes) > 256 THEN
        RAISE EXCEPTION 'direct spool wake fanout exceeds 256 live nodes'
          USING ERRCODE='54000';
    END IF;
    INSERT INTO direct_spool_wake_outbox AS pending
        (xmpp_domain,node_id,recipient_id)
    SELECT instance.xmpp_domain,instance.node_id,p_recipient
     FROM cluster_node_instances AS instance
     WHERE instance.xmpp_domain=p_domain
       AND instance.lease_until>clock_timestamp()
    ON CONFLICT (xmpp_domain,node_id,recipient_id) DO UPDATE
       SET revision=pg_catalog.gen_random_uuid(),
           next_attempt_at=clock_timestamp(),
           claim_token=NULL,claim_instance_uuid=NULL,
           claim_instance_epoch=NULL,claim_until=NULL,
           updated_at=clock_timestamp();
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected > 0 THEN
        -- current_schema() is pg_catalog under this definer's pinned search
        -- path. Resolve this exact routine's owning schema for the listener.
        PERFORM pg_catalog.pg_notify(
            'northstar_direct_spool_wake_v1',
            (SELECT namespace.nspname
               FROM pg_catalog.pg_proc AS routine
               JOIN pg_catalog.pg_namespace AS namespace
                 ON namespace.oid=routine.pronamespace
              WHERE routine.oid=pg_catalog.to_regprocedure(
                  'northstar_record_direct_spool_wake(text,uuid)'))
        );
    END IF;
    RETURN affected;
END;
$record_direct_spool_wake$;

CREATE FUNCTION northstar_claim_direct_spool_wakes(
    p_domain TEXT,p_node TEXT,p_instance UUID,p_epoch BIGINT,p_limit INTEGER
) RETURNS TABLE(recipient_id UUID,revision UUID,claim_token UUID,replay_cutoff TIMESTAMPTZ)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $claim_direct_spool_wakes$
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'invalid direct spool wake claim limit' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM cluster_node_instances AS instance
     WHERE instance.xmpp_domain=p_domain AND instance.node_id=p_node
       AND instance.instance_uuid=p_instance AND instance.instance_epoch=p_epoch
       AND instance.lease_until>clock_timestamp() FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'direct spool wake claimant is not authoritative'
          USING ERRCODE='55000';
    END IF;
    RETURN QUERY
    WITH due AS MATERIALIZED (
        SELECT pending.xmpp_domain,pending.node_id,pending.recipient_id
          FROM direct_spool_wake_outbox AS pending
         WHERE pending.xmpp_domain=p_domain AND pending.node_id=p_node
           AND pending.next_attempt_at<=clock_timestamp()
           AND (pending.claim_until IS NULL
                OR pending.claim_until<=clock_timestamp()
                OR pending.claim_instance_uuid<>p_instance
                OR pending.claim_instance_epoch<>p_epoch)
         ORDER BY pending.next_attempt_at,pending.recipient_id
         LIMIT p_limit FOR UPDATE OF pending SKIP LOCKED
    ), claimed AS (
        UPDATE direct_spool_wake_outbox AS pending
           SET claim_token=pg_catalog.gen_random_uuid(),
               claim_instance_uuid=p_instance,claim_instance_epoch=p_epoch,
               claim_until=clock_timestamp()+INTERVAL '90 seconds',
               updated_at=clock_timestamp()
          FROM due
         WHERE (pending.xmpp_domain,pending.node_id,pending.recipient_id)=
               (due.xmpp_domain,due.node_id,due.recipient_id)
        RETURNING pending.recipient_id,pending.revision,pending.claim_token
    )
    SELECT claimed.recipient_id,claimed.revision,claimed.claim_token,
           clock_timestamp()
      FROM claimed;
END;
$claim_direct_spool_wakes$;

CREATE FUNCTION northstar_direct_spool_routes_page(
    p_domain TEXT,p_node TEXT,p_instance UUID,p_epoch BIGINT,
    p_recipient UUID,p_after TEXT,p_limit INTEGER
) RETURNS TABLE(full_jid TEXT,connection_id UUID)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $direct_spool_routes_page$
BEGIN
    IF p_recipient IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'invalid direct spool route page' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM cluster_node_instances AS instance
     WHERE instance.xmpp_domain=p_domain AND instance.node_id=p_node
       AND instance.instance_uuid=p_instance AND instance.instance_epoch=p_epoch
       AND instance.lease_until>clock_timestamp() FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'direct spool route owner is not authoritative'
          USING ERRCODE='55000';
    END IF;
    RETURN QUERY
    SELECT route.full_jid::TEXT,route.connection_uuid
      FROM users AS recipient
      JOIN cluster_session_routes AS route
        ON route.namespace=p_domain
       AND route.bare_jid=recipient.username || '@' || p_domain
     WHERE recipient.id=p_recipient AND NOT recipient.is_disabled
       AND route.owner_node_id=p_node
       AND route.owner_instance_uuid=p_instance
       AND route.owner_instance_epoch=p_epoch
       AND route.lease_until>clock_timestamp()
       AND (p_after IS NULL OR route.full_jid>p_after)
       AND northstar_cluster_session_route_authorized(
             route.full_jid,route.connection_uuid,route.claim_proof_kind,
             route.sm_session_id,route.sm_claim_token)
     ORDER BY route.full_jid LIMIT p_limit;
END;
$direct_spool_routes_page$;

CREATE FUNCTION northstar_ack_direct_spool_wake_if_empty(
    p_domain TEXT,p_node TEXT,p_instance UUID,p_epoch BIGINT,
    p_recipient UUID,p_revision UUID,p_claim UUID
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $ack_direct_spool_wake$
BEGIN
    PERFORM 1 FROM cluster_node_instances AS instance
     WHERE instance.xmpp_domain=p_domain AND instance.node_id=p_node
       AND instance.instance_uuid=p_instance AND instance.instance_epoch=p_epoch
       AND instance.lease_until>clock_timestamp() FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    -- The producer UPSERT and this DELETE lock the same stable node/recipient
    -- row. If a new spool transaction wins first its revision changes; if this
    -- ACK wins first the producer reinserts the wake after the ACK commits.
    DELETE FROM direct_spool_wake_outbox AS pending
     WHERE pending.xmpp_domain=p_domain AND pending.node_id=p_node
       AND pending.recipient_id=p_recipient AND pending.revision=p_revision
       AND pending.claim_token=p_claim
       AND pending.claim_instance_uuid=p_instance
       AND pending.claim_instance_epoch=p_epoch
       AND pending.claim_until>clock_timestamp()
       AND NOT EXISTS (
           SELECT 1 FROM offline_messages AS message
            WHERE message.recipient_id=p_recipient
       );
    RETURN FOUND;
END;
$ack_direct_spool_wake$;

CREATE FUNCTION northstar_defer_direct_spool_wake(
    p_domain TEXT,p_node TEXT,p_instance UUID,p_epoch BIGINT,
    p_recipient UUID,p_revision UUID,p_claim UUID,p_delay_seconds INTEGER
) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $defer_direct_spool_wake$
BEGIN
    IF p_delay_seconds IS NULL OR p_delay_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION 'invalid direct spool wake retry delay' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM cluster_node_instances AS instance
     WHERE instance.xmpp_domain=p_domain AND instance.node_id=p_node
       AND instance.instance_uuid=p_instance AND instance.instance_epoch=p_epoch
       AND instance.lease_until>clock_timestamp() FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    UPDATE direct_spool_wake_outbox AS pending
       SET next_attempt_at=clock_timestamp()+
               pg_catalog.make_interval(secs=>p_delay_seconds),
           claim_token=NULL,claim_instance_uuid=NULL,
           claim_instance_epoch=NULL,claim_until=NULL,
           updated_at=clock_timestamp()
     WHERE pending.xmpp_domain=p_domain AND pending.node_id=p_node
       AND pending.recipient_id=p_recipient AND pending.revision=p_revision
       AND pending.claim_token=p_claim
       AND pending.claim_instance_uuid=p_instance
       AND pending.claim_instance_epoch=p_epoch;
    RETURN FOUND;
END;
$defer_direct_spool_wake$;

-- Keep replacement-node handoff possible across short lease gaps. Expired
-- stable node slots are pruned only after seven days with no live route; a
-- later claim/bind then obtains a fresh replay cutoff after the old commit.
CREATE FUNCTION northstar_cleanup_direct_spool_wakes(p_limit INTEGER)
RETURNS BIGINT LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $cleanup_direct_spool_wakes$
DECLARE affected BIGINT;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'invalid direct spool wake cleanup limit' USING ERRCODE='22023';
    END IF;
    -- Serialize with new instance claims before taking outbox row locks.
    PERFORM pg_catalog.pg_advisory_xact_lock_shared(4741070036074865762);
    WITH stale AS MATERIALIZED (
        SELECT pending.xmpp_domain,pending.node_id,pending.recipient_id
          FROM direct_spool_wake_outbox AS pending
          LEFT JOIN cluster_node_instances AS instance
            ON instance.xmpp_domain=pending.xmpp_domain
           AND instance.node_id=pending.node_id
         WHERE pending.updated_at<=clock_timestamp()-INTERVAL '7 days'
           AND (instance.node_id IS NULL
                OR instance.lease_until<=clock_timestamp()-INTERVAL '7 days')
           AND NOT EXISTS (
               SELECT 1 FROM cluster_session_routes AS route
                WHERE route.namespace=pending.xmpp_domain
                  AND route.owner_node_id=pending.node_id
                  AND route.lease_until>clock_timestamp()
           )
         ORDER BY pending.updated_at,pending.recipient_id
         LIMIT p_limit FOR UPDATE OF pending SKIP LOCKED
    )
    DELETE FROM direct_spool_wake_outbox AS pending USING stale
     WHERE (pending.xmpp_domain,pending.node_id,pending.recipient_id)=
           (stale.xmpp_domain,stale.node_id,stale.recipient_id);
    GET DIAGNOSTICS affected = ROW_COUNT;
    RETURN affected;
END;
$cleanup_direct_spool_wakes$;

DO $pin_direct_spool_wake$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_record_direct_spool_wake(text,uuid)',
        'northstar_claim_direct_spool_wakes(text,text,uuid,int8,int4)',
        'northstar_direct_spool_routes_page(text,text,uuid,int8,uuid,text,int4)',
        'northstar_ack_direct_spool_wake_if_empty(text,text,uuid,int8,uuid,uuid,uuid)',
        'northstar_defer_direct_spool_wake(text,text,uuid,int8,uuid,uuid,uuid,int4)',
        'northstar_cleanup_direct_spool_wakes(int4)'
    ] LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %I.%s RESET ALL',migration_schema,routine_signature);
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema);
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',migration_schema,routine_signature);
    END LOOP;
    EXECUTE pg_catalog.format('REVOKE ALL ON TABLE %I.direct_spool_wake_outbox FROM PUBLIC',migration_schema);
END;
$pin_direct_spool_wake$;
