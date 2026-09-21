-- A committed credential change must remain visible when Redis is unavailable.
-- Coalesce per account/process; the revision prevents an old ACK from deleting
-- a newer change. No sequence cursor can skip a transaction that commits late.
CREATE TABLE account_revocation_outbox (
    xmpp_domain TEXT NOT NULL,
    node_id TEXT NOT NULL,
    instance_uuid UUID NOT NULL,
    instance_epoch BIGINT NOT NULL CHECK (instance_epoch > 0),
    user_id UUID NOT NULL,
    username TEXT NOT NULL,
    before_generation BIGINT NOT NULL CHECK (before_generation >= 0),
    account_deleted BOOLEAN NOT NULL,
    revision UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (xmpp_domain, node_id, instance_uuid, instance_epoch, user_id)
);
CREATE INDEX account_revocation_outbox_due
    ON account_revocation_outbox (xmpp_domain, node_id, instance_uuid, created_at, user_id);

CREATE FUNCTION northstar_record_account_revocation()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $record_revocation$
DECLARE
    revoked_user UUID;
    revoked_name TEXT;
    fence BIGINT;
    deleted BOOLEAN := TG_OP = 'DELETE';
BEGIN
    IF NOT deleted AND NEW.auth_generation = OLD.auth_generation
       AND NEW.is_disabled = OLD.is_disabled THEN
        RETURN NEW;
    END IF;
    revoked_user := OLD.id;
    revoked_name := OLD.username;
    IF deleted THEN
        fence := OLD.auth_generation;
    ELSE
        fence := NEW.auth_generation;
        IF NEW.is_disabled AND fence < 9223372036854775807 THEN
            fence := fence + 1;
        END IF;
    END IF;
    INSERT INTO account_revocation_outbox AS pending
        (xmpp_domain,node_id,instance_uuid,instance_epoch,user_id,username,
         before_generation,account_deleted)
    SELECT xmpp_domain,node_id,instance_uuid,instance_epoch,revoked_user,
           revoked_name,fence,deleted
      FROM cluster_node_instances
     ORDER BY xmpp_domain,node_id
    ON CONFLICT (xmpp_domain,node_id,instance_uuid,instance_epoch,user_id) DO UPDATE
        SET before_generation=GREATEST(pending.before_generation,EXCLUDED.before_generation),
            account_deleted=pending.account_deleted OR EXCLUDED.account_deleted,
            revision=pg_catalog.gen_random_uuid();
    PERFORM pg_catalog.pg_notify('northstar_account_revocations', TG_TABLE_SCHEMA);
    IF deleted THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$record_revocation$;

CREATE TRIGGER users_account_revocation
AFTER UPDATE OF auth_generation,is_disabled OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION northstar_record_account_revocation();

CREATE FUNCTION northstar_pending_account_revocations(
    p_domain TEXT,p_node TEXT,p_instance UUID,p_epoch BIGINT,p_limit INTEGER
)
RETURNS TABLE(user_id UUID,username TEXT,before_generation BIGINT,
              account_deleted BOOLEAN,revision UUID)
LANGUAGE plpgsql SECURITY DEFINER AS $pending_revocations$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM cluster_node_instances node
        WHERE node.xmpp_domain=p_domain AND node.node_id=p_node
          AND node.instance_uuid=p_instance AND node.instance_epoch=p_epoch) THEN
        RAISE EXCEPTION 'revocation consumer process was replaced' USING ERRCODE='55000';
    END IF;
    RETURN QUERY SELECT event.user_id,event.username,event.before_generation,
                        event.account_deleted,event.revision
      FROM account_revocation_outbox event
     WHERE event.xmpp_domain=p_domain AND event.node_id=p_node
       AND event.instance_uuid=p_instance AND event.instance_epoch=p_epoch
     ORDER BY event.created_at,event.user_id LIMIT LEAST(GREATEST(p_limit,1),256);
END;
$pending_revocations$;

CREATE FUNCTION northstar_ack_account_revocations(
    p_domain TEXT,p_node TEXT,p_instance UUID,p_epoch BIGINT,p_revisions UUID[]
)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER AS $ack_revocations$
DECLARE removed BIGINT;
BEGIN
    IF pg_catalog.cardinality(p_revisions)>256 THEN
        RAISE EXCEPTION 'revocation ACK exceeds batch limit' USING ERRCODE='22023';
    END IF;
    DELETE FROM account_revocation_outbox event
     WHERE event.xmpp_domain=p_domain AND event.node_id=p_node
       AND event.instance_uuid=p_instance AND event.instance_epoch=p_epoch
       AND event.revision=ANY(p_revisions);
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$ack_revocations$;

CREATE FUNCTION northstar_cleanup_account_revocations(p_limit INTEGER)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER AS $cleanup_revocations$
DECLARE removed BIGINT;
BEGIN
    WITH obsolete AS MATERIALIZED (
        SELECT event.ctid FROM account_revocation_outbox event
         WHERE NOT EXISTS (SELECT 1 FROM cluster_node_instances node
             WHERE node.xmpp_domain=event.xmpp_domain AND node.node_id=event.node_id
               AND node.instance_uuid=event.instance_uuid
               AND node.instance_epoch=event.instance_epoch)
         ORDER BY event.created_at,event.user_id
         LIMIT LEAST(GREATEST(p_limit,1),1000) FOR UPDATE OF event SKIP LOCKED
    )
    DELETE FROM account_revocation_outbox event USING obsolete
     WHERE event.ctid=obsolete.ctid;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$cleanup_revocations$;

DO $harden_revocations$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_record_account_revocation()',
        'northstar_pending_account_revocations(text,text,uuid,int8,int4)',
        'northstar_ack_account_revocations(text,text,uuid,int8,uuid[])',
        'northstar_cleanup_account_revocations(int4)'
    ] LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %I.%s RESET ALL',migration_schema,routine_signature);
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema);
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',migration_schema,routine_signature);
    END LOOP;
    EXECUTE pg_catalog.format('REVOKE ALL ON TABLE %I.account_revocation_outbox FROM PUBLIC',migration_schema);
END;
$harden_revocations$;
