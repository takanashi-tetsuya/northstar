-- Database capability hardening for immutable governance history.
--
-- A transaction-local GUC is provenance metadata, not authority: any role can
-- set a custom GUC.  The immutable-history guards therefore accept a bounded
-- cleanup marker only while the command executes as the exact owning role of
-- the protected relation.  The only runtime paths which can satisfy both
-- conditions are the reviewed, owner-held SECURITY DEFINER capabilities below.

CREATE OR REPLACE FUNCTION prevent_legal_hold_link_mutation() RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME='legal_hold_offline_snapshots' AND TG_OP='DELETE'
       AND current_setting('northstar.hold_snapshot_retention_cleanup',TRUE)='bounded-v1' THEN
        IF current_user <> pg_catalog.pg_get_userbyid(
            (SELECT relation.relowner FROM pg_catalog.pg_class relation
              WHERE relation.oid=TG_RELID)
        ) THEN
            RAISE EXCEPTION 'untrusted legal-hold snapshot cleanup marker'
                USING ERRCODE='42501';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'legal hold target history is immutable' USING ERRCODE='55000';
END;
$$;

CREATE OR REPLACE FUNCTION enforce_audit_log_immutability() RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='DELETE'
       AND current_setting('northstar.audit_retention_cleanup',TRUE)='bounded-v1' THEN
        IF current_user <> pg_catalog.pg_get_userbyid(
            (SELECT relation.relowner FROM pg_catalog.pg_class relation
              WHERE relation.oid=TG_RELID)
        ) THEN
            RAISE EXCEPTION 'untrusted audit cleanup marker' USING ERRCODE='42501';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit history is immutable outside bounded retention cleanup'
        USING ERRCODE='55000';
END;
$$;

CREATE OR REPLACE FUNCTION enforce_governance_export_lease_history() RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='DELETE'
       AND current_setting('northstar.governance_export_cleanup',TRUE)='bounded-v1' THEN
        IF current_user <> pg_catalog.pg_get_userbyid(
            (SELECT relation.relowner FROM pg_catalog.pg_class relation
              WHERE relation.oid=TG_RELID)
        ) THEN
            RAISE EXCEPTION 'untrusted governance-export cleanup marker'
                USING ERRCODE='42501';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP='UPDATE'
       AND OLD.id=NEW.id
       AND OLD.export_kind=NEW.export_kind
       AND OLD.actor_id=NEW.actor_id
       AND OLD.hold_id IS NOT DISTINCT FROM NEW.hold_id
       AND OLD.filter_start IS NOT DISTINCT FROM NEW.filter_start
       AND OLD.filter_end IS NOT DISTINCT FROM NEW.filter_end
       AND OLD.snapshot_at=NEW.snapshot_at
       AND OLD.snapshot_max_id IS NOT DISTINCT FROM NEW.snapshot_max_id
       AND OLD.expires_at=NEW.expires_at
       AND OLD.created_at=NEW.created_at
       AND OLD.completed_at IS NULL
       AND NEW.completed_at IS NOT NULL
       AND NEW.completed_at <= OLD.expires_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'governance export lease history is immutable'
        USING ERRCODE='55000';
END;
$$;

CREATE OR REPLACE FUNCTION reject_cluster_muc_operation_mutation() RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='DELETE'
       AND current_setting('northstar.cluster_muc_retention_cleanup',TRUE)='bounded-v1' THEN
        IF current_user <> pg_catalog.pg_get_userbyid(
            (SELECT relation.relowner FROM pg_catalog.pg_class relation
              WHERE relation.oid=TG_RELID)
        ) THEN
            RAISE EXCEPTION 'untrusted cluster MUC cleanup marker' USING ERRCODE='42501';
        END IF;
        IF EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                EXISTS (
                    SELECT 1 FROM legal_hold_scopes scope_link
                     WHERE scope_link.hold_id=hold.id
                       AND scope_link.scope_type='muc_archive_room'
                       AND scope_link.subject_id=OLD.room_id
                ) OR EXISTS (
                    SELECT 1 FROM legal_hold_muc_archives exact_link
                     WHERE exact_link.hold_id=hold.id
                       AND exact_link.room_id=OLD.room_id
                )
             )
        ) THEN
            RAISE EXCEPTION 'cluster MUC operation is protected by an active legal hold'
                USING ERRCODE='55000';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'cluster MUC operations are append-only' USING ERRCODE='55000';
END;
$$;

-- The complete release transition, authorization check, export fence and
-- audit projection share one owner-executed transaction.  Application code
-- receives a deliberately small typed outcome and never receives direct
-- UPDATE authority on legal_holds.
CREATE OR REPLACE FUNCTION northstar_release_legal_hold(
    requested_actor_id UUID,
    requested_hold_id UUID,
    requested_reason TEXT,
    requested_request_id UUID
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE
    actor_allowed BOOLEAN;
    existing_released_at TIMESTAMPTZ;
    existing_request_id UUID;
BEGIN
    IF requested_reason IS NULL
       OR btrim(requested_reason)=''
       OR octet_length(btrim(requested_reason))>16384 THEN
        RETURN 'invalid';
    END IF;

    SELECT account.is_admin AND NOT account.is_disabled
      INTO actor_allowed
      FROM users account
     WHERE account.id=requested_actor_id
     FOR SHARE;
    IF COALESCE(actor_allowed,FALSE)=FALSE THEN
        RETURN 'forbidden';
    END IF;

    SELECT hold.released_at,hold.released_request_id
      INTO existing_released_at,existing_request_id
      FROM legal_holds hold
     WHERE hold.id=requested_hold_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'not_found';
    END IF;
    IF existing_released_at IS NOT NULL THEN
        IF existing_request_id=requested_request_id THEN
            RETURN 'replayed';
        END IF;
        RETURN 'conflict';
    END IF;
    IF EXISTS (
        SELECT 1 FROM governance_export_leases lease
         WHERE lease.export_kind='legal_hold'
           AND lease.hold_id=requested_hold_id
           AND lease.completed_at IS NULL
           AND lease.expires_at>clock_timestamp()
    ) THEN
        RETURN 'conflict';
    END IF;

    UPDATE legal_holds
       SET released_by=requested_actor_id,
           released_request_id=requested_request_id,
           released_at=clock_timestamp(),
           release_reason=btrim(requested_reason)
     WHERE id=requested_hold_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'legal hold disappeared while locked' USING ERRCODE='40001';
    END IF;
    INSERT INTO audit_log(actor_id,action,target,details,request_id)
    VALUES(
        requested_actor_id,
        'data.legal_hold.release',
        requested_hold_id::TEXT,
        pg_catalog.jsonb_build_object('reason',btrim(requested_reason)),
        requested_request_id
    );
    RETURN 'released';
END;
$$;

DO $northstar_database_capabilities$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
    routine_oid pg_catalog.oid;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0107 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;

    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_purge_released_hold_offline_snapshots(int4,int4)',
        'northstar_purge_audit_log(int4,int4)',
        'northstar_purge_governance_export_leases(int4,int4)',
        'northstar_purge_cluster_muc_history(int4,int4)',
        'northstar_release_legal_hold(uuid,uuid,text,uuid)'
    ] LOOP
        routine_oid := pg_catalog.to_regprocedure(
            pg_catalog.format('%I.%s',migration_schema,routine_signature)
        );
        IF routine_oid IS NULL THEN
            RAISE EXCEPTION 'database capability % is absent from migration schema %',
                routine_signature,migration_schema USING ERRCODE='42883';
        END IF;
        IF pg_catalog.pg_get_userbyid(
            (SELECT routine.proowner FROM pg_catalog.pg_proc routine
              WHERE routine.oid=routine_oid)
        ) <> CURRENT_USER THEN
            RAISE EXCEPTION 'database capability % is not owned by migration role',routine_signature
                USING ERRCODE='42501';
        END IF;
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',
            migration_schema,routine_signature
        );
    END LOOP;

    -- CREATE OR REPLACE above must not reintroduce a caller-controlled path on
    -- the invoker guards repaired by 0098/0099.
    FOREACH routine_signature IN ARRAY ARRAY[
        'prevent_legal_hold_link_mutation()',
        'enforce_audit_log_immutability()',
        'enforce_governance_export_lease_history()',
        'reject_cluster_muc_operation_mutation()'
    ] LOOP
        routine_oid := pg_catalog.to_regprocedure(
            pg_catalog.format('%I.%s',migration_schema,routine_signature)
        );
        IF routine_oid IS NULL THEN
            RAISE EXCEPTION 'database guard % is absent from migration schema %',
                routine_signature,migration_schema USING ERRCODE='42883';
        END IF;
        IF (SELECT routine.prosecdef FROM pg_catalog.pg_proc routine
             WHERE routine.oid=routine_oid) THEN
            RAISE EXCEPTION 'database guard % must remain SECURITY INVOKER',routine_signature
                USING ERRCODE='42501';
        END IF;
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema
        );
    END LOOP;
END;
$northstar_database_capabilities$;

COMMENT ON FUNCTION northstar_release_legal_hold(UUID,UUID,TEXT,UUID) IS
    'Owner-held atomic authorization, release and audit capability; runtime receives EXECUTE but no direct legal_holds UPDATE';
