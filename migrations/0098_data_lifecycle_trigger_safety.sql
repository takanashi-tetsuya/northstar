-- Make the migration-0087 legal-hold and retention routines independent of
-- the caller's search_path.  Also repair a BEFORE UPDATE semantic bug in the
-- shared legal-hold guard: returning OLD silently discarded every permitted
-- update (including offline delivery claim/fencing metadata) even though the
-- UPDATE ... RETURNING result looked successful to the caller.

CREATE OR REPLACE FUNCTION protect_held_data_record() RETURNS TRIGGER AS $$
DECLARE
    protected pg_catalog.bool;
BEGIN
    protected := FALSE;
    IF TG_TABLE_NAME='message_archive' THEN
        SELECT EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                 EXISTS (SELECT 1 FROM legal_hold_personal_archives link
                          WHERE link.hold_id=hold.id AND link.archive_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                            WHERE scope_link.hold_id=hold.id
                              AND scope_link.scope_type='personal_archive_owner'
                              AND scope_link.subject_id=OLD.owner_id)
             )
        ) INTO protected;
    ELSIF TG_TABLE_NAME='muc_messages' THEN
        SELECT EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                 EXISTS (SELECT 1 FROM legal_hold_muc_archives link
                          WHERE link.hold_id=hold.id AND link.message_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                            WHERE scope_link.hold_id=hold.id
                              AND scope_link.scope_type='muc_archive_room'
                              AND scope_link.subject_id=OLD.room_id)
             )
        ) INTO protected;
    ELSIF TG_TABLE_NAME='offline_messages' THEN
        -- Claim/lease fields remain mutable while payload and identity fields
        -- covered by an active hold remain immutable.
        IF TG_OP='UPDATE' AND (
            OLD.recipient_id IS DISTINCT FROM NEW.recipient_id
            OR OLD.sender_jid IS DISTINCT FROM NEW.sender_jid
            OR OLD.stanza IS DISTINCT FROM NEW.stanza
            OR OLD.encrypted IS DISTINCT FROM NEW.encrypted
            OR OLD.created_at IS DISTINCT FROM NEW.created_at
        ) THEN
            SELECT EXISTS (
                SELECT 1 FROM legal_holds hold
                 WHERE hold.released_at IS NULL AND (
                     EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                              WHERE link.hold_id=hold.id AND link.message_id=OLD.id)
                     OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                WHERE scope_link.hold_id=hold.id
                                  AND scope_link.scope_type='offline_message_recipient'
                                  AND scope_link.subject_id=OLD.recipient_id)
                 )
            ) INTO protected;
        END IF;
    ELSIF TG_TABLE_NAME='abuse_report_evidence' THEN
        SELECT EXISTS (
            SELECT 1 FROM legal_holds hold
             WHERE hold.released_at IS NULL AND (
                 EXISTS (SELECT 1 FROM legal_hold_report_evidence link
                          WHERE link.hold_id=hold.id AND link.evidence_id=OLD.id)
                 OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                            WHERE scope_link.hold_id=hold.id
                              AND scope_link.scope_type='report_evidence_report'
                              AND scope_link.subject_id=OLD.report_id)
             )
        ) INTO protected;
    END IF;
    IF protected THEN
        RAISE EXCEPTION 'data record is protected by an active legal hold'
            USING ERRCODE='55000';
    END IF;

    -- PostgreSQL replaces NEW with the row returned by a BEFORE UPDATE
    -- trigger. DELETE has no NEW row and must continue returning OLD.
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Bind every migration-0087 routine that executes in an application session,
-- plus the two migration-0079 offline-admission trigger routines that share
-- the same delete path, to the exact installation schema. These remain
-- SECURITY INVOKER routines; no owner, ACL, or privilege is changed. The
-- ALTERs run in the same transactional migration as the replacement above, so
-- no caller-visible unpinned version exists.
DO $northstar_data_lifecycle_routine_paths$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
    routine_oid pg_catalog.oid;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0098 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;

    FOREACH routine_signature IN ARRAY ARRAY[
        'release_offline_message_admission_capacity()',
        'detach_delivered_offline_message_admission()',
        'preserve_held_offline_message()',
        'protect_held_data_record()',
        'protect_legal_hold_subject_delete()',
        'enforce_legal_hold_history()',
        'prevent_legal_hold_link_mutation()',
        'enforce_audit_log_immutability()',
        'northstar_purge_released_hold_offline_snapshots(int4,int4)',
        'northstar_purge_audit_log(int4,int4)'
    ] LOOP
        routine_oid := pg_catalog.to_regprocedure(
            pg_catalog.format('%I.%s',migration_schema,routine_signature)
        );
        IF routine_oid IS NULL THEN
            RAISE EXCEPTION 'data lifecycle routine % is absent from migration schema %',
                routine_signature,migration_schema
                USING ERRCODE='42883';
        END IF;
        IF (SELECT routine.prosecdef FROM pg_catalog.pg_proc routine
             WHERE routine.oid=routine_oid) THEN
            RAISE EXCEPTION 'data lifecycle routine % unexpectedly expands privileges',
                routine_signature
                USING ERRCODE='42501';
        END IF;
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema
        );
    END LOOP;
END;
$northstar_data_lifecycle_routine_paths$;
