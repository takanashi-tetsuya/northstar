-- XEP-0198 owns a rotated MIX lease while its resume queue contains the
-- source.  Session teardown is executed by an owner-held capability and
-- cascades the child queue rows, so the release must happen before that
-- cascade removes the exact source identities.  A parent BEFORE DELETE
-- trigger keeps the session -> queue -> recipient lock order intact and does
-- not interfere with ordinary checkpoint replacement or client ACK deletion.

CREATE FUNCTION northstar_release_sm_session_mix_delivery_owners()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path FROM CURRENT
AS $$
BEGIN
    UPDATE mix_delivery_recipients AS recipient
       SET lease_token=NULL,
           lease_until=NULL,
           next_attempt_at=clock_timestamp(),
           last_error='stream-management session ended before MIX acknowledgement'
      FROM sm_resume_stanzas AS stanza
     WHERE stanza.session_id=OLD.id
       AND stanza.mix_delivery_id IS NOT NULL
       AND stanza.mix_delivery_lease_token IS NOT NULL
       AND recipient.delivery_id=stanza.mix_delivery_id
       AND recipient.lease_token=stanza.mix_delivery_lease_token;
    RETURN OLD;
END;
$$;

CREATE TRIGGER sm_resume_sessions_release_mix_delivery_owners
BEFORE DELETE ON sm_resume_sessions
FOR EACH ROW EXECUTE FUNCTION northstar_release_sm_session_mix_delivery_owners();

-- Migrations may execute in an isolated application schema. Pin the invoker
-- trigger helper there, reject an unsafe schema, and leave execution governed
-- by its table trigger rather than an ambient PUBLIC function grant.
DO $northstar_sm_mix_teardown_release_hardening$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_oid pg_catalog.oid;
    expected_path pg_catalog.text;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0136 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;

    routine_oid := pg_catalog.to_regprocedure(
        pg_catalog.format(
            '%I.northstar_release_sm_session_mix_delivery_owners()',
            migration_schema
        )
    );
    IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'MIX SM teardown trigger helper is absent from schema %', migration_schema
            USING ERRCODE='42883';
    END IF;

    expected_path := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp',
        migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.northstar_release_sm_session_mix_delivery_owners() '
        || 'SECURITY INVOKER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,
        migration_schema
    );
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.northstar_release_sm_session_mix_delivery_owners() FROM PUBLIC',
        migration_schema
    );

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS routine
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid=routine.pronamespace
         WHERE routine.oid=routine_oid
           AND routine.proowner=namespace.nspowner
           AND routine.prokind='f'
           AND NOT routine.prosecdef
           AND routine.proconfig=ARRAY[expected_path]::pg_catalog.text[]
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_catalog.aclexplode(COALESCE(
                     routine.proacl,
                     pg_catalog.acldefault('f',routine.proowner)
                 )) AS privilege
                WHERE privilege.grantee=0
                  AND privilege.privilege_type='EXECUTE'
           )
    ) THEN
        RAISE EXCEPTION 'MIX SM teardown trigger helper has unexpected owner, security mode, path, or PUBLIC ACL'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_sm_mix_teardown_release_hardening$;

COMMENT ON FUNCTION northstar_release_sm_session_mix_delivery_owners() IS
  'SECURITY INVOKER parent teardown trigger: releases only exact rotated MIX leases before XEP-0198 queue cascade';
COMMENT ON TRIGGER sm_resume_sessions_release_mix_delivery_owners ON sm_resume_sessions IS
  'Releases unacknowledged MIX source leases before deleting their parent SM session';
