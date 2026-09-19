-- Transaction-ordered, schema-local wake hints for durable MIX delivery.
--
-- The recipient table remains the sole authority.  This trigger emits only
-- the physical schema name after an INSERT or DELETE statement commits, so a
-- process must still run the normal fenced claim before it can deliver a
-- stanza.  DELETE matters as much as INSERT: acknowledging or dead-lettering
-- one recipient can make the next ordered recipient projection eligible.

CREATE FUNCTION northstar_mix_delivery_notify()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path FROM CURRENT
AS $$
BEGIN
    PERFORM pg_catalog.pg_notify(
        'northstar_mix_delivery_v1',
        TG_TABLE_SCHEMA
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER mix_delivery_recipients_wake
AFTER INSERT OR DELETE ON mix_delivery_recipients
FOR EACH STATEMENT EXECUTE FUNCTION northstar_mix_delivery_notify();

-- Migrations may run in a dedicated isolated schema.  Pin this invoker
-- trigger helper to that exact schema rather than assuming `public`, then
-- remove its direct PUBLIC execution surface.  Trigger execution remains
-- governed by the table mutation authority; the function has no elevated
-- privileges and only emits a bounded, non-secret wake hint.
DO $northstar_mix_delivery_wake_hardening$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_oid pg_catalog.oid;
    expected_path pg_catalog.text;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION
            'migration 0133 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;

    routine_oid := pg_catalog.to_regprocedure(
        pg_catalog.format('%I.northstar_mix_delivery_notify()', migration_schema)
    );
    IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'MIX delivery wake trigger helper is absent from schema %', migration_schema
            USING ERRCODE='42883';
    END IF;

    expected_path := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp', migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.northstar_mix_delivery_notify() '
        || 'SECURITY INVOKER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,
        migration_schema
    );
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.northstar_mix_delivery_notify() FROM PUBLIC',
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
        RAISE EXCEPTION
            'MIX delivery wake helper has unexpected owner, security mode, path, or PUBLIC ACL'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_mix_delivery_wake_hardening$;

COMMENT ON FUNCTION northstar_mix_delivery_notify() IS
  'SECURITY INVOKER statement trigger: emits a commit-ordered schema-only MIX delivery wake';
COMMENT ON TRIGGER mix_delivery_recipients_wake ON mix_delivery_recipients IS
  'Wake accelerator only; workers re-claim exact ordered recipients from PostgreSQL';
