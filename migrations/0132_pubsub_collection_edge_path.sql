-- Pin the collection-edge trigger helper to the schema in which it was
-- installed.  Migration 0129 corrected the graph semantics but was added
-- after the catalog-wide routine hardening pass, so its invoker trigger
-- function retained a caller-selected search_path.  Do not rewrite 0129:
-- existing installations need a forward-only repair as well.
--
-- The function remains SECURITY INVOKER.  It is a trigger guard, not a
-- privileged capability, and changing it to SECURITY DEFINER would widen the
-- database authority of every collection-edge mutation.

DO $northstar_pubsub_collection_edge_path$
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
            'migration 0132 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;

    routine_oid := pg_catalog.to_regprocedure(
        pg_catalog.format('%I.check_pubsub_collection_edge()', migration_schema)
    );
    IF routine_oid IS NULL THEN
        RAISE EXCEPTION
            'PubSub collection-edge trigger helper is absent from schema %',
            migration_schema USING ERRCODE='42883';
    END IF;

    expected_path := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp', migration_schema
    );
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS routine
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid=routine.pronamespace
         WHERE routine.oid=routine_oid
           AND routine.prokind='f'
           AND routine.proowner=namespace.nspowner
    ) THEN
        RAISE EXCEPTION
            'PubSub collection-edge trigger helper has an unexpected owner or namespace'
            USING ERRCODE='42501';
    END IF;

    -- Keep this helper invoker-scoped, then make its unqualified graph-table
    -- references deterministic in both public and isolated-schema installs.
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.check_pubsub_collection_edge() SECURITY INVOKER',
        migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.check_pubsub_collection_edge() '
        || 'SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema
    );

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS routine
         WHERE routine.oid=routine_oid
           AND NOT routine.prosecdef
           AND routine.proconfig=ARRAY[expected_path]::pg_catalog.text[]
    ) THEN
        RAISE EXCEPTION
            'PubSub collection-edge trigger helper was not pinned as an invoker routine'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_pubsub_collection_edge_path$;
