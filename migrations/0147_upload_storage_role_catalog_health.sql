-- The upload catalog audit follows the storage/runtime capability split.
-- The function is created without resolving either role, so migrations can
-- precede role creation on an existing volume.
CREATE OR REPLACE FUNCTION northstar_upload_capability_catalog_healthy(
  requested_schema pg_catalog.text
) RETURNS pg_catalog.bool
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $northstar_upload_capability_catalog_healthy$
WITH namespace AS (
  SELECT oid,nspowner FROM pg_catalog.pg_namespace
   WHERE nspname=requested_schema
), upload_relations AS (
  SELECT relation.oid,relation.relowner,relation.relacl,namespace.nspowner
    FROM namespace
    JOIN pg_catalog.pg_class relation ON relation.relnamespace=namespace.oid
   WHERE relation.relname IN (
     'upload_storage_authority','upload_storage_capacity_ledger','upload_slots',
     'upload_storage_jobs','upload_cleanup_queue'
   ) AND relation.relkind IN ('r','p')
), upload_routines AS (
  SELECT routine.oid,routine.proname,routine.proowner,routine.prosecdef,routine.proconfig,
         routine.proacl,namespace.nspowner
    FROM namespace
    JOIN pg_catalog.pg_proc routine ON routine.pronamespace=namespace.oid
   WHERE routine.proname LIKE 'northstar_upload_%'
), public_relation_acl AS (
  SELECT 1 FROM upload_relations relation
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
    relation.relacl,pg_catalog.acldefault('r',relation.relowner)
  )) privilege WHERE privilege.grantee=0
), public_routine_acl AS (
  SELECT 1 FROM upload_routines routine
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
    routine.proacl,pg_catalog.acldefault('f',routine.proowner)
  )) privilege
  WHERE privilege.grantee=0 AND privilege.privilege_type='EXECUTE'
), workload_relation_acl AS (
  SELECT 1 FROM upload_relations relation
   WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(relation.relowner)
     AND (
       pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'SELECT')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'INSERT')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'UPDATE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'DELETE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRUNCATE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'REFERENCES')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRIGGER')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'SELECT')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'INSERT')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'UPDATE')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'REFERENCES')
     )
), workload_routine_acl_mismatch AS (
  SELECT 1 FROM upload_routines routine
   WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(routine.proowner)
     AND pg_catalog.has_function_privilege(
           SESSION_USER,routine.oid,'EXECUTE'
         ) IS DISTINCT FROM CASE
           WHEN SESSION_USER='northstar_storage' THEN
             routine.proname NOT IN (
               'northstar_upload_offline_bootstrap_authority',
               'northstar_upload_require_capacity_lock',
               'northstar_upload_dead_letters_page',
               'northstar_upload_retry_dead_letter',
               'northstar_upload_durable_state_exists',
               'northstar_upload_capacity_lock',
               'northstar_upload_public_slot_count'
             )
           WHEN SESSION_USER='northstar_runtime' THEN
             routine.proname IN (
               'northstar_upload_dead_letters_page',
               'northstar_upload_retry_dead_letter',
               'northstar_upload_durable_state_exists',
               'northstar_upload_capacity_lock',
               'northstar_upload_public_slot_count'
             )
           ELSE FALSE
         END
)
SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
  AND (SELECT pg_catalog.count(*)=5 AND pg_catalog.bool_and(
         relowner=nspowner
       ) FROM upload_relations)
  AND NOT EXISTS(SELECT 1 FROM public_relation_acl)
  AND NOT EXISTS(SELECT 1 FROM workload_relation_acl)
  AND (SELECT pg_catalog.count(*)=44 AND pg_catalog.bool_and(
         proowner=nspowner AND prosecdef
         AND proconfig=ARRAY[
           pg_catalog.format('search_path=pg_catalog, %I, pg_temp',requested_schema)
         ]::pg_catalog.text[]
       ) FROM upload_routines)
  AND NOT EXISTS(SELECT 1 FROM public_routine_acl)
  AND NOT EXISTS(SELECT 1 FROM workload_routine_acl_mismatch)
$northstar_upload_capability_catalog_healthy$;

DO $harden_upload_storage_role_catalog_health$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_upload_capability_catalog_healthy(text)'
    ] LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %I.%s RESET ALL',migration_schema,routine_signature);
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',
            migration_schema,routine_signature
        );
    END LOOP;
END;
$harden_upload_storage_role_catalog_health$;
