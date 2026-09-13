-- Migration 0136 added the parent-side SM teardown hook which releases an
-- exact MIX delivery lease before ON DELETE cascade removes its source queue
-- row.  The session catalog verifier intentionally rejects every unknown
-- trigger, so teach its immutable manifest about that reviewed eighth hook.
-- Do not alter 0127: already-migrated installations must retain its checksum.

CREATE OR REPLACE FUNCTION northstar_session_capability_catalog_healthy(
    requested_schema TEXT
) RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
WITH namespace AS (
  SELECT oid,nspowner FROM pg_catalog.pg_namespace WHERE nspname=requested_schema
), protected_relations AS (
  SELECT relation.oid,relation.relname,relation.relowner,relation.relacl,
         namespace.nspowner
    FROM namespace JOIN pg_catalog.pg_class relation
      ON relation.relnamespace=namespace.oid
   WHERE relation.relname IN (
     'deployment_session_leases','deployment_session_binding_claims','sm_resume_sessions'
   ) AND relation.relkind IN ('r','p')
), expected_routine(signature,workload) AS (
  VALUES
    ('northstar_session_delete_expired_live_leases()','runtime'),
    ('northstar_session_capacity_reconcile_lock()','runtime'),
    ('northstar_session_reserve_live(uuid,uuid,text,int8,bool)','runtime'),
    ('northstar_session_finalize_binding(uuid,uuid,text)','runtime'),
    ('northstar_session_publish_binding(uuid,uuid,text,int8)','runtime'),
    ('northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)','runtime'),
    ('northstar_session_release_live(uuid)','runtime'),
    ('northstar_session_refresh_live(uuid[],int8)','runtime'),
    ('northstar_session_cleanup_live(int8)','runtime'),
    ('northstar_session_extend_live(uuid,int8)','runtime'),
    ('northstar_sm_create(uuid,bytea,uuid,int8,text,text,text,uuid,int8,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,int8,int8)','runtime'),
    ('northstar_sm_update_snapshot(uuid,uuid,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,bool,int8,int8)','runtime'),
    ('northstar_sm_remove_memberships(uuid,uuid,jsonb)','runtime'),
    ('northstar_sm_exact_owner_state(uuid,uuid,uuid,int8)','runtime'),
    ('northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)','runtime'),
    ('northstar_sm_claim_authority(uuid,uuid)','runtime'),
    ('northstar_sm_activate(uuid,uuid,uuid,int8,inet,uuid,int8,int8)','runtime'),
    ('northstar_sm_release_claim(uuid,uuid)','runtime'),
    ('northstar_sm_revoke(uuid)','runtime'),
    ('northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)','runtime'),
    ('northstar_sm_teardown_pending(text,uuid,uuid,int8,text,uuid)','runtime'),
    ('northstar_sm_count(text,uuid,int8,text)','runtime'),
    ('northstar_sm_finalize_teardown(uuid,uuid)','runtime'),
    ('northstar_sm_lock_suspended(uuid)','runtime'),
    ('northstar_sm_advance_suspended(uuid,int8,int8)','runtime'),
    ('northstar_sm_expire_before_generation(uuid,int8)','runtime'),
    ('northstar_sm_privacy_list_in_use(uuid,text)','runtime'),
    ('northstar_sm_privacy_state(uuid)','runtime'),
    ('northstar_session_capability_catalog_healthy(text)','runtime'),
    ('northstar_sm_state_version()','private'),
    ('northstar_sm_state_notify()','private')
), resolved_routine AS (
  SELECT expected.*,
         pg_catalog.to_regprocedure(
           pg_catalog.format('%I.',requested_schema)||expected.signature
         ) AS oid
    FROM expected_routine expected
), protected_routines AS (
  SELECT expected.signature,expected.workload,expected.oid AS expected_oid,
         routine.oid,routine.proowner,routine.prosecdef,routine.prokind,
         routine.proconfig,routine.proacl,namespace.nspowner
    FROM namespace CROSS JOIN resolved_routine expected
    LEFT JOIN pg_catalog.pg_proc routine
      ON routine.oid=expected.oid AND routine.pronamespace=namespace.oid
), unexpected_session_routine AS (
  SELECT 1 FROM namespace
    JOIN pg_catalog.pg_proc routine ON routine.pronamespace=namespace.oid
   WHERE routine.prosecdef
     AND routine.proname IN (
       SELECT pg_catalog.split_part(expected.signature,'(',1)
         FROM expected_routine expected
     )
     AND routine.oid NOT IN (
       SELECT resolved.oid FROM resolved_routine resolved
        WHERE resolved.oid IS NOT NULL
     )
), expected_trigger(
  table_name,trigger_name,function_signature,expected_tgtype,
  expected_update_columns,security_definer
) AS (
  VALUES
    ('deployment_session_leases','deployment_session_leases_capacity_insert',
     'northstar_session_capacity_insert()',5::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    ('deployment_session_leases','deployment_session_leases_capacity_delete',
     'northstar_session_capacity_delete()',9::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    ('deployment_session_leases','deployment_session_leases_capacity_update',
     'northstar_session_capacity_update()',17::pg_catalog.int2,
     ARRAY['lease_id','connection_id','user_id','full_jid']::pg_catalog.text[],FALSE),
    ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_insert',
     'northstar_sm_capacity_insert()',5::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_delete',
     'northstar_sm_capacity_delete()',9::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    -- This must stay BEFORE DELETE (tgtype 11) so the source queue's exact
    -- rotated lease is released before PostgreSQL cascades it away.
    ('sm_resume_sessions','sm_resume_sessions_release_mix_delivery_owners',
     'northstar_release_sm_session_mix_delivery_owners()',11::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],FALSE),
    ('sm_resume_sessions','sm_resume_sessions_authority_version',
     'northstar_sm_state_version()',19::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],TRUE),
    ('sm_resume_sessions','sm_resume_sessions_authority_notify',
     'northstar_sm_state_notify()',29::pg_catalog.int2,
     ARRAY[]::pg_catalog.text[],TRUE)
), protected_triggers AS (
  SELECT expected.*,trigger.oid,trigger.tgfoid,trigger.tgtype,
         trigger.tgenabled,trigger.tgqual,trigger.tgnargs,trigger.tgargs,
         trigger.tgconstraint,trigger.tgdeferrable,trigger.tginitdeferred,
         trigger.tgparentid,routine.proowner,routine.prokind,
         routine.prosecdef,routine.proconfig,routine.prorettype,
         routine.pronargs,routine.provariadic,
         ARRAY(
           SELECT attribute.attname::pg_catalog.text
             FROM pg_catalog.unnest(trigger.tgattr::pg_catalog.int2[])
                  WITH ORDINALITY selected(attnum,position)
             JOIN pg_catalog.pg_attribute attribute
               ON attribute.attrelid=relation.oid
              AND attribute.attnum=selected.attnum
            ORDER BY selected.position
         ) AS update_columns,
         pg_catalog.to_regprocedure(
           pg_catalog.format('%I.',requested_schema)||expected.function_signature
         ) AS expected_function_oid,namespace.nspowner
    FROM namespace CROSS JOIN expected_trigger expected
    LEFT JOIN pg_catalog.pg_class relation
      ON relation.relnamespace=namespace.oid
     AND relation.relname=expected.table_name AND relation.relkind IN ('r','p')
    LEFT JOIN pg_catalog.pg_trigger trigger
      ON trigger.tgrelid=relation.oid AND trigger.tgname=expected.trigger_name
     AND NOT trigger.tgisinternal
    LEFT JOIN pg_catalog.pg_proc routine ON routine.oid=trigger.tgfoid
), unexpected_trigger AS (
  SELECT 1 FROM namespace
    JOIN pg_catalog.pg_class relation ON relation.relnamespace=namespace.oid
    JOIN pg_catalog.pg_trigger trigger ON trigger.tgrelid=relation.oid
    LEFT JOIN expected_trigger expected
      ON expected.table_name=relation.relname
     AND expected.trigger_name=trigger.tgname
   WHERE relation.relname IN ('deployment_session_leases','sm_resume_sessions')
     AND NOT trigger.tgisinternal AND expected.trigger_name IS NULL
), unexpected_relation_acl AS (
  SELECT 1 FROM protected_relations relation
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
    relation.relacl,pg_catalog.acldefault('r',relation.relowner)
  )) privilege
  WHERE privilege.grantee<>relation.relowner
    AND NOT COALESCE(
      SESSION_USER<>pg_catalog.pg_get_userbyid(relation.nspowner)
      AND privilege.grantor=relation.relowner
      AND privilege.privilege_type='SELECT' AND NOT privilege.is_grantable AND (
        (relation.relname IN (
           'deployment_session_leases','deployment_session_binding_claims'
         ) AND privilege.grantee=(
           SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'
         ))
        OR (relation.relname IN (
           'deployment_session_leases','deployment_session_binding_claims',
           'sm_resume_sessions'
         ) AND privilege.grantee=(
           SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_backup'
         ))
      ),FALSE
    )
), unexpected_column_acl AS (
  SELECT 1 FROM protected_relations relation
  JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=relation.oid
    AND attribute.attnum>0 AND NOT attribute.attisdropped
  CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
  WHERE privilege.grantee<>relation.relowner
    AND NOT COALESCE(
      SESSION_USER<>pg_catalog.pg_get_userbyid(relation.nspowner)
      AND relation.relname='sm_resume_sessions'
      AND privilege.grantor=relation.relowner
      AND privilege.grantee=(
        SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'
      ) AND privilege.privilege_type='SELECT' AND NOT privilege.is_grantable
      AND attribute.attname IN (
        'id','user_id','auth_generation','full_jid','resource','connection_id',
        'resume_timeout_seconds','inbound_h','outbound_h','acked_h','available',
        'carbons','priority','blocklist_requested','roster_requested',
        'active_privacy_list','privacy_requested','user_agent_id','joined_rooms',
        'directed_presence','last_presence','resumable','live_lease_until',
        'expires_at','claimed_until','created_at','updated_at'
      ),FALSE
    )
), routine_acl_drift AS (
  SELECT 1 FROM protected_routines routine
   WHERE routine.oid IS NULL OR routine.expected_oid IS NULL
      OR routine.proowner<>routine.nspowner OR NOT routine.prosecdef
      OR routine.prokind<>'f'
      OR routine.proconfig IS DISTINCT FROM ARRAY[
           pg_catalog.format('search_path=pg_catalog, %I, pg_temp',requested_schema)
         ]::pg_catalog.text[]
      OR (SELECT pg_catalog.count(*)
            FROM pg_catalog.aclexplode(COALESCE(
              routine.proacl,pg_catalog.acldefault('f',routine.proowner)
            )) privilege)<>CASE
              WHEN routine.workload='private'
                OR SESSION_USER=pg_catalog.pg_get_userbyid(routine.nspowner)
                THEN 1 ELSE 2 END
      OR EXISTS(
           SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
             routine.proacl,pg_catalog.acldefault('f',routine.proowner)
           )) privilege
            WHERE privilege.privilege_type<>'EXECUTE' OR privilege.is_grantable
               OR privilege.grantor<>routine.proowner
               OR (privilege.grantee<>routine.proowner AND (
                    routine.workload='private'
                    OR SESSION_USER=pg_catalog.pg_get_userbyid(routine.nspowner)
                    OR privilege.grantee IS DISTINCT FROM (
                         SELECT role.oid FROM pg_catalog.pg_roles role
                          WHERE role.rolname='northstar_runtime'
                    )))
      )
      OR NOT EXISTS(
           SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
             routine.proacl,pg_catalog.acldefault('f',routine.proowner)
           )) privilege
            WHERE privilege.grantee=routine.proowner
              AND privilege.grantor=routine.proowner
              AND privilege.privilege_type='EXECUTE'
              AND NOT privilege.is_grantable
      )
      OR (routine.workload='runtime'
          AND SESSION_USER<>pg_catalog.pg_get_userbyid(routine.nspowner)
          AND NOT EXISTS(
            SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
              routine.proacl,pg_catalog.acldefault('f',routine.proowner)
            )) privilege
             WHERE privilege.grantee=(
                     SELECT role.oid FROM pg_catalog.pg_roles role
                      WHERE role.rolname='northstar_runtime'
                   )
               AND privilege.grantor=routine.proowner
               AND privilege.privilege_type='EXECUTE'
               AND NOT privilege.is_grantable
          ))
), runtime_dml_acl AS (
  SELECT 1 FROM protected_relations relation
   WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(relation.relowner)
     AND (pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'INSERT')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'UPDATE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'DELETE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRUNCATE')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'REFERENCES')
       OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRIGGER')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'INSERT')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'UPDATE')
       OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'REFERENCES'))
), sensitive_sm_acl AS (
  SELECT 1 FROM namespace
   WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(namespace.nspowner)
     AND (pg_catalog.has_column_privilege(
            SESSION_USER,pg_catalog.format('%I.sm_resume_sessions',requested_schema),
            'token_hash','SELECT')
       OR pg_catalog.has_column_privilege(
            SESSION_USER,pg_catalog.format('%I.sm_resume_sessions',requested_schema),
            'claim_token','SELECT')
       OR pg_catalog.has_column_privilege(
            SESSION_USER,pg_catalog.format('%I.sm_resume_sessions',requested_schema),
            'peer_ip','SELECT')
       OR pg_catalog.has_column_privilege(
            SESSION_USER,pg_catalog.format('%I.sm_resume_sessions',requested_schema),
            'state_version','SELECT'))
)
SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
  AND (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(relowner=nspowner)
         FROM protected_relations)
  AND NOT EXISTS(SELECT 1 FROM unexpected_relation_acl)
  AND NOT EXISTS(SELECT 1 FROM unexpected_column_acl)
  AND NOT EXISTS(SELECT 1 FROM routine_acl_drift)
  AND NOT EXISTS(SELECT 1 FROM unexpected_session_routine)
  AND NOT EXISTS(SELECT 1 FROM runtime_dml_acl)
  AND NOT EXISTS(SELECT 1 FROM sensitive_sm_acl)
  AND NOT EXISTS(SELECT 1 FROM unexpected_trigger)
  AND (SELECT pg_catalog.count(*)=8 AND pg_catalog.bool_and(
         oid IS NOT NULL AND expected_function_oid IS NOT NULL
          AND tgfoid=expected_function_oid AND tgtype=expected_tgtype
          AND update_columns=expected_update_columns
          AND tgenabled='O' AND tgqual IS NULL
          AND tgnargs=0 AND pg_catalog.octet_length(tgargs)=0
          AND tgconstraint=0 AND NOT tgdeferrable AND NOT tginitdeferred
          AND tgparentid=0 AND proowner=nspowner AND prokind='f'
          AND prosecdef=security_definer
          AND proconfig IS NOT DISTINCT FROM ARRAY[
            pg_catalog.format('search_path=pg_catalog, %I, pg_temp',requested_schema)
          ]::pg_catalog.text[]
          AND prorettype='pg_catalog.trigger'::pg_catalog.regtype
          AND pronargs=0 AND provariadic=0
       ) FROM protected_triggers)
  AND (SELECT pg_catalog.count(*)=(SELECT pg_catalog.count(*) FROM expected_routine)
         AND pg_catalog.bool_and(oid IS NOT NULL) FROM protected_routines)
$$;

DO $northstar_sm_mix_teardown_catalog_hardening$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_oid pg_catalog.oid;
    expected_path pg_catalog.text;
BEGIN
    IF migration_schema IS NULL
       OR migration_schema IN ('pg_catalog','information_schema')
       OR migration_schema LIKE 'pg_temp_%'
       OR migration_schema LIKE 'pg_toast_temp_%' THEN
        RAISE EXCEPTION 'migration 0138 requires a dedicated application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;

    routine_oid := pg_catalog.to_regprocedure(pg_catalog.format(
        '%I.northstar_session_capability_catalog_healthy(text)',migration_schema
    ));
    IF routine_oid IS NULL THEN
        RAISE EXCEPTION 'session capability catalog verifier is absent from schema %',migration_schema
            USING ERRCODE='42883';
    END IF;
    expected_path := pg_catalog.format(
        'search_path=pg_catalog, %I, pg_temp',migration_schema
    );
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.northstar_session_capability_catalog_healthy(text) '
        || 'SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,migration_schema
    );
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.northstar_session_capability_catalog_healthy(text) FROM PUBLIC',
        migration_schema
    );
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc routine
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
         WHERE routine.oid=routine_oid
           AND routine.proowner=namespace.nspowner
           AND routine.prosecdef AND routine.prokind='f'
           AND routine.proconfig=ARRAY[expected_path]::pg_catalog.text[]
           AND NOT EXISTS (
             SELECT 1
               FROM pg_catalog.aclexplode(COALESCE(
                 routine.proacl,pg_catalog.acldefault('f',routine.proowner)
               )) privilege
              WHERE privilege.grantee=0
                AND privilege.privilege_type='EXECUTE'
           )
    ) THEN
        RAISE EXCEPTION 'session capability catalog verifier has unsafe owner, security mode, path, or PUBLIC ACL'
            USING ERRCODE='55000';
    END IF;
END;
$northstar_sm_mix_teardown_catalog_hardening$;

COMMENT ON FUNCTION northstar_session_capability_catalog_healthy(TEXT) IS
  'Exact session authority catalog verifier, including the SM-to-MIX lease-release BEFORE DELETE trigger';
