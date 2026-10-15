//! Attest the shared PostgreSQL role, ownership, membership, and object ACL catalog boundary.

use super::*;

/// Attest the shared PostgreSQL catalog boundary, not merely the privileges of
/// the connection that happened to start this pool.  This catches a powerful
/// auxiliary role, alien direct ACL, delegated grant chain, ownership drift or
/// read/write backup crossover even when the current runtime/command login is
/// itself perfectly restricted.
pub(super) async fn attest_database_capability_catalog(pool: &PgPool) -> Result<()> {
    let accepted: bool = sqlx::query_scalar(
        r#"WITH expected_role(role_name,connection_limit) AS (
             VALUES
               ('northstar_migrator'::pg_catalog.text,4),
               ('northstar_runtime'::pg_catalog.text,64),
               ('northstar_commands'::pg_catalog.text,8),
               ('northstar_storage'::pg_catalog.text,16),
               ('northstar_backup'::pg_catalog.text,2)
           ), workload_role AS (
             SELECT expected.*,role.oid,role.rolcanlogin,role.rolsuper,
                    role.rolinherit,role.rolcreatedb,role.rolcreaterole,
                    role.rolreplication,role.rolbypassrls,role.rolconnlimit,
                    role.rolvaliduntil,role.rolconfig
               FROM expected_role expected
               LEFT JOIN pg_catalog.pg_roles role ON role.rolname=expected.role_name
           ), migrator AS (
             SELECT oid FROM workload_role WHERE role_name='northstar_migrator'
           ), runtime AS (
             SELECT oid FROM workload_role WHERE role_name='northstar_runtime'
           ), command_role AS (
             SELECT oid FROM workload_role WHERE role_name='northstar_commands'
           ), storage AS (
             SELECT oid FROM workload_role WHERE role_name='northstar_storage'
           ), backup AS (
             SELECT oid FROM workload_role WHERE role_name='northstar_backup'
           ), namespace AS (
             SELECT oid,nspowner,nspacl FROM pg_catalog.pg_namespace
              WHERE nspname='public'
           ), application_database AS (
             SELECT oid,datdba,datacl FROM pg_catalog.pg_database
              WHERE datname=pg_catalog.current_database()
           ), application_relation AS (
             SELECT relation.oid,relation.relname,relation.relkind,
                    relation.relowner,relation.relacl
               FROM namespace
               JOIN pg_catalog.pg_class relation
                 ON relation.relnamespace=namespace.oid
              WHERE relation.relkind IN ('r','p','v','m','S','f','i','I')
                AND NOT EXISTS (
                  SELECT 1 FROM pg_catalog.pg_depend dependency
                   WHERE dependency.classid='pg_catalog.pg_class'::pg_catalog.regclass
                     AND dependency.objid=relation.oid
                     AND dependency.deptype='e'
                )
           ), application_routine AS (
             SELECT routine.oid,routine.proowner,routine.proacl,
                    routine.prosecdef,routine.prorettype
               FROM namespace
               JOIN pg_catalog.pg_proc routine ON routine.pronamespace=namespace.oid
              WHERE NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_depend dependency
                 WHERE dependency.classid='pg_catalog.pg_proc'::pg_catalog.regclass
                   AND dependency.objid=routine.oid
                   AND dependency.deptype='e'
              )
           ), application_type AS (
             SELECT data_type.oid,data_type.typowner,data_type.typacl
               FROM namespace
               JOIN pg_catalog.pg_type data_type ON data_type.typnamespace=namespace.oid
              WHERE data_type.typelem=0
                AND (
                  (data_type.typrelid=0
                   AND data_type.typtype IN ('b','d','e','r','m'))
                  OR (data_type.typtype='c' AND EXISTS (
                    SELECT 1 FROM pg_catalog.pg_class composite_relation
                     WHERE composite_relation.oid=data_type.typrelid
                       AND composite_relation.relkind='c'
                  ))
                )
                AND NOT EXISTS (
                  SELECT 1 FROM pg_catalog.pg_depend dependency
                   WHERE dependency.classid='pg_catalog.pg_type'::pg_catalog.regclass
                     AND dependency.objid=data_type.oid
                     AND (dependency.deptype='e'
                       OR (dependency.deptype='i' AND data_type.typtype<>'c'))
                )
           ), expected_sm_column(attname) AS (
             SELECT pg_catalog.unnest(ARRAY[
               'id','user_id','auth_generation','full_jid','resource','connection_id',
               'resume_timeout_seconds','inbound_h','outbound_h','acked_h','available','carbons',
               'priority','blocklist_requested','roster_requested','active_privacy_list',
               'privacy_requested','user_agent_id','joined_rooms','directed_presence',
               'last_presence','resumable','live_lease_until','expires_at','claimed_until',
               'created_at','updated_at'
             ]::pg_catalog.text[])
           ), unexpected_default AS (
             SELECT 1
               FROM pg_catalog.pg_default_acl default_acl
               JOIN pg_catalog.pg_roles owner ON owner.oid=default_acl.defaclrole
               LEFT JOIN namespace ON namespace.oid=default_acl.defaclnamespace
              WHERE namespace.oid IS NOT NULL
                 OR (default_acl.defaclnamespace=0 AND (
                   owner.rolname<>'northstar_migrator'
                   OR default_acl.defaclobjtype NOT IN ('r','S','f','T','n')
                   OR EXISTS (
                     SELECT 1
                       FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
                      WHERE privilege.grantee<>default_acl.defaclrole
                         OR privilege.grantor<>default_acl.defaclrole
                         OR privilege.is_grantable
                         OR NOT EXISTS (
                           SELECT 1
                             FROM pg_catalog.aclexplode(pg_catalog.acldefault(
                               default_acl.defaclobjtype,default_acl.defaclrole
                             )) built_in
                            WHERE built_in.grantee=default_acl.defaclrole
                              AND built_in.grantor=default_acl.defaclrole
                              AND built_in.privilege_type=privilege.privilege_type
                              AND NOT built_in.is_grantable
                         )
                   )
                   OR EXISTS (
                     SELECT 1
                       FROM pg_catalog.aclexplode(pg_catalog.acldefault(
                         default_acl.defaclobjtype,default_acl.defaclrole
                       )) built_in
                      WHERE built_in.grantee=default_acl.defaclrole
                        AND built_in.grantor=default_acl.defaclrole
                        AND NOT built_in.is_grantable
                        AND NOT EXISTS (
                          SELECT 1
                            FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
                           WHERE privilege.grantee=default_acl.defaclrole
                             AND privilege.grantor=default_acl.defaclrole
                             AND privilege.privilege_type=built_in.privilege_type
                             AND NOT privilege.is_grantable
                        )
                   )
                 ))
             UNION ALL
             SELECT 1
               FROM (VALUES ('f'::"char"),('T'::"char")) required(object_type)
              WHERE NOT EXISTS (
                SELECT 1
                  FROM pg_catalog.pg_default_acl default_acl
                 WHERE default_acl.defaclrole=(
                         SELECT oid FROM workload_role
                          WHERE role_name='northstar_migrator'
                       )
                   AND default_acl.defaclnamespace=0
                   AND default_acl.defaclobjtype=required.object_type
                   AND NOT EXISTS (
                     SELECT 1
                       FROM pg_catalog.aclexplode(default_acl.defaclacl) privilege
                      WHERE privilege.grantee<>default_acl.defaclrole
                         OR privilege.grantor<>default_acl.defaclrole
                         OR privilege.is_grantable
                   )
              )
           )
           SELECT (SELECT pg_catalog.count(*)=5 AND pg_catalog.bool_and(
                    oid IS NOT NULL AND rolcanlogin AND NOT rolsuper
                    AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole
                    AND NOT rolreplication AND NOT rolbypassrls
                    AND rolconnlimit=connection_limit
                    AND rolvaliduntil IS NOT DISTINCT FROM
                        'infinity'::pg_catalog.timestamptz
                    AND rolconfig IS NULL
                  ) FROM workload_role)
             AND (SELECT pg_catalog.count(*)=1 FROM namespace)
             AND (SELECT datdba=(SELECT oid FROM migrator) FROM application_database)
             AND (SELECT nspowner=(SELECT oid FROM migrator) FROM namespace)
             AND NOT EXISTS (
               SELECT 1 FROM pg_catalog.pg_auth_members membership
                WHERE membership.member IN (SELECT oid FROM workload_role)
                   OR membership.roleid IN (SELECT oid FROM workload_role)
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_database database
               CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
                 database.datacl,pg_catalog.acldefault('d',database.datdba)
               )) privilege
                WHERE privilege.grantee<>database.datdba
                  AND NOT COALESCE(
                    privilege.grantor=database.datdba
                    AND NOT privilege.is_grantable
                    AND privilege.privilege_type='CONNECT'
                    AND privilege.grantee IN (
                      (SELECT oid FROM runtime),(SELECT oid FROM command_role),
                      (SELECT oid FROM storage),(SELECT oid FROM backup)
                    ),FALSE)
             )
             AND NOT EXISTS (
               SELECT 1 FROM namespace
               CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
                 namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner)
               )) privilege
                WHERE privilege.grantee<>namespace.nspowner
                  AND NOT COALESCE(
                    privilege.grantor=namespace.nspowner
                    AND NOT privilege.is_grantable
                    AND privilege.privilege_type='USAGE'
                    AND privilege.grantee IN (
                      (SELECT oid FROM runtime),(SELECT oid FROM command_role),
                      (SELECT oid FROM storage),(SELECT oid FROM backup)
                    ),FALSE)
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_relation
                WHERE relowner<>(SELECT oid FROM migrator)
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_routine
                WHERE proowner<>(SELECT oid FROM migrator)
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_routine routine
               CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
                 routine.proacl,pg_catalog.acldefault('f',routine.proowner)
               )) privilege
                WHERE privilege.grantee<>routine.proowner
                  AND NOT COALESCE(
                    privilege.grantor=routine.proowner
                    AND NOT privilege.is_grantable
                    AND privilege.privilege_type='EXECUTE'
                    AND privilege.grantee IN (
                      (SELECT oid FROM runtime),(SELECT oid FROM command_role),
                      (SELECT oid FROM storage)
                    ),FALSE
                  )
             )
             -- Installed SECURITY INVOKER triggers execute through approved
             -- table DML; runtime must not retain an independently callable
             -- EXECUTE capability for any trigger-returning helper. Keep the
             -- reviewed SECURITY DEFINER manifest and command-role policy in
             -- their dedicated attestations below unchanged.
             AND NOT EXISTS (
               SELECT 1 FROM application_routine routine
                WHERE NOT routine.prosecdef
                  AND routine.prorettype='pg_catalog.trigger'::pg_catalog.regtype
                  AND pg_catalog.has_function_privilege(
                        (SELECT oid FROM runtime),routine.oid,'EXECUTE'
                      )
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_routine routine
                WHERE NOT routine.prosecdef
                  AND routine.prorettype='pg_catalog.trigger'::pg_catalog.regtype
                  AND pg_catalog.has_function_privilege(
                        (SELECT oid FROM storage),routine.oid,'EXECUTE'
                      )
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_type
                WHERE typowner<>(SELECT oid FROM migrator)
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_relation relation
               CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) privilege
                WHERE privilege.grantee<>relation.relowner
                  AND NOT COALESCE(
                    privilege.grantor=relation.relowner
                    AND NOT privilege.is_grantable
                    AND (
                      (relation.relkind IN ('r','p','v','m','f')
                       AND privilege.grantee=(SELECT oid FROM runtime)
                       AND privilege.privilege_type IN ('SELECT','INSERT','UPDATE','DELETE'))
                      OR
                      (relation.relkind IN ('r','p','v','m','f')
                       AND privilege.grantee=(SELECT oid FROM backup)
                       AND privilege.privilege_type='SELECT')
                      OR
                      (relation.relkind='S'
                       AND privilege.grantee=(SELECT oid FROM runtime)
                       AND privilege.privilege_type IN ('USAGE','SELECT'))
                      OR
                      (relation.relkind='S'
                       AND privilege.grantee=(SELECT oid FROM backup)
                       AND privilege.privilege_type='SELECT')
                    ),FALSE)
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_relation relation
               JOIN pg_catalog.pg_attribute attribute
                 ON attribute.attrelid=relation.oid
                AND attribute.attnum>0 AND NOT attribute.attisdropped
               CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
                WHERE privilege.grantee<>relation.relowner
                  AND NOT COALESCE(
                    relation.relname='sm_resume_sessions'
                    AND privilege.grantor=relation.relowner
                    AND privilege.grantee=(SELECT oid FROM runtime)
                    AND privilege.privilege_type='SELECT'
                    AND NOT privilege.is_grantable
                    AND attribute.attname IN (SELECT attname FROM expected_sm_column),FALSE)
             )
             AND NOT EXISTS (
               SELECT 1 FROM expected_sm_column expected
                WHERE NOT EXISTS (
                  SELECT 1 FROM application_relation relation
                  JOIN pg_catalog.pg_attribute attribute
                    ON attribute.attrelid=relation.oid
                   AND attribute.attname=expected.attname
                   AND attribute.attnum>0 AND NOT attribute.attisdropped
                  CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
                   WHERE relation.relname='sm_resume_sessions'
                     AND privilege.grantor=relation.relowner
                     AND privilege.grantee=(SELECT oid FROM runtime)
                     AND privilege.privilege_type='SELECT'
                     AND NOT privilege.is_grantable
                )
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_type data_type
               CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
                 data_type.typacl,pg_catalog.acldefault('T',data_type.typowner)
               )) privilege
                WHERE NOT COALESCE(
                  privilege.grantor=data_type.typowner
                  AND NOT privilege.is_grantable
                  AND privilege.privilege_type='USAGE'
                  AND privilege.grantee IN (
                    data_type.typowner,(SELECT oid FROM runtime),
                    (SELECT oid FROM storage),(SELECT oid FROM backup)
                  ),FALSE)
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_type data_type
                WHERE EXISTS (
                  SELECT required.grantee FROM (VALUES
                    (data_type.typowner),((SELECT oid FROM runtime)),
                    ((SELECT oid FROM storage)),((SELECT oid FROM backup))
                  ) required(grantee)
                   WHERE NOT EXISTS (
                     SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                       data_type.typacl,pg_catalog.acldefault('T',data_type.typowner)
                     )) privilege
                      WHERE privilege.grantee=required.grantee
                        AND privilege.grantor=data_type.typowner
                        AND privilege.privilege_type='USAGE'
                        AND NOT privilege.is_grantable
                   )
                )
             )
             AND NOT EXISTS (SELECT 1 FROM unexpected_default)
             AND NOT pg_catalog.has_database_privilege((SELECT oid FROM runtime),pg_catalog.current_database(),'CREATE')
             AND NOT pg_catalog.has_database_privilege((SELECT oid FROM runtime),pg_catalog.current_database(),'TEMP')
             AND pg_catalog.has_database_privilege((SELECT oid FROM runtime),pg_catalog.current_database(),'CONNECT')
             AND pg_catalog.has_schema_privilege((SELECT oid FROM runtime),'public','USAGE')
             AND NOT pg_catalog.has_schema_privilege((SELECT oid FROM runtime),'public','CREATE')
             AND NOT EXISTS (
               SELECT 1 FROM application_relation relation
                WHERE (relation.relkind<>'S' AND (
                         pg_catalog.has_table_privilege((SELECT oid FROM runtime),relation.oid,'TRUNCATE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM runtime),relation.oid,'REFERENCES')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM runtime),relation.oid,'TRIGGER')))
                   OR CASE WHEN relation.relkind='S' THEN
                        pg_catalog.has_sequence_privilege(
                          (SELECT oid FROM runtime),relation.oid,'UPDATE')
                      ELSE FALSE END
             )
             AND pg_catalog.has_database_privilege((SELECT oid FROM command_role),pg_catalog.current_database(),'CONNECT')
             AND NOT pg_catalog.has_database_privilege((SELECT oid FROM command_role),pg_catalog.current_database(),'CREATE')
             AND NOT pg_catalog.has_database_privilege((SELECT oid FROM command_role),pg_catalog.current_database(),'TEMP')
             AND pg_catalog.has_schema_privilege((SELECT oid FROM command_role),'public','USAGE')
             AND NOT pg_catalog.has_schema_privilege((SELECT oid FROM command_role),'public','CREATE')
             AND NOT EXISTS (
               SELECT 1 FROM application_relation relation
                WHERE (relation.relkind<>'S' AND (
                         pg_catalog.has_table_privilege((SELECT oid FROM command_role),relation.oid,'SELECT')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM command_role),relation.oid,'INSERT')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM command_role),relation.oid,'UPDATE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM command_role),relation.oid,'DELETE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM command_role),relation.oid,'TRUNCATE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM command_role),relation.oid,'REFERENCES')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM command_role),relation.oid,'TRIGGER')
                      OR pg_catalog.has_any_column_privilege((SELECT oid FROM command_role),relation.oid,'SELECT')
                      OR pg_catalog.has_any_column_privilege((SELECT oid FROM command_role),relation.oid,'INSERT')
                      OR pg_catalog.has_any_column_privilege((SELECT oid FROM command_role),relation.oid,'UPDATE')
                      OR pg_catalog.has_any_column_privilege((SELECT oid FROM command_role),relation.oid,'REFERENCES')))
                   OR CASE WHEN relation.relkind='S' THEN (
                        pg_catalog.has_sequence_privilege((SELECT oid FROM command_role),relation.oid,'SELECT')
                     OR pg_catalog.has_sequence_privilege((SELECT oid FROM command_role),relation.oid,'USAGE')
                     OR pg_catalog.has_sequence_privilege((SELECT oid FROM command_role),relation.oid,'UPDATE'))
                      ELSE FALSE END
             )
             AND pg_catalog.has_database_privilege((SELECT oid FROM storage),pg_catalog.current_database(),'CONNECT')
             AND NOT pg_catalog.has_database_privilege((SELECT oid FROM storage),pg_catalog.current_database(),'CREATE')
             AND NOT pg_catalog.has_database_privilege((SELECT oid FROM storage),pg_catalog.current_database(),'TEMP')
             AND pg_catalog.has_schema_privilege((SELECT oid FROM storage),'public','USAGE')
             AND NOT pg_catalog.has_schema_privilege((SELECT oid FROM storage),'public','CREATE')
             AND NOT EXISTS (
               SELECT 1 FROM application_relation relation
                WHERE (relation.relkind<>'S' AND (
                         pg_catalog.has_table_privilege((SELECT oid FROM storage),relation.oid,'SELECT')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM storage),relation.oid,'INSERT')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM storage),relation.oid,'UPDATE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM storage),relation.oid,'DELETE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM storage),relation.oid,'TRUNCATE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM storage),relation.oid,'REFERENCES')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM storage),relation.oid,'TRIGGER')
                      OR pg_catalog.has_any_column_privilege((SELECT oid FROM storage),relation.oid,'SELECT')
                      OR pg_catalog.has_any_column_privilege((SELECT oid FROM storage),relation.oid,'INSERT')
                      OR pg_catalog.has_any_column_privilege((SELECT oid FROM storage),relation.oid,'UPDATE')
                      OR pg_catalog.has_any_column_privilege((SELECT oid FROM storage),relation.oid,'REFERENCES')))
                   OR CASE WHEN relation.relkind='S' THEN (
                        pg_catalog.has_sequence_privilege((SELECT oid FROM storage),relation.oid,'SELECT')
                     OR pg_catalog.has_sequence_privilege((SELECT oid FROM storage),relation.oid,'USAGE')
                     OR pg_catalog.has_sequence_privilege((SELECT oid FROM storage),relation.oid,'UPDATE'))
                      ELSE FALSE END
             )
             AND NOT pg_catalog.has_database_privilege((SELECT oid FROM backup),pg_catalog.current_database(),'CREATE')
             AND NOT pg_catalog.has_database_privilege((SELECT oid FROM backup),pg_catalog.current_database(),'TEMP')
             AND pg_catalog.has_database_privilege((SELECT oid FROM backup),pg_catalog.current_database(),'CONNECT')
             AND pg_catalog.has_schema_privilege((SELECT oid FROM backup),'public','USAGE')
             AND NOT pg_catalog.has_schema_privilege((SELECT oid FROM backup),'public','CREATE')
             AND NOT EXISTS (
               SELECT 1 FROM application_relation relation
                WHERE (relation.relkind IN ('r','p','v','m','f') AND (
                         NOT pg_catalog.has_table_privilege((SELECT oid FROM backup),relation.oid,'SELECT')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM backup),relation.oid,'INSERT')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM backup),relation.oid,'UPDATE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM backup),relation.oid,'DELETE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM backup),relation.oid,'TRUNCATE')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM backup),relation.oid,'REFERENCES')
                      OR pg_catalog.has_table_privilege((SELECT oid FROM backup),relation.oid,'TRIGGER')))
                   OR CASE WHEN relation.relkind='S' THEN (
                        NOT pg_catalog.has_sequence_privilege((SELECT oid FROM backup),relation.oid,'SELECT')
                     OR pg_catalog.has_sequence_privilege((SELECT oid FROM backup),relation.oid,'USAGE')
                     OR pg_catalog.has_sequence_privilege((SELECT oid FROM backup),relation.oid,'UPDATE'))
                      ELSE FALSE END
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_routine routine
                WHERE pg_catalog.has_function_privilege((SELECT oid FROM backup),routine.oid,'EXECUTE')
             )"#,
    )
    .fetch_one(pool)
    .await
    .context("could not attest the shared PostgreSQL role/object capability catalog")?;
    anyhow::ensure!(
        accepted,
        "shared PostgreSQL capability catalog drifted: reconcile role attributes, memberships, owners, relation/column/sequence/type/default ACLs, trigger-only runtime routine execution, runtime dangerous privileges, and backup read-only access"
    );
    Ok(())
}
