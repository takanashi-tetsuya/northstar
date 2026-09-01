use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::collections::HashSet;
use std::net::IpAddr;

const CAPABILITY_MANIFEST_SQL: &str =
    include_str!("../../deploy/postgres-init/lib/northstar-capability-manifest.sql");
const MIGRATION_LEDGER_MANIFEST_SQL: &str =
    include_str!("../../deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql");

#[derive(Debug, PartialEq, Eq)]
struct MigrationLedgerManifest {
    versions: Vec<i64>,
    descriptions: Vec<String>,
    checksum_hex: Vec<String>,
}

fn parse_sql_string_literal(source: &str) -> Result<(String, &str)> {
    let source = source
        .strip_prefix('\'')
        .context("migration ledger description is not a SQL string literal")?;
    let mut value = String::new();
    let mut chars = source.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if character != '\'' {
            value.push(character);
            continue;
        }
        if matches!(chars.peek(), Some((_, '\''))) {
            let _ = chars.next();
            value.push('\'');
            continue;
        }
        return Ok((value, &source[index + character.len_utf8()..]));
    }
    anyhow::bail!("migration ledger description has no closing quote")
}

fn parse_migration_ledger_manifest(source: &str) -> Result<MigrationLedgerManifest> {
    const CHECKSUM_PREFIX: &str = ",pg_catalog.decode('";
    const CHECKSUM_SUFFIX: &str = "','hex')";
    let mut versions = Vec::new();
    let mut descriptions = Vec::new();
    let mut checksum_hex = Vec::new();
    let mut seen = HashSet::new();

    for line in source.lines() {
        let row = line.trim().trim_end_matches([',', ';']);
        let Some(row) = row.strip_prefix('(').and_then(|row| row.strip_suffix(')')) else {
            continue;
        };
        let Some((version, remainder)) = row.split_once(',') else {
            continue;
        };
        if !version.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let version = version
            .parse::<i64>()
            .context("migration ledger contains an invalid version")?;
        anyhow::ensure!(version > 0, "migration ledger version must be positive");
        anyhow::ensure!(
            seen.insert(version),
            "migration ledger contains a duplicate version"
        );
        let (description, remainder) = parse_sql_string_literal(remainder)?;
        anyhow::ensure!(
            !description.is_empty(),
            "migration ledger contains an empty description"
        );
        let checksum = remainder
            .strip_prefix(CHECKSUM_PREFIX)
            .and_then(|value| value.strip_suffix(CHECKSUM_SUFFIX))
            .context("migration ledger checksum expression is malformed")?;
        anyhow::ensure!(
            checksum.len() == 96
                && checksum
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "migration ledger checksum is not a lowercase SHA-384 digest"
        );
        versions.push(version);
        descriptions.push(description);
        checksum_hex.push(checksum.to_owned());
    }
    anyhow::ensure!(!versions.is_empty(), "embedded migration ledger is empty");
    anyhow::ensure!(
        source.matches("pg_catalog.decode('").count() == versions.len()
            && source
                .matches("\\set northstar_migration_ledger_manifest_is_loaded true")
                .count()
                == 1,
        "embedded migration ledger contains an unparsed or duplicate structure"
    );
    anyhow::ensure!(
        versions.windows(2).all(|pair| pair[0] < pair[1]),
        "embedded migration ledger is not ordered by version"
    );
    anyhow::ensure!(
        versions.first() == Some(&1)
            && versions
                .windows(2)
                .all(|pair| { pair[1] == pair[0] + 1 || (pair[0] == 20 && pair[1] == 22) })
            && versions.contains(&20)
            && versions.contains(&22)
            && !versions.contains(&21),
        "embedded migration ledger contains an unreviewed version gap"
    );
    Ok(MigrationLedgerManifest {
        versions,
        descriptions,
        checksum_hex,
    })
}

async fn attest_migration_ledger(pool: &PgPool) -> Result<()> {
    let expected = parse_migration_ledger_manifest(MIGRATION_LEDGER_MANIFEST_SQL)?;
    let accepted: bool = sqlx::query_scalar(
        r#"WITH expected AS (
             SELECT version,description,checksum_hex
               FROM pg_catalog.unnest(
                 $1::pg_catalog.int8[],
                 $2::pg_catalog.text[],
                 $3::pg_catalog.text[]
               ) AS manifest(version,description,checksum_hex)
           ), actual AS (
             SELECT version,description,success,
                    pg_catalog.encode(checksum,'hex') AS checksum_hex
               FROM public._sqlx_migrations
           )
           SELECT NOT EXISTS (
                    SELECT 1 FROM actual
                     WHERE NOT success OR version<=0 OR description=''
                        OR pg_catalog.length(checksum_hex)<>96
                  )
             AND (SELECT pg_catalog.count(*) FROM actual)
                  =(SELECT pg_catalog.count(DISTINCT version) FROM actual)
             AND (SELECT pg_catalog.count(*) FROM actual)
                  =(SELECT pg_catalog.count(*) FROM expected)
             AND NOT EXISTS (
               (SELECT version,description,checksum_hex FROM actual WHERE success
                EXCEPT
                SELECT version,description,checksum_hex FROM expected)
               UNION ALL
               (SELECT version,description,checksum_hex FROM expected
                EXCEPT
                SELECT version,description,checksum_hex FROM actual WHERE success)
             )"#,
    )
    .bind(&expected.versions)
    .bind(&expected.descriptions)
    .bind(&expected.checksum_hex)
    .fetch_one(pool)
    .await
    .context("could not attest the repository migration ledger")?;
    anyhow::ensure!(
        accepted,
        "PostgreSQL migration ledger drifted: an expected version/description/SHA-384 row is missing, unknown, failed, duplicated, or tampered"
    );
    Ok(())
}

fn parse_security_definer_capability_manifest(source: &str) -> Result<(Vec<String>, Vec<String>)> {
    let mut signatures = Vec::new();
    let mut workloads = Vec::new();
    let mut seen = HashSet::new();
    for line in source.lines() {
        let row = line.trim().trim_end_matches([',', ';']);
        let Some(row) = row
            .strip_prefix("('")
            .and_then(|row| row.strip_suffix("')"))
        else {
            continue;
        };
        let fields = row.split("','").collect::<Vec<_>>();
        if fields.len() != 3 || !matches!(fields[1], "runtime" | "command" | "private") {
            continue;
        }
        let signature = fields[0];
        anyhow::ensure!(
            !signature.is_empty()
                && signature.contains('(')
                && signature.ends_with(')')
                && signature.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'(' | b')' | b',' | b'[' | b']')
                }),
            "the embedded PostgreSQL capability manifest contains an unsafe signature"
        );
        anyhow::ensure!(
            seen.insert(signature.to_owned()),
            "the embedded PostgreSQL capability manifest contains a duplicate signature"
        );
        signatures.push(signature.to_owned());
        workloads.push(fields[1].to_owned());
    }
    anyhow::ensure!(
        !signatures.is_empty() && signatures.len() == workloads.len(),
        "the embedded PostgreSQL capability manifest is empty or malformed"
    );
    Ok((signatures, workloads))
}

pub(super) fn security_definer_capability_manifest() -> Result<(Vec<String>, Vec<String>)> {
    parse_security_definer_capability_manifest(CAPABILITY_MANIFEST_SQL)
}

/// Compare the ACL catalog itself with the version-controlled capability
/// manifest. Effective `has_function_privilege` checks are insufficient here:
/// PUBLIC, a retired login, the backup role, a role membership, or a stale
/// overloaded helper could otherwise retain a callable owner-held routine.
async fn attest_security_definer_capability_acls(pool: &PgPool) -> Result<()> {
    let (signatures, workloads) = security_definer_capability_manifest()?;
    let accepted: bool = sqlx::query_scalar(
        r#"WITH signature_rows AS (
             SELECT signature,ordinality
               FROM pg_catalog.unnest($1::pg_catalog.text[])
                    WITH ORDINALITY AS value(signature,ordinality)
           ), workload_rows AS (
             SELECT workload,ordinality
               FROM pg_catalog.unnest($2::pg_catalog.text[])
                    WITH ORDINALITY AS value(workload,ordinality)
           ), expected AS (
             SELECT signature_rows.signature,workload_rows.workload
               FROM signature_rows JOIN workload_rows USING(ordinality)
           ), namespace AS (
             SELECT oid,nspowner FROM pg_catalog.pg_namespace
              WHERE nspname='public'
           ), resolved AS (
             SELECT expected.signature,expected.workload,
                    pg_catalog.to_regprocedure('public.' || expected.signature) AS oid,
                    CASE expected.workload
                      WHEN 'runtime' THEN (SELECT role.oid
                        FROM pg_catalog.pg_roles role
                        WHERE role.rolname='northstar_runtime')
                      WHEN 'command' THEN (SELECT role.oid
                        FROM pg_catalog.pg_roles role
                        WHERE role.rolname='northstar_commands')
                      ELSE NULL
                    END AS workload_role
               FROM expected
           ), protected AS (
             SELECT resolved.*,routine.proowner,routine.prosecdef,routine.prokind,
                    routine.proconfig,routine.proacl,namespace.nspowner
               FROM namespace CROSS JOIN resolved
               LEFT JOIN pg_catalog.pg_proc routine
                 ON routine.oid=resolved.oid
                AND routine.pronamespace=namespace.oid
           )
           SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
             AND NOT EXISTS(
               SELECT 1 FROM protected routine
                WHERE routine.oid IS NULL
                   OR routine.proowner<>routine.nspowner
                   OR NOT routine.prosecdef
                   OR routine.prokind<>'f'
                   OR routine.proconfig IS DISTINCT FROM
                        ARRAY['search_path=pg_catalog, public, pg_temp']::pg_catalog.text[]
                   OR (routine.workload<>'private' AND routine.workload_role IS NULL)
                   OR (SELECT pg_catalog.count(*)
                         FROM pg_catalog.aclexplode(COALESCE(
                           routine.proacl,
                           pg_catalog.acldefault('f',routine.proowner)
                         )) privilege)
                        <>CASE WHEN routine.workload='private' THEN 1 ELSE 2 END
                   OR EXISTS(
                     SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                       routine.proacl,pg_catalog.acldefault('f',routine.proowner)
                     )) privilege
                      WHERE privilege.privilege_type<>'EXECUTE'
                         OR privilege.is_grantable
                         OR privilege.grantor<>routine.proowner
                         OR (privilege.grantee<>routine.proowner
                           AND privilege.grantee IS DISTINCT FROM routine.workload_role)
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
                   OR (routine.workload<>'private' AND NOT EXISTS(
                     SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                       routine.proacl,pg_catalog.acldefault('f',routine.proowner)
                     )) privilege
                      WHERE privilege.grantee=routine.workload_role
                        AND privilege.grantor=routine.proowner
                        AND privilege.privilege_type='EXECUTE'
                        AND NOT privilege.is_grantable
                   ))
             )
             AND NOT EXISTS(
               SELECT 1 FROM namespace
               JOIN pg_catalog.pg_proc routine
                 ON routine.pronamespace=namespace.oid AND routine.prosecdef
               LEFT JOIN resolved expected ON expected.oid=routine.oid
                WHERE expected.oid IS NULL
             )"#,
    )
    .bind(&signatures)
    .bind(&workloads)
    .fetch_one(pool)
    .await
    .context("could not attest the PostgreSQL SECURITY DEFINER capability ACL manifest")?;
    anyhow::ensure!(
        accepted,
        "PostgreSQL SECURITY DEFINER capability ACL manifest drifted: reconcile grants and remove PUBLIC, unknown, backup, grant-option, command/runtime crossover, or stale helper access"
    );
    Ok(())
}

/// Attest the shared PostgreSQL catalog boundary, not merely the privileges of
/// the connection that happened to start this pool.  This catches a powerful
/// auxiliary role, alien direct ACL, delegated grant chain, ownership drift or
/// read/write backup crossover even when the current runtime/command login is
/// itself perfectly restricted.
async fn attest_database_capability_catalog(pool: &PgPool) -> Result<()> {
    let accepted: bool = sqlx::query_scalar(
        r#"WITH expected_role(role_name,connection_limit) AS (
             VALUES
               ('northstar_migrator'::pg_catalog.text,4),
               ('northstar_runtime'::pg_catalog.text,64),
               ('northstar_commands'::pg_catalog.text,8),
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
             SELECT routine.oid,routine.proowner,routine.proacl
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
           SELECT (SELECT pg_catalog.count(*)=4 AND pg_catalog.bool_and(
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
                      (SELECT oid FROM runtime),(SELECT oid FROM command_role),(SELECT oid FROM backup)
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
                      (SELECT oid FROM runtime),(SELECT oid FROM command_role),(SELECT oid FROM backup)
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
                      (SELECT oid FROM runtime),(SELECT oid FROM command_role)
                    ),FALSE
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
                    data_type.typowner,(SELECT oid FROM runtime),(SELECT oid FROM backup)
                  ),FALSE)
             )
             AND NOT EXISTS (
               SELECT 1 FROM application_type data_type
                WHERE EXISTS (
                  SELECT required.grantee FROM (VALUES
                    (data_type.typowner),((SELECT oid FROM runtime)),((SELECT oid FROM backup))
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
        "shared PostgreSQL capability catalog drifted: reconcile role attributes, memberships, owners, relation/column/sequence/type/default ACLs, runtime dangerous privileges, and backup read-only access"
    );
    Ok(())
}

/// Production database capabilities are defined only for the `public`
/// application schema. Pin every physical pooled connection instead of
/// trusting a caller-controlled DSN `options=-c search_path=...` value.
pub fn pin_public_application_schema(options: PgPoolOptions) -> PgPoolOptions {
    options.after_connect(|connection, _| {
        Box::pin(async move {
            sqlx::query("SELECT pg_catalog.set_config('search_path','public',FALSE)")
                .execute(&mut *connection)
                .await?;
            Ok(())
        })
    })
}

/// The development escape hatch is intentionally narrower than simply
/// skipping role attestation. The caller must already have proved that the
/// deployment uses a reserved test domain and loopback listeners; this final
/// database-side check prevents that escape hatch from being pointed at a
/// shared or remote PostgreSQL server.
pub async fn attest_development_database_is_loopback(pool: &PgPool) -> Result<()> {
    let server_address: Option<String> =
        sqlx::query_scalar("SELECT pg_catalog.inet_server_addr()::text")
            .fetch_one(pool)
            .await
            .context("could not inspect the development PostgreSQL server address")?;
    if let Some(server_address) = server_address {
        let address = server_address
            .split_once('/')
            .map_or(server_address.as_str(), |(address, _)| address)
            .parse::<IpAddr>()
            .context("PostgreSQL returned an invalid server address")?;
        anyhow::ensure!(
            address.is_loopback(),
            "the unsafe development database-role override is restricted to loopback PostgreSQL"
        );
    }
    Ok(())
}

/// Proves that the long-lived application connection is not an owner or DDL
/// identity.  Object-specific ACLs remain enforced by the reconciled database
/// capability manifest; this check prevents an accidentally-mounted migrator
/// or bootstrap URL from turning those boundaries into advisory conventions.
pub async fn attest_runtime_role(pool: &PgPool) -> Result<()> {
    attest_migration_ledger(pool).await?;
    attest_database_capability_catalog(pool).await?;
    attest_security_definer_capability_acls(pool).await?;
    let accepted: bool = sqlx::query_scalar(
        r#"WITH expected_definer(signature) AS (
             VALUES
               ('northstar_transfer_cluster_muc_outbox(uuid,uuid,uuid,uuid,int8,uuid,int8,text)'),
               ('northstar_purge_released_hold_offline_snapshots(int4,int4)'),
               ('northstar_purge_audit_log(int4,int4)'),
               ('northstar_purge_governance_export_leases(int4,int4)'),
               ('northstar_purge_cluster_muc_history(int4,int4)'),
               ('northstar_release_legal_hold(uuid,uuid,text,uuid)'),
               ('northstar_user_register(uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,bytea,bool,int4,uuid)'),
               ('northstar_user_create_bootstrap_admin(uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
               ('northstar_user_clear_scram_sha1()'),
               ('northstar_user_apply_login(uuid,text,int8,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
               ('northstar_user_change_password_api(uuid,text,int8,bytea,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,uuid)'),
               ('northstar_user_change_password_stream(uuid,int8,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea)'),
               ('northstar_user_set_status_api(uuid,int8,bytea,uuid,bool,bool)'),
               ('northstar_user_bump_roster_version(uuid)'),
               ('northstar_user_consume_recovery_generation(uuid,int8,bytea)'),
               ('northstar_user_quiesce_deletion(uuid,int8)'),
               ('northstar_user_delete_quiesced(uuid,text)'),
               ('northstar_admin_command_authorize_claim(text,uuid,text,int8,text,bytea)'),
               ('northstar_admin_command_create_user(text,uuid,text,int8,text,bytea,uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,text)'),
               ('northstar_admin_command_reset_user_password(text,uuid,text,int8,text,bytea,uuid,text,text,bytea,int4,bytea,bytea,bytea,int4,bytea,bytea,text,text)'),
               ('northstar_admin_command_user_lifecycle(text,uuid,text,int8,text,bytea,uuid,text,text,text,text,bool,text)'),
               ('northstar_admin_command_issue_delete_cleanup(text,uuid,text,int8,text,bytea,uuid,text,text)'),
               ('northstar_claim_admin_session_cleanup(uuid,int4)'),
               ('northstar_renew_admin_session_cleanup(uuid,uuid,uuid,int4)'),
               ('northstar_retry_admin_session_cleanup(uuid,uuid,uuid,text)'),
               ('northstar_complete_admin_session_cleanup(uuid,uuid,uuid)'),
               ('northstar_admin_session_cleanup_target_current(uuid,uuid,uuid)'),
               ('northstar_admin_session_cleanup_snapshot()'),
               ('northstar_admin_command_delete_user(text,uuid,text,int8,text,bytea,uuid,text,bool,text)'),
               ('northstar_admin_command_replace_users(text,uuid,text,int8,text,bytea,uuid[],text)'),
               ('northstar_admin_command_record_announcement(text,uuid,text,int8,text,bytea,int4,int4,text)'),
               ('northstar_admin_command_set_service_message(text,uuid,text,int8,text,bytea,text,text,text)'),
               ('northstar_admin_command_replace_federation_rules(text,uuid,text,int8,text,bytea,text,text[],text)'),
               ('northstar_admin_command_service_control(text,uuid,text,int8,text,bytea,text,int4,text,bool,text)'),
               ('northstar_admin_service_control_poll()'),
               ('northstar_admit_cluster_envelope_replay(text,text,uuid,int8,text,int8,text,uuid,int8,text,int8,uuid,bytea,text,timestamptz)'),
               ('northstar_cleanup_cluster_envelope_replays(int4)'),
               ('northstar_cluster_replay_capacity_healthy()'),
               ('northstar_claim_cluster_session_route(text,text,text,text,uuid,int8,uuid,uuid,uuid,int4)'),
               ('northstar_refresh_cluster_session_route(text,text,text,uuid,int8,uuid,int4)'),
               ('northstar_release_cluster_session_route(text,text,text,uuid,int8,uuid)'),
               ('northstar_cluster_session_route(text,text)'),
               ('northstar_cluster_session_nodes_for_bare(text,text)'),
               ('northstar_cleanup_cluster_session_routes(int4)'),
               ('northstar_cluster_session_authority_healthy()'),
               ('northstar_upload_bootstrap_authority(text,bytea)'),
               ('northstar_upload_bind_capacity_policy(int8,int8,int8)'),
               ('northstar_upload_capacity_lock()'),
               ('northstar_upload_active_slot_count(uuid)'),
               ('northstar_upload_public_slot_count()'),
               ('northstar_upload_renew_claim(uuid,uuid,int8)'),
               ('northstar_upload_authority_probe(text,bytea,int8,int8,int8,int8,int8)'),
               ('northstar_upload_dead_letters_page(text,int8,uuid,int4)'),
               ('northstar_upload_retry_dead_letter(uuid,int8,bytea,text,int8,uuid,uuid)'),
               ('northstar_upload_claim_cleanup(uuid)'),
               ('northstar_upload_cleanup_quiescent(uuid,uuid,int8)'),
               ('northstar_upload_defer_cleanup(uuid,uuid)'),
               ('northstar_upload_confirm_cleanup_absence(uuid,uuid,bool,int8)'),
               ('northstar_upload_fail_cleanup(uuid,uuid,text)'),
               ('northstar_upload_complete_cleanup(uuid,uuid)'),
               ('northstar_upload_claim_storage_jobs(uuid)'),
               ('northstar_upload_complete_storage_job(int8,uuid)'),
               ('northstar_upload_confirm_stage_absence(int8,uuid,bool,int8)'),
               ('northstar_upload_fail_storage_job(int8,uuid,text)'),
               ('northstar_upload_defer_storage_job(int8,uuid)'),
               ('northstar_upload_claim_promotion_job(uuid,uuid,int8,uuid)'),
               ('northstar_upload_defer_promotion_job(uuid,uuid,int8,uuid)'),
               ('northstar_upload_retire_promotion_for_cleanup(uuid,uuid,int8,uuid)'),
               ('northstar_upload_record_stage(uuid,uuid,text,text,text,text,bytea,int8,int8)'),
               ('northstar_upload_release_claim(uuid,uuid)'),
               ('northstar_upload_complete_promotion(uuid,uuid,uuid,text,text,text,bytea,int8,int8,int8)'),
               ('northstar_upload_reserve_slot(uuid,uuid,text,text,int8,bytea,int8,int8,text,int8,int8,int8)'),
               ('northstar_upload_claim_is_live(uuid,uuid)'),
               ('northstar_upload_begin_promotion(uuid,uuid,int8,uuid)'),
               ('northstar_upload_attempt_committed(uuid,uuid,text,text,text,bytea,int8,int8)'),
               ('northstar_upload_record_replay(uuid,bytea,bytea,int8)'),
               ('northstar_upload_public_file(uuid)'),
               ('northstar_upload_claim_scrub()'),
               ('northstar_upload_finish_scrub(uuid,uuid,text)'),
               ('northstar_upload_claim_slot(uuid,bytea,int8,int8,int8)'),
               ('northstar_upload_capacity_reconciliation()'),
               ('northstar_upload_queue_snapshot()'),
               ('northstar_upload_policy_binding_matches(int8,int8,int8)'),
               ('northstar_upload_admit_expired_cleanup()'),
               ('northstar_upload_delete_owned(uuid,int8,bytea,uuid,uuid)'),
               ('northstar_upload_capability_catalog_healthy(text)'),
               ('northstar_session_delete_expired_live_leases()'),
               ('northstar_session_capacity_reconcile_lock()'),
               ('northstar_session_reserve_live(uuid,uuid,text,int8,bool)'),
               ('northstar_session_finalize_binding(uuid,uuid,text)'),
               ('northstar_session_publish_binding(uuid,uuid,text,int8)'),
               ('northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)'),
               ('northstar_session_release_live(uuid)'),
               ('northstar_session_refresh_live(uuid[],int8)'),
               ('northstar_session_cleanup_live(int8)'),
               ('northstar_session_extend_live(uuid,int8)'),
               ('northstar_sm_create(uuid,bytea,uuid,int8,text,text,text,uuid,int8,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,int8,int8)'),
               ('northstar_sm_update_snapshot(uuid,uuid,int8,int8,int8,bool,bool,int2,bool,bool,text,bool,inet,uuid,jsonb,jsonb,text,bool,int8,int8)'),
               ('northstar_sm_remove_memberships(uuid,uuid,jsonb)'),
               ('northstar_sm_exact_owner_state(uuid,uuid,uuid,int8)'),
               ('northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)'),
               ('northstar_sm_claim_authority(uuid,uuid)'),
               ('northstar_sm_activate(uuid,uuid,uuid,int8,inet,uuid,int8,int8)'),
               ('northstar_sm_release_claim(uuid,uuid)'),
               ('northstar_sm_revoke(uuid)'),
               ('northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)'),
               ('northstar_sm_teardown_pending(text,uuid,uuid,int8,text,uuid)'),
               ('northstar_sm_count(text,uuid,int8,text)'),
               ('northstar_sm_finalize_teardown(uuid,uuid)'),
               ('northstar_sm_lock_suspended(uuid)'),
               ('northstar_sm_advance_suspended(uuid,int8,int8)'),
               ('northstar_sm_expire_before_generation(uuid,int8)'),
               ('northstar_sm_privacy_list_in_use(uuid,text)'),
               ('northstar_sm_privacy_state(uuid)'),
               ('northstar_session_capability_catalog_healthy(text)')
           ), resolved_definer AS (
             SELECT signature,
                    pg_catalog.to_regprocedure('public.' || signature) AS oid
               FROM expected_definer
           ), immutable(name,deny_insert) AS (
             VALUES
               ('audit_log',FALSE),('legal_holds',FALSE),
               ('legal_hold_personal_archives',FALSE),('legal_hold_muc_archives',FALSE),
               ('legal_hold_offline_messages',FALSE),('legal_hold_report_evidence',FALSE),
               ('legal_hold_scopes',FALSE),('legal_hold_offline_snapshots',FALSE),
               ('cluster_muc_operations',FALSE),('cluster_muc_delivery_handoffs',TRUE)
           ), migration_ledger(name) AS (
             VALUES ('_sqlx_migrations'),('jid_identity_migrations')
           )
           SELECT role.rolname='northstar_runtime'
             AND session_user=current_user
             AND session_user='northstar_runtime'
             AND role.rolcanlogin
             AND NOT role.rolsuper
             AND NOT role.rolinherit
             AND NOT role.rolcreatedb
             AND NOT role.rolcreaterole
             AND NOT role.rolreplication
             AND NOT role.rolbypassrls
             AND role.rolconnlimit=64
             AND current_schema()='public'
             AND current_schemas(FALSE)=ARRAY['public'::pg_catalog.name]
             AND pg_catalog.pg_get_userbyid(database.datdba)='northstar_migrator'
             AND pg_catalog.pg_get_userbyid(namespace.nspowner)='northstar_migrator'
             AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'CREATE')
             AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'TEMP')
             AND NOT pg_catalog.has_schema_privilege(current_user,namespace.oid,'CREATE')
             AND NOT EXISTS (
                 SELECT 1 FROM immutable
                 CROSS JOIN LATERAL (
                   SELECT pg_catalog.to_regclass(
                     pg_catalog.format('%I.%I',namespace.nspname,immutable.name)
                   ) AS oid
                 ) relation
                 WHERE relation.oid IS NULL
                    OR (immutable.deny_insert AND pg_catalog.has_table_privilege(
                          current_user,relation.oid,'INSERT'))
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'UPDATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'DELETE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRUNCATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'REFERENCES')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRIGGER')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'INSERT')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'UPDATE')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'REFERENCES')
             )
             AND NOT EXISTS (
                 SELECT 1 FROM (SELECT pg_catalog.to_regclass(
                   pg_catalog.format('%I.governance_export_leases',namespace.nspname)
                 ) AS oid) relation
                 WHERE relation.oid IS NULL
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'DELETE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRUNCATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'REFERENCES')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRIGGER')
             )
             AND NOT EXISTS (
                 SELECT 1 FROM migration_ledger
                 CROSS JOIN LATERAL (
                   SELECT pg_catalog.to_regclass(
                     pg_catalog.format('%I.%I',namespace.nspname,migration_ledger.name)
                   ) AS oid
                 ) relation
                 WHERE relation.oid IS NULL
                    OR NOT pg_catalog.has_table_privilege(current_user,relation.oid,'SELECT')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'INSERT')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'UPDATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'DELETE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRUNCATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'REFERENCES')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRIGGER')
             )
             AND NOT EXISTS (
                 SELECT 1 FROM (SELECT pg_catalog.to_regclass(
                   pg_catalog.format('%I.users',namespace.nspname)
                 ) AS oid) relation
                 WHERE relation.oid IS NULL
                    OR NOT pg_catalog.has_table_privilege(current_user,relation.oid,'SELECT')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'INSERT')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'UPDATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'DELETE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRUNCATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'REFERENCES')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRIGGER')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'INSERT')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'UPDATE')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'REFERENCES')
             )
             AND NOT EXISTS (
                 SELECT 1 FROM (VALUES
                   ('admin_service_messages'),
                   ('federation_runtime_rules'),
                   ('admin_service_control')
                 ) protected(name)
                 CROSS JOIN LATERAL (
                   SELECT pg_catalog.to_regclass(
                     pg_catalog.format('%I.%I',namespace.nspname,protected.name)
                   ) AS oid
                 ) relation
                 WHERE relation.oid IS NULL
                    OR NOT pg_catalog.has_table_privilege(current_user,relation.oid,'SELECT')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'INSERT')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'UPDATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'DELETE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRUNCATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'REFERENCES')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRIGGER')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'INSERT')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'UPDATE')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'REFERENCES')
             )
             AND NOT EXISTS (
                 SELECT 1 FROM (VALUES
                   ('admin_command_sessions'),
                   ('admin_command_capability_authority'),
                   ('admin_session_cleanup_effects'),
                   ('admin_session_cleanup_capacity')
                 ) protected(name)
                 CROSS JOIN LATERAL (
                   SELECT pg_catalog.to_regclass(
                     pg_catalog.format('%I.%I',namespace.nspname,protected.name)
                   ) AS oid
                 ) relation
                 WHERE relation.oid IS NULL
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'SELECT')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'INSERT')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'UPDATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'DELETE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRUNCATE')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'REFERENCES')
                    OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRIGGER')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'SELECT')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'INSERT')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'UPDATE')
                    OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'REFERENCES')
             )
             AND NOT EXISTS (
                 SELECT 1 FROM (VALUES
                   ('northstar_protect_admin_session_cleanup_identity()'),
                   ('northstar_enqueue_admin_generation_cleanup(uuid,uuid,int8,text)'),
                   ('northstar_enqueue_admin_exact_session_cleanup(uuid,uuid,int8,text,uuid)')
                 ) private_helper(signature)
                 CROSS JOIN LATERAL (
                   SELECT pg_catalog.to_regprocedure(
                     pg_catalog.format('%I.%s',namespace.nspname,private_helper.signature)
                   ) AS oid
                 ) routine
                 WHERE routine.oid IS NULL
                    OR pg_catalog.has_function_privilege(
                         current_user,routine.oid,'EXECUTE')
             )
             AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_class sequence
                 WHERE sequence.relnamespace=namespace.oid
                   AND CASE WHEN sequence.relkind='S' THEN
                         pg_catalog.has_sequence_privilege(
                           current_user,sequence.oid,'UPDATE')
                       ELSE FALSE END
             )
             AND NOT EXISTS (
                 SELECT 1 FROM resolved_definer allowed
                 LEFT JOIN pg_catalog.pg_proc routine ON routine.oid=allowed.oid
                 WHERE allowed.oid IS NULL
                    OR routine.prokind<>'f'
                    OR NOT routine.prosecdef
                    OR pg_catalog.pg_get_userbyid(routine.proowner)<>'northstar_migrator'
                    OR routine.proconfig IS DISTINCT FROM
                         ARRAY['search_path=pg_catalog, public, pg_temp']::pg_catalog.text[]
                    OR NOT pg_catalog.has_function_privilege(
                         current_user,routine.oid,'EXECUTE')
             )
             AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_proc routine
                 WHERE routine.pronamespace=namespace.oid
                   AND routine.prosecdef
                   AND pg_catalog.has_function_privilege(current_user,routine.oid,'EXECUTE')
                   AND NOT EXISTS (
                     SELECT 1 FROM resolved_definer allowed WHERE allowed.oid=routine.oid
                   )
             )
             AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_auth_members membership
                  WHERE membership.member=role.oid OR membership.roleid=role.oid
             )
          FROM pg_catalog.pg_roles role
          JOIN pg_catalog.pg_database database ON database.datname=current_database()
          JOIN pg_catalog.pg_namespace namespace ON namespace.nspname='public'
         WHERE role.rolname=current_user"#,
    )
    .fetch_one(pool)
    .await
    .context("could not inspect runtime PostgreSQL role")?;
    anyhow::ensure!(
        accepted,
        "PostgreSQL runtime role attestation failed: mount the bounded northstar_runtime URL; owner, superuser, CREATE, TEMP, role-membership and unbounded-login identities are refused"
    );
    Ok(())
}

/// Proves that the isolated XEP-0133 session issuer has no relation access and
/// can execute only the eight typed, owner-held session lifecycle commands.
/// The bearer and claim secrets therefore cannot be minted through arbitrary
/// SQL on the normal runtime pool.
pub async fn attest_admin_command_role(pool: &PgPool) -> Result<()> {
    attest_database_capability_catalog(pool).await?;
    attest_security_definer_capability_acls(pool).await?;
    let accepted: bool = sqlx::query_scalar(
        r#"WITH expected(signature) AS (
             VALUES
               ('northstar_admin_command_create_session(uuid,text,uuid,text,text,text,int8,text,text)'),
               ('northstar_admin_command_finish_session(text,uuid,text,text,int8,text,text)'),
               ('northstar_admin_command_complete_immediate_read(text,uuid,text,text,int8,text,text)'),
               ('northstar_admin_command_begin_execution(text,text,uuid,uuid,text,text,int8,text,bytea)'),
               ('northstar_admin_command_renew_claim(text,uuid,text,int8,text,bytea)'),
               ('northstar_admin_command_release_claim(text,uuid,text,int8,text,bytea)'),
               ('northstar_admin_command_complete_read_claim(text,uuid,text,int8,text,bytea,text)'),
               ('northstar_admin_command_cleanup()')
           ), resolved AS (
             SELECT signature,
                    pg_catalog.to_regprocedure('public.' || signature) AS oid
               FROM expected
           )
           SELECT role.rolname='northstar_commands'
             AND session_user=current_user
             AND session_user='northstar_commands'
             AND role.rolcanlogin
             AND NOT role.rolsuper
             AND NOT role.rolinherit
             AND NOT role.rolcreatedb
             AND NOT role.rolcreaterole
             AND NOT role.rolreplication
             AND NOT role.rolbypassrls
             AND role.rolconnlimit=8
             AND current_schema()='public'
             AND current_schemas(FALSE)=ARRAY['public'::pg_catalog.name]
             AND pg_catalog.pg_get_userbyid(database.datdba)='northstar_migrator'
             AND pg_catalog.pg_get_userbyid(namespace.nspowner)='northstar_migrator'
             AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'CREATE')
             AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'TEMP')
             AND NOT pg_catalog.has_schema_privilege(current_user,namespace.oid,'CREATE')
             AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_class relation
                  WHERE relation.relnamespace=namespace.oid
                    AND relation.relkind IN ('r','p','v','m','f','S')
                    AND (pg_catalog.has_table_privilege(current_user,relation.oid,'SELECT')
                      OR pg_catalog.has_table_privilege(current_user,relation.oid,'INSERT')
                      OR pg_catalog.has_table_privilege(current_user,relation.oid,'UPDATE')
                      OR pg_catalog.has_table_privilege(current_user,relation.oid,'DELETE')
                      OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRUNCATE')
                      OR pg_catalog.has_table_privilege(current_user,relation.oid,'REFERENCES')
                      OR pg_catalog.has_table_privilege(current_user,relation.oid,'TRIGGER')
                      OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'SELECT')
                      OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'INSERT')
                      OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'UPDATE')
                      OR pg_catalog.has_any_column_privilege(current_user,relation.oid,'REFERENCES'))
             )
             AND NOT EXISTS (
                 SELECT 1 FROM resolved allowed
                 LEFT JOIN pg_catalog.pg_proc routine ON routine.oid=allowed.oid
                 WHERE allowed.oid IS NULL
                    OR routine.prokind<>'f'
                    OR NOT routine.prosecdef
                    OR pg_catalog.pg_get_userbyid(routine.proowner)<>'northstar_migrator'
                    OR routine.proconfig IS DISTINCT FROM
                         ARRAY['search_path=pg_catalog, public, pg_temp']::pg_catalog.text[]
                    OR NOT pg_catalog.has_function_privilege(
                         current_user,routine.oid,'EXECUTE')
             )
             AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_proc routine
                 WHERE routine.pronamespace=namespace.oid
                   AND routine.prosecdef
                   AND pg_catalog.has_function_privilege(current_user,routine.oid,'EXECUTE')
                   AND NOT EXISTS (
                     SELECT 1 FROM resolved allowed WHERE allowed.oid=routine.oid
                   )
             )
             AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_auth_members membership
                  WHERE membership.member=role.oid OR membership.roleid=role.oid
             )
          FROM pg_catalog.pg_roles role
          JOIN pg_catalog.pg_database database ON database.datname=current_database()
          JOIN pg_catalog.pg_namespace namespace ON namespace.nspname='public'
         WHERE role.rolname=current_user"#,
    )
    .fetch_one(pool)
    .await
    .context("could not inspect XEP-0133 command PostgreSQL role")?;
    anyhow::ensure!(
        accepted,
        "PostgreSQL command role attestation failed: mount the no-table-access northstar_commands URL with the exact XEP-0133 session capability set"
    );
    Ok(())
}

/// The one-shot migrator owns the database/application schema but must not be
/// a superuser or inherit any other capability-bearing role.
pub async fn attest_migrator_role(pool: &PgPool) -> Result<()> {
    let accepted: bool = sqlx::query_scalar(
        "SELECT role.rolname='northstar_migrator'
             AND session_user=current_user
             AND session_user='northstar_migrator'
             AND role.rolcanlogin
             AND NOT role.rolsuper
             AND NOT role.rolinherit
             AND NOT role.rolcreatedb
             AND NOT role.rolcreaterole
             AND NOT role.rolreplication
             AND NOT role.rolbypassrls
             AND role.rolconnlimit=4
             AND role.rolvaliduntil IS NOT DISTINCT FROM
                  'infinity'::pg_catalog.timestamptz
             AND role.rolconfig IS NULL
             AND current_schema()='public'
             AND current_schemas(FALSE)=ARRAY['public'::pg_catalog.name]
             AND pg_catalog.pg_get_userbyid(database.datdba)='northstar_migrator'
             AND pg_catalog.pg_get_userbyid(namespace.nspowner)='northstar_migrator'
             AND pg_catalog.has_schema_privilege(current_user,namespace.oid,'CREATE')
             AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_auth_members membership
                  WHERE membership.member=role.oid OR membership.roleid=role.oid
             )
          FROM pg_catalog.pg_roles role
          JOIN pg_catalog.pg_database database ON database.datname=current_database()
          JOIN pg_catalog.pg_namespace namespace ON namespace.nspname='public'
         WHERE role.rolname=current_user",
    )
    .fetch_one(pool)
    .await
    .context("could not inspect migrator PostgreSQL role")?;
    anyhow::ensure!(
        accepted,
        "PostgreSQL migrator role attestation failed: migrations require the bounded, non-superuser northstar_migrator owner"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_capability_manifest_is_complete_and_partitioned() {
        let (signatures, workloads) = security_definer_capability_manifest().unwrap();
        assert_eq!(signatures.len(), workloads.len());
        assert!(workloads.iter().any(|workload| workload == "runtime"));
        assert!(workloads.iter().any(|workload| workload == "command"));
        assert!(workloads.iter().any(|workload| workload == "private"));
        assert!(signatures
            .iter()
            .all(|signature| signature.contains('(') && signature.ends_with(')')));
    }

    #[test]
    fn capability_manifest_parser_rejects_sql_bearing_signatures() {
        let malformed = "INSERT INTO pg_temp.northstar_capability_manifest VALUES\n\
            ('safe();drop_table()','runtime','0114');";
        assert!(parse_security_definer_capability_manifest(malformed).is_err());
    }

    #[test]
    fn embedded_migration_ledger_is_complete_and_preserves_intentional_gaps() {
        let manifest = parse_migration_ledger_manifest(MIGRATION_LEDGER_MANIFEST_SQL).unwrap();
        assert_eq!(manifest.versions.len(), manifest.descriptions.len());
        assert_eq!(manifest.versions.len(), manifest.checksum_hex.len());
        assert!(manifest.versions.contains(&113));
        assert!(manifest.versions.contains(&114));
        assert!(manifest.versions.contains(&115));
        assert!(!manifest.versions.contains(&21));
        assert!(manifest
            .checksum_hex
            .iter()
            .all(|checksum| checksum.len() == 96));
    }

    #[test]
    fn migration_ledger_parser_rejects_duplicate_or_malformed_rows() {
        let duplicate = "INSERT INTO pg_temp.northstar_migration_ledger_manifest VALUES\n\
            (1,'one',pg_catalog.decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex')),\n\
            (1,'again',pg_catalog.decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'));";
        assert!(parse_migration_ledger_manifest(duplicate).is_err());
        let short_checksum = "(1,'one',pg_catalog.decode('aa','hex'));";
        assert!(parse_migration_ledger_manifest(short_checksum).is_err());
    }
}
