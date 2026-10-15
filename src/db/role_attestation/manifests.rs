//! Parse embedded manifests and attest the migration ledger, SECURITY DEFINER ACLs, and runtime relation privileges.

use super::*;

pub(super) fn parse_sql_string_literal(source: &str) -> Result<(String, &str)> {
    let source = source
        .strip_prefix('\'')
        .context("manifest value is not a SQL string literal")?;
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
    anyhow::bail!("manifest SQL string literal has no closing quote")
}

pub(super) fn parse_manifest_boolean(source: &str) -> Result<(bool, &str)> {
    if let Some(remainder) = source.strip_prefix("TRUE") {
        Ok((true, remainder))
    } else if let Some(remainder) = source.strip_prefix("FALSE") {
        Ok((false, remainder))
    } else {
        anyhow::bail!("runtime relation manifest privilege is not TRUE or FALSE")
    }
}

pub(super) fn parse_runtime_relation_manifest(source: &str) -> Result<RuntimeRelationManifest> {
    const INSERT_MARKER: &str = "INSERT INTO pg_temp.northstar_runtime_relation_manifest";
    const EXPECTED_COLUMNS: &str =
        "(relation_name,can_select,can_insert,can_update,can_delete,origin)";

    anyhow::ensure!(
        source.matches(INSERT_MARKER).count() == 1,
        "embedded runtime relation manifest has a missing or duplicate INSERT"
    );
    let statement = source
        .split_once(INSERT_MARKER)
        .map(|(_, statement)| statement)
        .context("embedded runtime relation manifest INSERT is absent")?;
    let (columns, values) = statement
        .split_once("VALUES")
        .context("embedded runtime relation manifest has no VALUES clause")?;
    let columns = columns
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    anyhow::ensure!(
        columns == EXPECTED_COLUMNS,
        "embedded runtime relation manifest columns are malformed or reordered"
    );
    let statement_end = values
        .find(';')
        .context("embedded runtime relation manifest INSERT is unterminated")?;
    let rows = &values[..statement_end];

    let mut relation_names = Vec::new();
    let mut can_select = Vec::new();
    let mut can_insert = Vec::new();
    let mut can_update = Vec::new();
    let mut can_delete = Vec::new();
    let mut origins = Vec::new();
    let mut seen = HashSet::new();

    for line in rows.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("--") {
            continue;
        }
        let row = line.trim_end_matches(',');
        let row = row
            .strip_prefix('(')
            .and_then(|row| row.strip_suffix(')'))
            .context("runtime relation manifest row is not a single SQL tuple")?;
        let (relation_name, remainder) = parse_sql_string_literal(row)?;
        let remainder = remainder
            .strip_prefix(',')
            .context("runtime relation manifest relation name is not followed by a comma")?;
        let (select, remainder) = parse_manifest_boolean(remainder)?;
        let remainder = remainder
            .strip_prefix(',')
            .context("runtime relation manifest SELECT flag is not followed by a comma")?;
        let (insert, remainder) = parse_manifest_boolean(remainder)?;
        let remainder = remainder
            .strip_prefix(',')
            .context("runtime relation manifest INSERT flag is not followed by a comma")?;
        let (update, remainder) = parse_manifest_boolean(remainder)?;
        let remainder = remainder
            .strip_prefix(',')
            .context("runtime relation manifest UPDATE flag is not followed by a comma")?;
        let (delete, remainder) = parse_manifest_boolean(remainder)?;
        let remainder = remainder
            .strip_prefix(',')
            .context("runtime relation manifest DELETE flag is not followed by a comma")?;
        let (origin, remainder) = parse_sql_string_literal(remainder)?;
        anyhow::ensure!(
            remainder.is_empty(),
            "runtime relation manifest row contains trailing SQL"
        );

        anyhow::ensure!(
            (1..=63).contains(&relation_name.len())
                && relation_name.bytes().enumerate().all(|(index, byte)| {
                    if index == 0 {
                        byte.is_ascii_lowercase() || byte == b'_'
                    } else {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    }
                }),
            "runtime relation manifest contains an unsafe relation identifier"
        );
        anyhow::ensure!(
            seen.insert(relation_name.clone()),
            "runtime relation manifest contains a duplicate relation"
        );
        anyhow::ensure!(
            origin == "sqlx"
                || (origin.len() == 4
                    && origin.bytes().all(|byte| byte.is_ascii_digit())
                    && origin != "0000"),
            "runtime relation manifest contains an invalid origin"
        );

        relation_names.push(relation_name);
        can_select.push(select);
        can_insert.push(insert);
        can_update.push(update);
        can_delete.push(delete);
        origins.push(origin);
    }

    anyhow::ensure!(
        !relation_names.is_empty()
            && relation_names.len() == can_select.len()
            && relation_names.len() == can_insert.len()
            && relation_names.len() == can_update.len()
            && relation_names.len() == can_delete.len()
            && relation_names.len() == origins.len(),
        "embedded runtime relation manifest is empty or malformed"
    );
    Ok(RuntimeRelationManifest {
        relation_names,
        can_select,
        can_insert,
        can_update,
        can_delete,
        origins,
    })
}

pub(super) fn parse_migration_ledger_manifest(source: &str) -> Result<MigrationLedgerManifest> {
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

pub(super) async fn attest_migration_ledger(pool: &PgPool) -> Result<()> {
    let expected = parse_migration_ledger_manifest(MIGRATION_LEDGER_MANIFEST_SQL)?;
    let accepted: bool = sqlx::query_scalar(MIGRATION_LEDGER_ATTESTATION_SQL)
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

pub(super) fn parse_security_definer_capability_manifest(
    source: &str,
) -> Result<(Vec<String>, Vec<String>)> {
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
        if fields.len() != 3 || !matches!(fields[1], "runtime" | "command" | "storage" | "private")
        {
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

/// Compare the ACL catalog itself with the version-controlled capability
/// manifest. Effective `has_function_privilege` checks are insufficient here:
/// PUBLIC, a retired login, the backup role, a role membership, or a stale
/// overloaded helper could otherwise retain a callable owner-held routine.
pub(super) async fn attest_security_definer_capability_acls(pool: &PgPool) -> Result<()> {
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
                      WHEN 'storage' THEN (SELECT role.oid
                        FROM pg_catalog.pg_roles role
                        WHERE role.rolname='northstar_storage')
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

/// Compare the runtime role's effective table privileges with the same
/// version-controlled manifest used by grant reconciliation. Column ACLs are
/// denied everywhere except for the exact non-secret SM resume projection.
pub(super) async fn attest_runtime_relation_capability_manifest(pool: &PgPool) -> Result<()> {
    let expected = parse_runtime_relation_manifest(RUNTIME_RELATION_MANIFEST_SQL)?;
    debug_assert_eq!(expected.origins.len(), expected.relation_names.len());
    let accepted: bool = sqlx::query_scalar(
        r#"WITH relation_name_rows AS (
             SELECT relation_name,ordinality
               FROM pg_catalog.unnest($1::pg_catalog.text[])
                    WITH ORDINALITY AS value(relation_name,ordinality)
           ), relation_select_rows AS (
             SELECT can_select,ordinality
               FROM pg_catalog.unnest($2::pg_catalog.bool[])
                    WITH ORDINALITY AS value(can_select,ordinality)
           ), relation_insert_rows AS (
             SELECT can_insert,ordinality
               FROM pg_catalog.unnest($3::pg_catalog.bool[])
                    WITH ORDINALITY AS value(can_insert,ordinality)
           ), relation_update_rows AS (
             SELECT can_update,ordinality
               FROM pg_catalog.unnest($4::pg_catalog.bool[])
                    WITH ORDINALITY AS value(can_update,ordinality)
           ), relation_delete_rows AS (
             SELECT can_delete,ordinality
               FROM pg_catalog.unnest($5::pg_catalog.bool[])
                    WITH ORDINALITY AS value(can_delete,ordinality)
           ), expected_relation AS (
             SELECT name.relation_name,selected.can_select,inserted.can_insert,
                    updated.can_update,deleted.can_delete
               FROM relation_name_rows name
               JOIN relation_select_rows selected USING(ordinality)
               JOIN relation_insert_rows inserted USING(ordinality)
               JOIN relation_update_rows updated USING(ordinality)
               JOIN relation_delete_rows deleted USING(ordinality)
           ), namespace AS (
             SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='public'
           ), runtime_role AS (
             SELECT oid FROM pg_catalog.pg_roles WHERE rolname='northstar_runtime'
           ), actual_relation AS (
             SELECT relation.oid,relation.relname,relation.relowner
               FROM namespace
               JOIN pg_catalog.pg_class relation
                 ON relation.relnamespace=namespace.oid
              WHERE relation.relkind IN ('r','p')
                AND NOT EXISTS (
                  SELECT 1 FROM pg_catalog.pg_depend dependency
                   WHERE dependency.classid=
                           'pg_catalog.pg_class'::pg_catalog.regclass
                     AND dependency.objid=relation.oid
                     AND dependency.deptype='e'
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
           )
           SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
             AND (SELECT pg_catalog.count(*)=1 FROM runtime_role)
             AND NOT EXISTS (
               SELECT 1 FROM expected_relation expected
               LEFT JOIN actual_relation relation
                 ON relation.relname=expected.relation_name
                WHERE relation.oid IS NULL
                   OR pg_catalog.has_table_privilege(
                        (SELECT oid FROM runtime_role),relation.oid,'SELECT'
                      ) IS DISTINCT FROM expected.can_select
                   OR pg_catalog.has_table_privilege(
                        (SELECT oid FROM runtime_role),relation.oid,'INSERT'
                      ) IS DISTINCT FROM expected.can_insert
                   OR pg_catalog.has_table_privilege(
                        (SELECT oid FROM runtime_role),relation.oid,'UPDATE'
                      ) IS DISTINCT FROM expected.can_update
                   OR pg_catalog.has_table_privilege(
                        (SELECT oid FROM runtime_role),relation.oid,'DELETE'
                      ) IS DISTINCT FROM expected.can_delete
                   OR pg_catalog.has_table_privilege(
                        (SELECT oid FROM runtime_role),relation.oid,'TRUNCATE')
                   OR pg_catalog.has_table_privilege(
                        (SELECT oid FROM runtime_role),relation.oid,'REFERENCES')
                   OR pg_catalog.has_table_privilege(
                        (SELECT oid FROM runtime_role),relation.oid,'TRIGGER')
             )
             AND NOT EXISTS (
               SELECT 1 FROM actual_relation relation
                WHERE NOT EXISTS (
                  SELECT 1 FROM expected_relation expected
                   WHERE expected.relation_name=relation.relname
                )
             )
             AND NOT EXISTS (
               SELECT 1 FROM actual_relation relation
               JOIN pg_catalog.pg_attribute attribute
                 ON attribute.attrelid=relation.oid
                AND attribute.attnum>0 AND NOT attribute.attisdropped
               CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
                WHERE privilege.grantee<>relation.relowner
                  AND NOT COALESCE(
                    relation.relname='sm_resume_sessions'
                    AND privilege.grantor=relation.relowner
                    AND privilege.grantee=(SELECT oid FROM runtime_role)
                    AND privilege.privilege_type='SELECT'
                    AND NOT privilege.is_grantable
                    AND attribute.attname IN (SELECT attname FROM expected_sm_column),
                    FALSE
                  )
             )
             AND NOT EXISTS (
               SELECT 1 FROM expected_sm_column expected
                WHERE NOT EXISTS (
                  SELECT 1 FROM actual_relation relation
                  JOIN pg_catalog.pg_attribute attribute
                    ON attribute.attrelid=relation.oid
                   AND attribute.attname=expected.attname
                   AND attribute.attnum>0 AND NOT attribute.attisdropped
                  CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
                   WHERE relation.relname='sm_resume_sessions'
                     AND privilege.grantor=relation.relowner
                     AND privilege.grantee=(SELECT oid FROM runtime_role)
                     AND privilege.privilege_type='SELECT'
                     AND NOT privilege.is_grantable
                )
             )"#,
    )
    .bind(&expected.relation_names)
    .bind(&expected.can_select)
    .bind(&expected.can_insert)
    .bind(&expected.can_update)
    .bind(&expected.can_delete)
    .fetch_one(pool)
    .await
    .context("could not attest the PostgreSQL runtime relation capability manifest")?;
    anyhow::ensure!(
        accepted,
        "PostgreSQL runtime relation capability manifest drifted: a public relation, effective table privilege, private column ACL, or exact SM resume projection differs"
    );
    Ok(())
}
