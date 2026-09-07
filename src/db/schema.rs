use anyhow::{Context, Result};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::BTreeMap;

/// Catalog-attestation diagnostics are a bounded explanation of a failed
/// authoritative verdict, never a second verdict.  The bounds keep startup
/// errors useful without allowing catalog object names to become an unbounded
/// log or readiness-output channel.
const SESSION_AUTHORITY_DIAGNOSTIC_MAX_ITEMS: usize = 64;
const SESSION_AUTHORITY_DIAGNOSTIC_MAX_BYTES: usize = 16 * 1024;
/// Fetch one additional catalog row as a sentinel. The renderer still exposes
/// at most `MAX_ITEMS`, but the sentinel makes an exact full page distinct
/// from a truncated result without an unbounded catalog read.
const SESSION_AUTHORITY_DIAGNOSTIC_QUERY_LIMIT: i64 =
    SESSION_AUTHORITY_DIAGNOSTIC_MAX_ITEMS as i64 + 1;
const SESSION_AUTHORITY_PRIMARY_FAILURE: &str =
    "session capability ownership, search_path, or runtime ACL attestation failed";

const SESSION_AUTHORITY_FIXED_DIAGNOSTIC_CODES: &[&str] = &[
    "session_schema:missing_or_ambiguous",
    "session_relation:deployment_session_leases:missing_or_owner_mismatch",
    "session_relation:deployment_session_binding_claims:missing_or_owner_mismatch",
    "session_relation:sm_resume_sessions:missing_or_owner_mismatch",
    "session_trigger:deployment_session_leases.deployment_session_leases_capacity_insert:missing_or_binding_mismatch",
    "session_trigger:deployment_session_leases.deployment_session_leases_capacity_delete:missing_or_binding_mismatch",
    "session_trigger:deployment_session_leases.deployment_session_leases_capacity_update:missing_or_binding_mismatch",
    "session_trigger:sm_resume_sessions.sm_resume_sessions_deployment_capacity_insert:missing_or_binding_mismatch",
    "session_trigger:sm_resume_sessions.sm_resume_sessions_deployment_capacity_delete:missing_or_binding_mismatch",
    "session_trigger:sm_resume_sessions.sm_resume_sessions_release_mix_delivery_owners:missing_or_binding_mismatch",
    "session_trigger:sm_resume_sessions.sm_resume_sessions_authority_version:missing_or_binding_mismatch",
    "session_trigger:sm_resume_sessions.sm_resume_sessions_authority_notify:missing_or_binding_mismatch",
    "session_acl:relation_grant_drift",
    "session_acl:column_grant_drift",
    "session_acl:runtime_dml",
    "session_acl:sensitive_sm_read",
    "session_routine:unexpected_security_definer_signature",
    "session_routine:missing_or_binding_or_acl_mismatch",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionAuthorityDiagnosticSummary {
    issues: Vec<String>,
    collection_available: bool,
    truncated: bool,
}

fn known_session_authority_diagnostic(issue: &str) -> Option<&'static str> {
    SESSION_AUTHORITY_FIXED_DIAGNOSTIC_CODES
        .iter()
        .copied()
        .find(|known| *known == issue)
}

fn summarize_session_authority_diagnostics_with_limits(
    raw_issues: std::result::Result<Vec<String>, ()>,
    max_items: usize,
    max_bytes: usize,
) -> SessionAuthorityDiagnosticSummary {
    let Ok(raw_issues) = raw_issues else {
        return SessionAuthorityDiagnosticSummary {
            issues: vec!["session_catalog:diagnostics_unavailable".to_owned()],
            collection_available: false,
            truncated: false,
        };
    };

    let mut issues = Vec::new();
    let mut rendered_bytes = 0usize;
    let mut truncated = false;
    for raw_issue in raw_issues {
        if issues.len() == max_items {
            truncated = true;
            break;
        }
        // The catalog query can name an unexpected trigger.  Object names are
        // database input, so do not expose them verbatim in a startup error:
        // retain the fixed reason code while dropping the untrusted identifier.
        let issue = known_session_authority_diagnostic(&raw_issue)
            .unwrap_or("session_catalog:unexpected_or_unparseable_object");
        let separator_bytes = usize::from(!issues.is_empty());
        if rendered_bytes
            .saturating_add(separator_bytes)
            .saturating_add(issue.len())
            > max_bytes
        {
            truncated = true;
            break;
        }
        rendered_bytes += separator_bytes + issue.len();
        issues.push(issue.to_owned());
    }

    SessionAuthorityDiagnosticSummary {
        issues,
        collection_available: true,
        truncated,
    }
}

fn summarize_session_authority_diagnostics(
    raw_issues: std::result::Result<Vec<String>, ()>,
) -> SessionAuthorityDiagnosticSummary {
    summarize_session_authority_diagnostics_with_limits(
        raw_issues,
        SESSION_AUTHORITY_DIAGNOSTIC_MAX_ITEMS,
        SESSION_AUTHORITY_DIAGNOSTIC_MAX_BYTES,
    )
}

fn session_authority_readiness(verdict: std::result::Result<Option<bool>, ()>) -> bool {
    matches!(verdict, Ok(Some(true)))
}

fn render_session_authority_failure(summary: &SessionAuthorityDiagnosticSummary) -> String {
    let issues = if summary.issues.is_empty() {
        "session_catalog:contract_mismatch".to_owned()
    } else {
        summary.issues.join(",")
    };
    format!(
        "{SESSION_AUTHORITY_PRIMARY_FAILURE}; reconcile database grants before startup; \
         catalog_diagnostics(snapshot=attestation,collection_available={},truncated={}): {issues}",
        summary.collection_available, summary.truncated,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppliedMigration {
    version: i64,
    success: bool,
    checksum: Vec<u8>,
}

fn validate_applied_migrations(
    expected: &[(i64, Vec<u8>)],
    applied: &[AppliedMigration],
) -> Result<()> {
    let expected = expected.iter().cloned().collect::<BTreeMap<_, _>>();
    let mut actual = BTreeMap::new();
    for migration in applied {
        anyhow::ensure!(
            actual.insert(migration.version, migration).is_none(),
            "database migration {} is recorded more than once",
            migration.version
        );
        anyhow::ensure!(
            migration.success,
            "database migration {} is recorded as failed",
            migration.version
        );
    }

    for (version, checksum) in &expected {
        let migration = actual
            .get(version)
            .with_context(|| format!("database migration {version} is pending"))?;
        anyhow::ensure!(
            migration.checksum == *checksum,
            "database migration {version} checksum does not match this binary"
        );
    }
    for version in actual.keys() {
        anyhow::ensure!(
            expected.contains_key(version),
            "database contains migration {version}, which is missing from this binary"
        );
    }
    Ok(())
}

fn required_identity_migrations(domain: &str) -> Vec<(String, i32)> {
    [
        "pubsub-pep-rfc7622-ulabel-v2",
        "authorization-keys-rfc7622-ulabel-v2",
        "push-keys-rfc7622-ulabel-v2",
        "mix-keys-rfc7622-ulabel-v2",
        "profile-pep-item-jids-rfc7622-ulabel-v2",
        "remaining-identity-metadata-rfc7622-ulabel-v2",
    ]
    .into_iter()
    .map(|migration| (migration.to_owned(), 2))
    .chain(std::iter::once((
        format!("session-authorization-rfc7622-ulabel-v2:{domain}"),
        2,
    )))
    .collect()
}

fn validate_identity_migrations(
    required: &[(String, i32)],
    applied: &[(String, i32)],
) -> Result<()> {
    let applied = applied.iter().cloned().collect::<BTreeMap<_, _>>();
    for (migration, version) in required {
        let applied_version = applied
            .get(migration)
            .with_context(|| format!("identity migration {migration} is pending"))?;
        anyhow::ensure!(
            applied_version == version,
            "identity migration {migration} canonicalizer version does not match this binary"
        );
    }
    Ok(())
}

/// Return bounded, catalog-only detail when the strict session authority
/// verifier rejects a schema.  Startup must still fail closed; this merely
/// identifies the affected schema object so fixture and deployment operators
/// can reconcile the right owner, trigger, or fixed search path instead of
/// disabling the verifier.  It deliberately never reads application rows,
/// credentials, JIDs, or session values.
async fn session_authority_attestation_diagnostics(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<String>> {
    sqlx::query_scalar(
        r#"WITH namespace AS (
               SELECT oid,nspowner,current_schema() AS schema_name
                 FROM pg_catalog.pg_namespace
                WHERE nspname=current_schema()
             ), expected_relation(relation_name) AS (
               VALUES ('deployment_session_leases'),
                      ('deployment_session_binding_claims'),
                      ('sm_resume_sessions')
             ), expected_trigger(
               table_name,trigger_name,function_signature,expected_tgtype,security_definer,
               expected_update_columns
             ) AS (
               VALUES
                 ('deployment_session_leases','deployment_session_leases_capacity_insert',
                  'northstar_session_capacity_insert()',5::pg_catalog.int2,FALSE,
                  ARRAY[]::pg_catalog.text[]),
                 ('deployment_session_leases','deployment_session_leases_capacity_delete',
                  'northstar_session_capacity_delete()',9::pg_catalog.int2,FALSE,
                  ARRAY[]::pg_catalog.text[]),
                 ('deployment_session_leases','deployment_session_leases_capacity_update',
                  'northstar_session_capacity_update()',17::pg_catalog.int2,FALSE,
                  ARRAY['lease_id','connection_id','user_id','full_jid']::pg_catalog.text[]),
                 ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_insert',
                  'northstar_sm_capacity_insert()',5::pg_catalog.int2,FALSE,
                  ARRAY[]::pg_catalog.text[]),
                 ('sm_resume_sessions','sm_resume_sessions_deployment_capacity_delete',
                  'northstar_sm_capacity_delete()',9::pg_catalog.int2,FALSE,
                  ARRAY[]::pg_catalog.text[]),
                 ('sm_resume_sessions','sm_resume_sessions_release_mix_delivery_owners',
                  'northstar_release_sm_session_mix_delivery_owners()',11::pg_catalog.int2,FALSE,
                  ARRAY[]::pg_catalog.text[]),
                 ('sm_resume_sessions','sm_resume_sessions_authority_version',
                  'northstar_sm_state_version()',19::pg_catalog.int2,TRUE,
                  ARRAY[]::pg_catalog.text[]),
                 ('sm_resume_sessions','sm_resume_sessions_authority_notify',
                  'northstar_sm_state_notify()',29::pg_catalog.int2,TRUE,
                  ARRAY[]::pg_catalog.text[])
             ), protected_relation AS (
               SELECT relation.oid,relation.relname,relation.relowner,relation.relacl,
                      namespace.nspowner
                 FROM namespace
                 JOIN pg_catalog.pg_class relation ON relation.relnamespace=namespace.oid
                WHERE relation.relname IN (
                        'deployment_session_leases','deployment_session_binding_claims',
                        'sm_resume_sessions'
                      )
                  AND relation.relkind IN ('r','p')
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
             ), protected_routine AS (
               SELECT expected.signature,expected.workload,namespace.schema_name,
                      routine.oid,routine.proowner,
                      routine.prosecdef,routine.prokind,routine.proconfig,routine.proacl,
                      namespace.nspowner
                 FROM namespace CROSS JOIN expected_routine expected
                 LEFT JOIN pg_catalog.pg_proc routine
                   ON routine.oid=pg_catalog.to_regprocedure(
                        pg_catalog.format('%I.',namespace.schema_name)||expected.signature
                      )
                  AND routine.pronamespace=namespace.oid
             ), violations(issue) AS (
               SELECT 'session_schema:missing_or_ambiguous'
                WHERE (SELECT pg_catalog.count(*) FROM namespace)<>1
               UNION ALL
               SELECT 'session_relation:' || expected.relation_name || ':missing_or_owner_mismatch'
                 FROM expected_relation expected
                 CROSS JOIN namespace
                 LEFT JOIN pg_catalog.pg_class relation
                   ON relation.relnamespace=namespace.oid
                  AND relation.relname=expected.relation_name
                  AND relation.relkind IN ('r','p')
                WHERE relation.oid IS NULL OR relation.relowner<>namespace.nspowner
               UNION ALL
               SELECT 'session_trigger:unexpected:' || relation.relname || '.' || trigger.tgname
                 FROM namespace
                 JOIN pg_catalog.pg_class relation ON relation.relnamespace=namespace.oid
                 JOIN pg_catalog.pg_trigger trigger ON trigger.tgrelid=relation.oid
                WHERE relation.relname IN (
                        'deployment_session_leases','sm_resume_sessions'
                      )
                  AND NOT trigger.tgisinternal
                  AND NOT EXISTS (
                    SELECT 1 FROM expected_trigger expected
                     WHERE expected.table_name=relation.relname
                       AND expected.trigger_name=trigger.tgname
                  )
               UNION ALL
               SELECT 'session_trigger:' || expected.table_name || '.' || expected.trigger_name
                      || ':missing_or_binding_mismatch'
                 FROM expected_trigger expected
                 CROSS JOIN namespace
                 LEFT JOIN pg_catalog.pg_class relation
                   ON relation.relnamespace=namespace.oid
                  AND relation.relname=expected.table_name
                  AND relation.relkind IN ('r','p')
                 LEFT JOIN pg_catalog.pg_trigger trigger
                   ON trigger.tgrelid=relation.oid
                  AND trigger.tgname=expected.trigger_name
                  AND NOT trigger.tgisinternal
                 LEFT JOIN pg_catalog.pg_proc routine ON routine.oid=trigger.tgfoid
                WHERE trigger.oid IS NULL
                   OR routine.oid IS DISTINCT FROM pg_catalog.to_regprocedure(
                        pg_catalog.format('%I.',namespace.schema_name)
                        || expected.function_signature
                      )
                   OR trigger.tgtype<>expected.expected_tgtype
                   OR trigger.tgenabled<>'O'
                   OR trigger.tgqual IS NOT NULL
                   OR trigger.tgnargs<>0
                   OR pg_catalog.octet_length(trigger.tgargs)<>0
                   OR trigger.tgconstraint<>0
                   OR trigger.tgdeferrable
                   OR trigger.tginitdeferred
                   OR trigger.tgparentid<>0
                   OR ARRAY(
                        SELECT attribute.attname::pg_catalog.text
                          FROM pg_catalog.unnest(
                                 trigger.tgattr::pg_catalog.int2[]
                               ) WITH ORDINALITY selected(attnum,position)
                          JOIN pg_catalog.pg_attribute attribute
                            ON attribute.attrelid=relation.oid
                           AND attribute.attnum=selected.attnum
                         ORDER BY selected.position
                      ) IS DISTINCT FROM expected.expected_update_columns
                   OR routine.prosecdef<>expected.security_definer
                   OR routine.proowner<>namespace.nspowner
                   OR routine.prokind<>'f'
                   OR routine.prorettype<>'pg_catalog.trigger'::pg_catalog.regtype
                   OR routine.pronargs<>0
                   OR routine.provariadic<>0
                   OR routine.proconfig IS DISTINCT FROM ARRAY[
                        pg_catalog.format(
                          'search_path=pg_catalog, %I, pg_temp',namespace.schema_name
                        )
                      ]::pg_catalog.text[]
               UNION ALL
               SELECT 'session_acl:relation_grant_drift'
                WHERE EXISTS(
                    SELECT 1
                      FROM protected_relation relation
                      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
                        relation.relacl,pg_catalog.acldefault('r',relation.relowner)
                      )) privilege
                     WHERE privilege.grantee<>relation.relowner
                       AND NOT COALESCE(
                         SESSION_USER<>pg_catalog.pg_get_userbyid(relation.nspowner)
                         AND privilege.grantor=relation.relowner
                         AND privilege.privilege_type='SELECT'
                         AND NOT privilege.is_grantable
                         AND (
                           (relation.relname IN (
                             'deployment_session_leases','deployment_session_binding_claims'
                           ) AND privilege.grantee=(
                             SELECT oid FROM pg_catalog.pg_roles
                              WHERE rolname='northstar_runtime'
                           ))
                           OR (relation.relname IN (
                             'deployment_session_leases','deployment_session_binding_claims',
                             'sm_resume_sessions'
                           ) AND privilege.grantee=(
                             SELECT oid FROM pg_catalog.pg_roles
                              WHERE rolname='northstar_backup'
                           ))
                         ),FALSE
                       )
                )
               UNION ALL
               SELECT 'session_acl:column_grant_drift'
                WHERE EXISTS(
                    SELECT 1
                      FROM protected_relation relation
                      JOIN pg_catalog.pg_attribute attribute
                        ON attribute.attrelid=relation.oid
                       AND attribute.attnum>0 AND NOT attribute.attisdropped
                      CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) privilege
                     WHERE privilege.grantee<>relation.relowner
                       AND NOT COALESCE(
                         SESSION_USER<>pg_catalog.pg_get_userbyid(relation.nspowner)
                         AND relation.relname='sm_resume_sessions'
                         AND privilege.grantor=relation.relowner
                         AND privilege.grantee=(
                           SELECT oid FROM pg_catalog.pg_roles
                            WHERE rolname='northstar_runtime'
                         )
                         AND privilege.privilege_type='SELECT'
                         AND NOT privilege.is_grantable
                         AND attribute.attname IN (
                           'id','user_id','auth_generation','full_jid','resource',
                           'connection_id','resume_timeout_seconds','inbound_h',
                           'outbound_h','acked_h','available','carbons','priority',
                           'blocklist_requested','roster_requested','active_privacy_list',
                           'privacy_requested','user_agent_id','joined_rooms',
                           'directed_presence','last_presence','resumable',
                           'live_lease_until','expires_at','claimed_until',
                           'created_at','updated_at'
                         ),FALSE
                       )
                )
               UNION ALL
               SELECT 'session_routine:unexpected_security_definer_signature'
                WHERE EXISTS(
                    SELECT 1
                      FROM namespace
                      JOIN pg_catalog.pg_proc routine ON routine.pronamespace=namespace.oid
                     WHERE routine.prosecdef
                       AND routine.proname IN (
                         SELECT pg_catalog.split_part(expected.signature,'(',1)
                           FROM expected_routine expected
                       )
                       AND routine.oid NOT IN (
                         SELECT candidate.oid FROM protected_routine candidate
                          WHERE candidate.oid IS NOT NULL
                       )
                )
               UNION ALL
               SELECT 'session_routine:missing_or_binding_or_acl_mismatch'
                WHERE EXISTS(
                    SELECT 1 FROM protected_routine routine
                     WHERE routine.oid IS NULL
                        OR routine.proowner<>routine.nspowner
                        OR NOT routine.prosecdef
                        OR routine.prokind<>'f'
                        OR routine.proconfig IS DISTINCT FROM ARRAY[
                             pg_catalog.format(
                               'search_path=pg_catalog, %I, pg_temp',
                               routine.schema_name
                             )
                           ]::pg_catalog.text[]
                        OR (
                          routine.oid IS NOT NULL AND (
                            (SELECT pg_catalog.count(*)
                               FROM pg_catalog.aclexplode(COALESCE(
                                 routine.proacl,
                                 pg_catalog.acldefault('f',routine.proowner)
                               )) privilege)<>CASE
                                   WHEN routine.workload='private'
                                     OR SESSION_USER=pg_catalog.pg_get_userbyid(routine.nspowner)
                                     THEN 1 ELSE 2 END
                            OR EXISTS(
                              SELECT 1
                                FROM pg_catalog.aclexplode(COALESCE(
                                  routine.proacl,
                                  pg_catalog.acldefault('f',routine.proowner)
                                )) privilege
                               WHERE privilege.privilege_type<>'EXECUTE'
                                  OR privilege.is_grantable
                                  OR privilege.grantor<>routine.proowner
                                  OR (privilege.grantee<>routine.proowner AND (
                                    routine.workload='private'
                                    OR SESSION_USER=pg_catalog.pg_get_userbyid(routine.nspowner)
                                    OR privilege.grantee IS DISTINCT FROM (
                                      SELECT oid FROM pg_catalog.pg_roles
                                       WHERE rolname='northstar_runtime'
                                    )
                                  ))
                            )
                            OR NOT EXISTS(
                              SELECT 1
                                FROM pg_catalog.aclexplode(COALESCE(
                                  routine.proacl,
                                  pg_catalog.acldefault('f',routine.proowner)
                                )) privilege
                               WHERE privilege.grantee=routine.proowner
                                 AND privilege.grantor=routine.proowner
                                 AND privilege.privilege_type='EXECUTE'
                                 AND NOT privilege.is_grantable
                            )
                            OR (routine.workload='runtime'
                                AND SESSION_USER<>pg_catalog.pg_get_userbyid(routine.nspowner)
                                AND NOT EXISTS(
                                  SELECT 1
                                    FROM pg_catalog.aclexplode(COALESCE(
                                      routine.proacl,
                                      pg_catalog.acldefault('f',routine.proowner)
                                    )) privilege
                                   WHERE privilege.grantee=(
                                           SELECT oid FROM pg_catalog.pg_roles
                                            WHERE rolname='northstar_runtime'
                                         )
                                     AND privilege.grantor=routine.proowner
                                     AND privilege.privilege_type='EXECUTE'
                                     AND NOT privilege.is_grantable
                                ))
                          )
                        )
                )
               UNION ALL
               SELECT 'session_acl:runtime_dml'
                WHERE EXISTS(
                    SELECT 1 FROM protected_relation relation
                     WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(relation.relowner)
                       AND (
                         pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'INSERT')
                         OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'UPDATE')
                         OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'DELETE')
                         OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRUNCATE')
                         OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'REFERENCES')
                         OR pg_catalog.has_table_privilege(SESSION_USER,relation.oid,'TRIGGER')
                         OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'INSERT')
                         OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'UPDATE')
                         OR pg_catalog.has_any_column_privilege(SESSION_USER,relation.oid,'REFERENCES')
                       )
                )
               UNION ALL
               SELECT 'session_acl:sensitive_sm_read'
                WHERE EXISTS(
                    SELECT 1 FROM namespace
                     WHERE SESSION_USER<>pg_catalog.pg_get_userbyid(namespace.nspowner)
                       AND (
                         pg_catalog.has_column_privilege(
                           SESSION_USER,
                           pg_catalog.format('%I.sm_resume_sessions',namespace.schema_name),
                           'token_hash','SELECT'
                         )
                         OR pg_catalog.has_column_privilege(
                           SESSION_USER,
                           pg_catalog.format('%I.sm_resume_sessions',namespace.schema_name),
                           'claim_token','SELECT'
                         )
                         OR pg_catalog.has_column_privilege(
                           SESSION_USER,
                           pg_catalog.format('%I.sm_resume_sessions',namespace.schema_name),
                           'peer_ip','SELECT'
                         )
                         OR pg_catalog.has_column_privilege(
                           SESSION_USER,
                           pg_catalog.format('%I.sm_resume_sessions',namespace.schema_name),
                           'state_version','SELECT'
                         )
                       )
                )
             )
             SELECT issue FROM violations ORDER BY issue LIMIT $1"#,
    )
    .bind(SESSION_AUTHORITY_DIAGNOSTIC_QUERY_LIMIT)
    .fetch_all(&mut **transaction)
    .await
    .context("could not collect catalog-only session authority diagnostics")
}

/// Verify the SQLx migration ledger without creating or changing any database
/// object. Normal server startup uses this path with the non-owner runtime
/// role; only the explicit `migrate` command may run migrations.
pub async fn verify_schema(pool: &PgPool, domain: &str) -> Result<()> {
    let expected = super::MIGRATOR
        .iter()
        .map(|migration| (migration.version, migration.checksum.to_vec()))
        .collect::<Vec<_>>();
    let mut transaction = pool
        .begin()
        .await
        .context("could not begin read-only schema verification")?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .context("could not enforce read-only schema verification")?;
    // Production connections are pinned to `public` by
    // `pin_public_application_schema`. The explicit loopback-only development
    // escape hatch instead supplies a random isolated schema in its DSN. Keep
    // these verification reads on that already-pinned connection schema so a
    // test process cannot accidentally inspect a different shared schema.
    let rows: Vec<(i64, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version,success,checksum FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut *transaction)
    .await
    .context(
        "could not read the SQLx migration ledger; run `xmpp-server migrate` with the migrator role",
    )?;
    let applied = rows
        .into_iter()
        .map(|(version, success, checksum)| AppliedMigration {
            version,
            success,
            checksum,
        })
        .collect::<Vec<_>>();
    validate_applied_migrations(&expected, &applied)?;

    // These canonicalizers intentionally run after SQLx's DDL migrations. A
    // migrator crash between those phases must not allow a runtime process to
    // start merely because the SQLx ledger is current.
    let identity_rows: Vec<(String, i32)> =
        sqlx::query_as("SELECT migration,canonicalizer_version FROM jid_identity_migrations")
            .fetch_all(&mut *transaction)
            .await
            .context("could not read the RFC 7622 identity-migration ledger")?;
    validate_identity_migrations(&required_identity_migrations(domain), &identity_rows)?;
    let session_authority_healthy: Option<bool> = sqlx::query_scalar(
        "SELECT northstar_session_capability_catalog_healthy(pg_catalog.current_schema())",
    )
    .fetch_one(&mut *transaction)
    .await
    .context("could not attest session capability ownership/ACLs")?;
    if !session_authority_readiness(Ok(session_authority_healthy)) {
        // The health verdict above is the only startup authority.  A failed
        // diagnostic query is deliberately rendered as a fixed secondary
        // status, preserving the original attestation failure and never
        // exposing the database error text or catalog-controlled identifiers.
        let diagnostics = summarize_session_authority_diagnostics(
            session_authority_attestation_diagnostics(&mut transaction)
                .await
                .map_err(|_| ()),
        );
        anyhow::bail!(render_session_authority_failure(&diagnostics));
    }
    transaction
        .commit()
        .await
        .context("could not finish read-only schema verification")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applied(version: i64, checksum: &[u8]) -> AppliedMigration {
        AppliedMigration {
            version,
            success: true,
            checksum: checksum.to_vec(),
        }
    }

    #[test]
    fn exact_schema_is_accepted() {
        validate_applied_migrations(
            &[(1, vec![1]), (2, vec![2])],
            &[applied(1, &[1]), applied(2, &[2])],
        )
        .unwrap();
    }

    #[test]
    fn pending_failed_missing_and_checksum_drift_fail_closed() {
        let expected = [(1, vec![1]), (2, vec![2])];
        assert!(validate_applied_migrations(&expected, &[applied(1, &[1])]).is_err());
        assert!(validate_applied_migrations(
            &expected,
            &[
                applied(1, &[1]),
                AppliedMigration {
                    version: 2,
                    success: false,
                    checksum: vec![2],
                },
            ],
        )
        .is_err());
        assert!(
            validate_applied_migrations(&expected, &[applied(1, &[1]), applied(2, &[9])],).is_err()
        );
        assert!(validate_applied_migrations(
            &[(1, vec![1])],
            &[applied(1, &[1]), applied(2, &[2])],
        )
        .is_err());
    }

    #[test]
    fn duplicate_ledger_versions_fail_closed() {
        assert!(validate_applied_migrations(
            &[(1, vec![1])],
            &[applied(1, &[1]), applied(1, &[1])],
        )
        .is_err());
    }

    #[test]
    fn every_domain_scoped_identity_marker_is_required() {
        let required = required_identity_migrations("example.test");
        assert_eq!(required.len(), 7);
        assert!(required
            .iter()
            .any(|(name, version)| name.ends_with(":example.test") && *version == 2));
        validate_identity_migrations(&required, &required).unwrap();

        let mut incomplete = required.clone();
        incomplete.pop();
        assert!(validate_identity_migrations(&required, &incomplete).is_err());

        let mut stale = required.clone();
        stale[0].1 = 1;
        assert!(validate_identity_migrations(&required, &stale).is_err());
    }

    #[test]
    fn session_authority_diagnostics_accept_a_clean_synthetic_catalog() {
        let summary = summarize_session_authority_diagnostics(Ok(Vec::new()));
        assert!(summary.collection_available);
        assert!(summary.issues.is_empty());
        assert!(!summary.truncated);
        assert!(session_authority_readiness(Ok(Some(true))));
    }

    #[test]
    fn session_authority_diagnostics_keep_an_exact_known_trigger_reason() {
        let summary = summarize_session_authority_diagnostics(Ok(vec![
            "session_trigger:sm_resume_sessions.sm_resume_sessions_release_mix_delivery_owners:missing_or_binding_mismatch".to_owned(),
        ]));
        assert_eq!(
            summary.issues,
            vec![
                "session_trigger:sm_resume_sessions.sm_resume_sessions_release_mix_delivery_owners:missing_or_binding_mismatch"
            ]
        );
        assert!(!session_authority_readiness(Ok(Some(false))));
    }

    #[test]
    fn session_authority_diagnostic_failure_never_replaces_the_primary_failure() {
        let summary = summarize_session_authority_diagnostics(Err(()));
        let rendered = render_session_authority_failure(&summary);
        assert!(rendered.starts_with(SESSION_AUTHORITY_PRIMARY_FAILURE));
        assert!(rendered.contains("session_catalog:diagnostics_unavailable"));
        assert!(!summary.collection_available);
    }

    #[test]
    fn session_authority_diagnostics_do_not_emit_catalog_control_characters() {
        let canary = "unexpected\ntrigger\u{0007}";
        let summary = summarize_session_authority_diagnostics(Ok(vec![format!(
            "session_trigger:unexpected:{canary}"
        )]));
        let rendered = render_session_authority_failure(&summary);
        assert_eq!(
            summary.issues,
            vec!["session_catalog:unexpected_or_unparseable_object"]
        );
        assert!(!rendered.contains(canary));
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\u{0007}'));
    }

    #[test]
    fn session_authority_diagnostics_never_recover_untrusted_canaries() {
        let canary = "synthetic-secret-canary-do-not-log";
        let rendered =
            render_session_authority_failure(&summarize_session_authority_diagnostics(Ok(vec![
                format!("session_trigger:unexpected:{canary}"),
            ])));
        assert!(!rendered.contains(canary));
        assert!(!rendered.contains("synthetic-secret"));
    }

    #[test]
    fn session_authority_diagnostics_are_bounded_and_mark_truncation() {
        let summary = summarize_session_authority_diagnostics_with_limits(
            Ok((0..10)
                .map(|index| format!("session_trigger:unexpected:{index}"))
                .collect()),
            3,
            1_024,
        );
        let rendered = render_session_authority_failure(&summary);
        assert_eq!(summary.issues.len(), 3);
        assert!(summary.truncated);
        assert!(rendered.contains("truncated=true"));
        assert!(rendered.len() <= SESSION_AUTHORITY_PRIMARY_FAILURE.len() + 1_024 + 256);

        let byte_limited = summarize_session_authority_diagnostics_with_limits(
            Ok(vec![
                "session_schema:missing_or_ambiguous".to_owned(),
                "session_relation:deployment_session_leases:missing_or_owner_mismatch".to_owned(),
            ]),
            64,
            40,
        );
        assert_eq!(byte_limited.issues.len(), 1);
        assert!(byte_limited.truncated);
    }

    #[test]
    fn session_authority_diagnostic_sentinel_marks_an_exact_full_rendered_page() {
        assert_eq!(
            SESSION_AUTHORITY_DIAGNOSTIC_QUERY_LIMIT,
            SESSION_AUTHORITY_DIAGNOSTIC_MAX_ITEMS as i64 + 1
        );
        let summary = summarize_session_authority_diagnostics(Ok((0
            ..SESSION_AUTHORITY_DIAGNOSTIC_QUERY_LIMIT)
            .map(|index| format!("session_trigger:unexpected:{index}"))
            .collect()));
        assert_eq!(summary.issues.len(), SESSION_AUTHORITY_DIAGNOSTIC_MAX_ITEMS);
        assert!(
            summary.truncated,
            "the extra query sentinel must be observed"
        );
    }

    #[test]
    fn session_authority_reason_catalog_covers_every_fixed_category() {
        for code in SESSION_AUTHORITY_FIXED_DIAGNOSTIC_CODES {
            assert_eq!(known_session_authority_diagnostic(code), Some(*code));
        }
    }

    #[test]
    fn session_authority_readiness_fails_closed_for_null_missing_and_decode_models() {
        assert!(!session_authority_readiness(Ok(None)));
        assert!(!session_authority_readiness(Ok(Some(false))));
        assert!(!session_authority_readiness(Err(())));
    }
}
