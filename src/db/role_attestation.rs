use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::collections::HashSet;
use std::net::IpAddr;

mod catalog;
mod manifests;

use self::catalog::*;
use self::manifests::*;

const CAPABILITY_MANIFEST_SQL: &str =
    include_str!("../../deploy/postgres-init/lib/northstar-capability-manifest.sql");
const RUNTIME_RELATION_MANIFEST_SQL: &str = CAPABILITY_MANIFEST_SQL;
const MIGRATION_LEDGER_MANIFEST_SQL: &str =
    include_str!("../../deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql");
// PostgreSQL's polymorphic `unnest` overload accepts one array at a time.
// Keep independently typed manifest arrays aligned through ordinality instead
// of relying on a non-existent `unnest(int8[], text[], text[])` signature.
const MIGRATION_LEDGER_ATTESTATION_SQL: &str = r#"WITH version_rows AS (
             SELECT version,ordinality
               FROM pg_catalog.unnest($1::pg_catalog.int8[])
                    WITH ORDINALITY AS value(version,ordinality)
           ), description_rows AS (
             SELECT description,ordinality
               FROM pg_catalog.unnest($2::pg_catalog.text[])
                    WITH ORDINALITY AS value(description,ordinality)
           ), checksum_rows AS (
             SELECT checksum_hex,ordinality
               FROM pg_catalog.unnest($3::pg_catalog.text[])
                    WITH ORDINALITY AS value(checksum_hex,ordinality)
           ), expected AS (
             SELECT version,description,checksum_hex
               FROM version_rows
               JOIN description_rows USING(ordinality)
               JOIN checksum_rows USING(ordinality)
           ), actual AS (
             SELECT version,description,success,
                    pg_catalog.encode(checksum,'hex') AS checksum_hex
               FROM public._sqlx_migrations
           )
           SELECT (SELECT pg_catalog.count(*) FROM version_rows)
                  =(SELECT pg_catalog.count(*) FROM description_rows)
             AND (SELECT pg_catalog.count(*) FROM version_rows)
                  =(SELECT pg_catalog.count(*) FROM checksum_rows)
             AND NOT EXISTS (
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
             )"#;

#[derive(Debug, PartialEq, Eq)]
struct MigrationLedgerManifest {
    versions: Vec<i64>,
    descriptions: Vec<String>,
    checksum_hex: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct RuntimeRelationManifest {
    relation_names: Vec<String>,
    can_select: Vec<bool>,
    can_insert: Vec<bool>,
    can_update: Vec<bool>,
    can_delete: Vec<bool>,
    origins: Vec<String>,
}

/// Pure comparison model used by parser fixtures. Runtime attestation reads
/// the compiled ledger through `attest_migration_ledger` instead.
#[cfg(test)]
fn validate_migration_ledger_source(
    expected: &[(i64, String, String)],
    manifest: &MigrationLedgerManifest,
) -> Result<()> {
    anyhow::ensure!(
        expected.len() == manifest.versions.len()
            && expected.len() == manifest.descriptions.len()
            && expected.len() == manifest.checksum_hex.len(),
        "embedded migration ledger does not contain the complete migration set"
    );
    for (
        (version, description, checksum),
        (actual_version, (actual_description, actual_checksum)),
    ) in expected.iter().zip(
        manifest.versions.iter().zip(
            manifest
                .descriptions
                .iter()
                .zip(manifest.checksum_hex.iter()),
        ),
    ) {
        anyhow::ensure!(
            version == actual_version
                && description == actual_description
                && checksum == actual_checksum,
            "embedded migration ledger entry differs from the migration compiled into this binary"
        );
    }
    Ok(())
}

pub(super) fn security_definer_capability_manifest() -> Result<(Vec<String>, Vec<String>)> {
    parse_security_definer_capability_manifest(CAPABILITY_MANIFEST_SQL)
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

/// Verify the development database is local before allowing relaxed roles.
/// The caller must first verify a reserved test domain and loopback listeners.
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
    attest_runtime_relation_capability_manifest(pool).await?;
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
               ('northstar_upload_durable_state_exists()'),
               ('northstar_storage_migration_active()'),
               ('northstar_upload_capacity_lock()'),
               ('northstar_upload_public_slot_count()'),
               ('northstar_upload_dead_letters_page(text,int8,uuid,int4)'),
               ('northstar_upload_retry_dead_letter(uuid,int8,bytea,text,int8,uuid,uuid)'),
       ('northstar_passkey_challenge(uuid,int8,text,bytea,jsonb)'),
               ('northstar_lock_enabled_user_name(uuid,text)'),
               ('northstar_lock_auth_generation(uuid,int8)'),
       ('northstar_passkey_consume(uuid,text,bytea)'),
       ('northstar_passkey_register(uuid,int8,bytea,bytea,jsonb,text)'),
       ('northstar_passkey_accept(uuid,int8,uuid,uuid,jsonb,int8)'),
       ('northstar_passkey_remove(uuid,int8,bytea,uuid)'),
               ('northstar_pending_account_revocations(text,text,uuid,int8,int4)'),
               ('northstar_ack_account_revocations(text,text,uuid,int8,uuid[])'),
               ('northstar_cleanup_account_revocations(int4)'),
               ('northstar_record_direct_spool_wake(text,uuid)'),
               ('northstar_claim_direct_spool_wakes(text,text,uuid,int8,int4)'),
               ('northstar_direct_spool_routes_page(text,text,uuid,int8,uuid,text,int4)'),
               ('northstar_ack_direct_spool_wake_if_empty(text,text,uuid,int8,uuid,uuid,uuid)'),
               ('northstar_defer_direct_spool_wake(text,text,uuid,int8,uuid,uuid,uuid,int4)'),
               ('northstar_cleanup_direct_spool_wakes(int4)'),
               ('northstar_session_delete_expired_live_leases()'),
               ('northstar_session_capacity_reconcile_lock()'),
               ('northstar_session_reserve_live(uuid,uuid,text,int8,bool)'),
               ('northstar_session_finalize_binding(uuid,uuid,text)'),
               ('northstar_session_publish_binding(uuid,uuid,text,int8)'),
               ('northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)'),
               ('northstar_session_release_live(uuid)'),
               ('northstar_session_refresh_live(uuid[],int8)'),
               ('northstar_session_cleanup_live(int8)'),
               ('northstar_session_recovery_retention(uuid,timestamptz)'),
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
               ('northstar_session_capability_catalog_healthy(text)'),
               ('northstar_mix_delivery_capacity_drain()'),
               ('northstar_mix_delivery_capacity_reconcile()'),
               ('northstar_mix_pam_account_capacity_lock(uuid,text)'),
               ('northstar_mix_pam_operation_insert(uuid,uuid,text,text,text,text,text,text,bytea,uuid,bool,text,text,text[],int8,text)'),
               ('northstar_mix_pam_operation_prune(int8)'),
               ('northstar_mix_pam_capacity_reconcile()')
            ), resolved_definer AS (
              SELECT signature,
                     pg_catalog.to_regprocedure('public.' || signature) AS oid
                FROM expected_definer
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
                 SELECT 1 FROM (VALUES
                   ('northstar_protect_admin_session_cleanup_identity()'),
                   ('northstar_enqueue_admin_generation_cleanup(uuid,uuid,int8,text)'),
                   ('northstar_enqueue_admin_exact_session_cleanup(uuid,uuid,int8,text,uuid)'),
                   ('northstar_upload_require_capacity_lock()'),
                   ('guard_upload_capacity_nowait()')
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

/// The upload pool can execute only the owner-held upload capabilities. It
/// has no direct table access, including to its own storage metadata.
pub async fn attest_storage_role(pool: &PgPool) -> Result<()> {
    attest_database_capability_catalog(pool).await?;
    attest_security_definer_capability_acls(pool).await?;
    let (signatures, workloads) = security_definer_capability_manifest()?;
    let expected: Vec<_> = signatures
        .into_iter()
        .zip(workloads)
        .filter_map(|(signature, workload)| (workload == "storage").then_some(signature))
        .collect();
    anyhow::ensure!(
        expected.len() == 37
            && expected
                .iter()
                .all(|signature| signature.starts_with("northstar_upload_")),
        "storage capability manifest must contain only the exact upload function set"
    );
    let accepted: bool = sqlx::query_scalar(
        r#"WITH expected(signature) AS (
             SELECT pg_catalog.unnest($1::pg_catalog.text[])
           ), resolved AS (
             SELECT signature,
                    pg_catalog.to_regprocedure('public.' || signature) AS oid
               FROM expected
           )
           SELECT role.rolname='northstar_storage'
             AND session_user=current_user
             AND session_user='northstar_storage'
             AND role.rolcanlogin
             AND NOT role.rolsuper
             AND NOT role.rolinherit
             AND NOT role.rolcreatedb
             AND NOT role.rolcreaterole
             AND NOT role.rolreplication
             AND NOT role.rolbypassrls
             AND role.rolconnlimit=16
             AND current_schema()='public'
             AND current_schemas(FALSE)=ARRAY['public'::pg_catalog.name]
             AND pg_catalog.pg_get_userbyid(database.datdba)='northstar_migrator'
             AND pg_catalog.pg_get_userbyid(namespace.nspowner)='northstar_migrator'
             AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'CREATE')
             AND NOT pg_catalog.has_database_privilege(current_user,current_database(),'TEMP')
             AND NOT pg_catalog.has_schema_privilege(current_user,namespace.oid,'CREATE')
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
    .bind(&expected)
    .fetch_one(pool)
    .await
    .context("could not inspect upload storage PostgreSQL role")?;
    anyhow::ensure!(
        accepted,
        "PostgreSQL storage role attestation failed: mount the bounded northstar_storage URL with only upload capabilities"
    );
    Ok(())
}

/// Proves that the isolated command login has no relation access and can
/// execute only the eight XEP-0133 session commands and nine REST command
/// capabilities. Neither workload can mint administrative authority through
/// arbitrary table access.
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
               ('northstar_admin_command_cleanup()'),
               ('northstar_admin_tls_reload_admit(uuid,int8,bytea,bytea,bytea,bytea,bytea,bytea,bytea,text,uuid,int8,int8)'),
               ('northstar_admin_tls_reload_rekey(uuid,uuid,int8,bytea,bytea,bytea,bytea,bytea,bytea,text,bytea,bytea)'),
               ('northstar_admin_tls_reload_commit(uuid,uuid,uuid,int8,bytea,uuid,text,bytea,bytea,int8)'),
               ('northstar_admin_panic_disconnect_admit(uuid,int8,bytea,bytea,bytea,bytea,bytea,bytea,bytea,text,uuid,int8,int8)'),
               ('northstar_admin_panic_disconnect_rekey(uuid,uuid,int8,bytea,bytea,bytea,bytea,bytea,bytea,text,bytea,bytea)'),
               ('northstar_admin_panic_disconnect_commit(uuid,uuid,uuid,int8,bytea,uuid,text,bytea,bytea,int8)'),
               ('northstar_admin_registration_admit(uuid,int8,bytea,bytea,bytea,bytea,bytea,bytea,bytea,text,uuid,int8,int8)'),
               ('northstar_admin_registration_rekey(uuid,uuid,int8,bytea,bytea,bytea,bytea,bytea,bytea,text,bytea,bytea)'),
               ('northstar_admin_registration_commit(uuid,uuid,uuid,int8,bytea,bool,text,bytea,bytea,int8)')
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
        "PostgreSQL command role attestation failed: mount the no-table-access northstar_commands URL with the exact administrator capability set"
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
mod tests;
