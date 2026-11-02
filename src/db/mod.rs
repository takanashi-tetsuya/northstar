#[cfg(test)]
mod operation_muc_destroy_repository_tests;
#[cfg(test)]
pub(crate) mod test_support;
use anyhow::{Context, Result};
use sqlx::PgPool;

mod migration_preflight;

pub(crate) use northstar_postgres::MIGRATOR;

pub(crate) mod abuse_effects;
#[cfg(test)]
mod abuse_guard_tests;
#[cfg(test)]
mod abuse_keys_tests;
#[cfg(test)]
mod account_revocations_tests;
#[cfg(test)]
mod admin_read_authorization_tests;
#[cfg(test)]
mod archive;
pub(crate) mod authentication_effects;
#[cfg(test)]
mod authentication_tests;
pub mod authority_listener;
pub mod authorization_identity;
pub(crate) mod background_housekeeping_repository;
pub mod capacity;
pub(crate) mod capacity_maintenance_repository;
pub(crate) mod cluster_authority_repository;
pub(crate) mod cluster_instance_release_repository;
pub mod cluster_keys;
#[cfg(test)]
mod cluster_muc_tests;
pub(crate) mod cluster_replay_maintenance_repository;
pub(crate) mod cluster_session_route_maintenance_repository;
pub(crate) mod direct_commit_cluster;
#[cfg(test)]
mod direct_spool_wake_repository_tests;
#[cfg(test)]
mod fast_tests;
pub mod identity_migration;
pub mod jid_identity;
pub(crate) mod maintenance_ownership;
#[cfg(test)]
mod message_repository_tests;
#[cfg(test)]
mod migration_upgrade_test;
#[cfg(test)]
mod mix_delivery_capacity_tests;
#[cfg(test)]
mod mix_delivery_route_wake_tests;
#[cfg(test)]
mod mix_identity_tests;
#[cfg(test)]
mod mix_mam_tests;
#[cfg(test)]
mod mix_muc_tests;
#[cfg(test)]
mod mix_pam_durability_tests;
#[cfg(test)]
mod mix_sequence_retention_tests;
#[cfg(test)]
mod muc_service_tests;
#[cfg(test)]
mod muc_tests;
pub(crate) mod node_message_projection_repository;
pub mod omemo_recovery;
#[cfg(test)]
mod passkeys_tests;
pub mod pep_roster;
pub(crate) mod pie;
pub mod presence_repository;
#[cfg(test)]
mod presence_service_tests;
pub mod privacy;
#[cfg(test)]
mod privacy_service_tests;
pub mod profile;
pub mod profile_identity;
pub mod push_identity;
#[cfg(test)]
mod push_tests;
pub(crate) mod readiness_repository;
pub mod remaining_identity;
pub mod replay;
pub mod replay_repository;
pub mod retention;
#[cfg(test)]
mod retraction_service_tests;
pub(crate) mod room_effects;
pub mod roster;
#[cfg(test)]
mod s2s_tests;
pub mod schema;
pub(crate) mod session_authority_sweep_repository;
pub mod session_identity;
pub(crate) mod session_termination_authority_repository;
pub mod sm;
pub mod sm_repository;
pub(crate) mod sm_teardown_presence_repository;
pub(crate) mod sm_teardown_repository;
#[cfg(test)]
pub use archive::*;
pub use capacity::*;
pub use cluster_keys::*;
pub use omemo_recovery::*;
pub use pep_roster::*;
pub use privacy::*;
pub use roster::*;
pub use schema::*;
pub use sm::*;
#[cfg(test)]
mod pubsub_integration_tests;
pub mod pubsub_repository;
pub use northstar_pubsub_postgres::*;

#[cfg(test)]
pub async fn migrate(pool: &PgPool) -> Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .context("database migration failed")?;
    jid_identity::canonicalize_identity_storage(pool)
        .await
        .context("RFC 7622 PubSub/PEP identity migration failed")?;
    authorization_identity::canonicalize_authorization_identity_storage(pool)
        .await
        .context("RFC 7622 authorization JID identity migration failed")?;
    push_identity::canonicalize_push_identity_storage(pool)
        .await
        .context("RFC 7622 push service JID identity migration failed")?;
    northstar_room_postgres::mix_identity::canonicalize_mix_identity_storage(pool)
        .await
        .context("RFC 7622 MIX JID identity migration failed")?;
    profile_identity::canonicalize_profile_identity_storage(pool)
        .await
        .context("RFC 7622 profile PEP ItemID migration failed")
}

pub async fn migrate_for_domain(pool: &PgPool, domain: &str) -> Result<()> {
    // Serialize DDL/identity migration with privilege reconciliation. The
    // dedicated pooled connection holds this session lock while SQLx uses the
    // remaining migrator connection; the production migrator pool is bounded
    // to two connections and the role itself to four.
    let mut policy_lock = pool
        .acquire()
        .await
        .context("could not acquire the database policy migration lock connection")?;
    sqlx::query(
        "SELECT pg_catalog.pg_advisory_lock(
           pg_catalog.hashtextextended('northstar-database-role-policy-v1',0)
         )",
    )
    .execute(&mut *policy_lock)
    .await
    .context("could not acquire the database policy migration lock")?;

    let migration_result = async {
        // Keep admission and SQLx on the same session: a pool connection's
        // search_path or CURRENT_USER must not differ between the check and
        // its DDL. Release this second connection before canonicalization,
        // which also uses the bounded migrator pool.
        {
            let mut migration_connection = pool
                .acquire()
                .await
                .context("could not acquire the database migration connection")?;
            migration_preflight::attest_schema_owner(&mut migration_connection).await?;
            MIGRATOR
                .run(&mut *migration_connection)
                .await
                .context("database migration failed")?;
        }
        identity_migration::canonicalize_all_identity_storage(pool, domain)
            .await
            .context("atomic RFC 7622 A-label to U-label identity migration failed")
    }
    .await;
    let unlock_result = sqlx::query_scalar::<_, bool>(
        "SELECT pg_catalog.pg_advisory_unlock(
           pg_catalog.hashtextextended('northstar-database-role-policy-v1',0)
         )",
    )
    .fetch_one(&mut *policy_lock)
    .await
    .context("could not release the database policy migration lock")
    .and_then(|unlocked| {
        anyhow::ensure!(
            unlocked,
            "database policy migration lock ownership was lost"
        );
        Ok(())
    });

    match (migration_result, unlock_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

pub(crate) mod muc_delivery_repository;
#[cfg(test)]
mod upload_account_tests;
#[cfg(test)]
mod upload_admin_tests;

pub(crate) mod sm_suspension;

pub(crate) mod omemo_recovery_repository;

#[cfg(test)]
mod account_admin_repository_tests;
#[cfg(test)]
mod account_deletion_tests;
#[cfg(test)]
mod account_repository_registration_guard_tests;
#[cfg(test)]
mod admin_command_sessions_tests;
#[cfg(test)]
mod admin_commands_boundary_tests;
#[cfg(test)]
mod admin_dispatch_repository_tests;
#[cfg(test)]
mod api_control_tests;
#[cfg(test)]
mod api_operations_tests;
#[cfg(test)]
mod api_pages_tests;
#[cfg(test)]
mod api_queries_tests;
#[cfg(test)]
mod data_lifecycle_tests;
#[cfg(test)]
mod governance_repository_tests;
#[cfg(test)]
mod invitation_admin_repository_tests;
#[cfg(test)]
mod operation_journal_worker_repository_tests;
#[cfg(test)]
mod password_change_repository_tests;
#[cfg(test)]
mod report_moderation_repository_tests;
#[cfg(test)]
mod reports_tests;
#[cfg(test)]
mod retention_policy_repository_tests;
#[cfg(test)]
mod retention_tests;
#[cfg(test)]
mod users_tests;
