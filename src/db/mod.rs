pub(crate) mod admin_dispatch_repository;
pub(crate) mod admin_mutations;
pub(crate) mod invitation_admin_repository;
pub(crate) mod operation_admin_repository;
pub(crate) mod passkeys;
pub(crate) mod report_moderation_repository;
pub(crate) mod retention_policy_repository;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) mod upload_admin_repository;
use anyhow::{Context, Result};
use sqlx::PgPool;

/// The release migration set is part of the trusted binary. Both the explicit
/// migrator and the runtime checksum verifier use these exact bytes instead of
/// trusting a mutable working-directory `migrations/` tree.
pub(crate) static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub mod abuse_keys;
pub mod account_deletion;
pub mod account_repository;
pub mod account_revocations;
pub mod admin_command_repository;
pub mod admin_commands;
pub mod api_control;
pub mod api_operations;
pub mod api_pages;
pub mod archive;
pub mod authentication;
pub mod authority_listener;
pub mod authorization_identity;
pub mod capacity;
pub(crate) mod capacity_maintenance_repository;
pub mod cluster_keys;
pub mod cluster_muc;
pub mod data_lifecycle;
pub mod fast;
pub mod identity_migration;
pub mod jid_identity;
pub(crate) mod mam;
pub(crate) mod messaging;
#[cfg(test)]
mod migration_upgrade_test;
pub mod mix;
pub mod mix_identity;
pub mod mix_muc;
pub mod mix_repository;
pub mod muc;
pub mod omemo_recovery;
pub mod pep;
pub mod presence_repository;
pub mod privacy;
pub mod private;
pub mod profile;
pub mod profile_identity;
pub mod push;
pub mod push_identity;
pub mod remaining_identity;
pub mod replay;
pub mod replay_repository;
pub mod reports;
pub mod retention;
pub mod retractions;
pub mod role_attestation;
pub(crate) mod room;
pub mod roster;
pub mod s2s;
pub mod schema;
pub mod session_identity;
pub mod sm;
pub mod sm_repository;
pub mod upload;
pub mod upload_admin;
pub mod users;
pub mod vcard;
pub use abuse_keys::*;
pub use account_deletion::*;
pub use admin_commands::*;
pub use api_control::*;
pub use api_operations::*;
pub use api_pages::*;
pub use archive::*;
pub use capacity::*;
pub use cluster_keys::*;
pub use cluster_muc::*;
pub use data_lifecycle::*;
pub use fast::*;
pub use mix::*;
pub use mix_muc::*;
pub use muc::*;
pub use omemo_recovery::*;
pub use pep::*;
pub use privacy::*;
pub use private::*;
pub use push::*;
pub use reports::*;
pub use retention::*;
pub use role_attestation::*;
pub use roster::*;
pub use s2s::*;
pub use schema::*;
pub use sm::*;
pub use upload::*;
pub use upload_admin::*;
pub use users::*;
pub use vcard::*;
pub mod pubsub;
pub mod pubsub_outbox;
pub mod pubsub_repository;
pub use pubsub::*;
pub use pubsub_outbox::*;

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
    mix_identity::canonicalize_mix_identity_storage(pool)
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
        MIGRATOR
            .run(pool)
            .await
            .context("database migration failed")?;
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

pub(crate) mod upload_maintenance;

pub(crate) mod sm_suspension;

pub(crate) mod api_queries;

pub(crate) mod omemo_recovery_repository;

pub(crate) mod api_mutations;

pub(crate) mod report_repository;
