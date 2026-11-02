#[cfg(test)]
mod operation_muc_destroy_repository_tests;
#[cfg(test)]
pub(crate) mod test_support;

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
pub(crate) mod background_housekeeping_repository;
#[cfg(test)]
mod cluster_muc_tests;
pub(crate) mod cluster_replay_maintenance_repository;
pub(crate) mod cluster_session_route_maintenance_repository;
pub(crate) mod direct_commit_cluster;
#[cfg(test)]
mod direct_spool_wake_repository_tests;
#[cfg(test)]
mod fast_tests;
pub(crate) mod maintenance_ownership;
#[cfg(test)]
mod message_repository_tests;
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
#[cfg(test)]
mod passkeys_tests;
// src/cluster/listener_policy.rs (S29) still names the presence repository through db::.
pub(crate) mod presence_repository {
    pub(crate) use northstar_workflows::presence_repository::PostgresPresenceRepository;
}
#[cfg(test)]
mod presence_service_tests;
#[cfg(test)]
mod privacy;
#[cfg(test)]
mod privacy_service_tests;
#[cfg(test)]
mod push_tests;
pub(crate) mod readiness_repository;
#[cfg(test)]
mod retraction_service_tests;
pub(crate) mod room_effects;
pub(crate) mod session_authority_sweep_repository;
pub(crate) mod session_termination_authority_repository;
pub mod sm;
pub mod sm_repository;
pub(crate) mod sm_teardown_presence_repository;
pub(crate) mod sm_teardown_repository;
#[cfg(test)]
pub use archive::*;
// Roster and privacy names that paths owned by the mainline (src/s2s, src/cluster, src/db/sm*)
// still reach through db::. Every other consumer imports the owning crate.
pub(crate) use northstar_roster_postgres::privacy::{
    privacy_denies, set_active_privacy_list_in_transaction,
};
#[cfg(test)]
pub(crate) use northstar_roster_postgres::roster::add_federated_presence_pending_with_stanza;
pub(crate) use northstar_roster_postgres::roster::{is_blocked_for_account, roster};
pub(crate) use northstar_xep_0016::PrivacyStanzaKind;
pub use sm::*;
#[cfg(test)]
mod pubsub_integration_tests;
pub use northstar_pubsub_postgres::*;

#[cfg(test)]
pub async fn migrate(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    northstar_workflows::identity_migration::migrate_for_tests(pool).await
}

pub(crate) mod muc_delivery_repository;
#[cfg(test)]
mod upload_account_tests;
#[cfg(test)]
mod upload_admin_tests;

pub(crate) mod sm_suspension;

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
mod sm_service_tests;
#[cfg(test)]
mod users_tests;
