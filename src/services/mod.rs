pub(crate) mod account;
pub(crate) mod account_admin;
pub(crate) mod account_revocation_consumer;
pub(crate) mod account_teardown;
pub(crate) mod admin_commands;
pub(crate) mod admin_dispatch;
pub(crate) mod admin_session_cleanup_worker;
pub(crate) mod authentication;
pub(crate) mod background_housekeeping;
pub(crate) mod blocking;
pub(crate) mod capacity_maintenance;
pub(crate) mod challenge_issuance;
pub(crate) mod cluster_authority;
pub(crate) mod cluster_instance_release;
pub(crate) mod cluster_muc_delivery_item;
pub(crate) mod cluster_muc_delivery_read;
pub(crate) mod cluster_muc_outbox_claim;
pub(crate) mod cluster_muc_outbox_housekeeping;
pub(crate) mod cluster_muc_outbox_preclaim;
pub(crate) mod cluster_muc_outbox_settlement;
pub(crate) mod cluster_muc_receipt_claim;
pub(crate) mod cluster_replay_maintenance;
pub(crate) mod cluster_session_route_maintenance;
pub(crate) mod durable_outbox;
pub(crate) mod extdisco;
pub(crate) mod federation_outbox;
pub(crate) mod governance;
pub(crate) mod invitation_admin;
pub(crate) mod locked_muc_expiry;
pub(crate) mod login_abuse;
pub(crate) mod mam;
pub(crate) mod message_admission;
pub(crate) mod messaging;
pub(crate) mod metrics_snapshot;
pub(crate) mod mix;
pub(crate) mod muc;
pub(crate) mod muc_delivery;
pub(crate) mod node_message_contract_verifier;
pub(crate) mod passkeys;
pub(crate) mod password_change;
pub(crate) mod presence;
pub(crate) mod privacy;
pub(crate) mod private_storage;
pub(crate) mod profile;
pub(crate) mod pubsub;
pub(crate) mod push;
pub(crate) mod readiness;
pub(crate) mod replay;
pub(crate) mod report_moderation;
pub(crate) mod retention_policy;
pub(crate) mod retractions;
pub(crate) mod roster;
pub(crate) mod s2s_outbox_dispatch;
pub(crate) mod s2s_roster_authorization;
pub(crate) mod s2s_sm_outbox;
pub(crate) mod session_authority_sweep;
pub(crate) mod session_cleanup;
pub(crate) mod session_termination_authority;
pub(crate) mod sm;
pub(crate) mod sm_capacity;
pub(crate) mod sm_teardown;
pub(crate) mod sm_teardown_muc;
pub(crate) mod sm_teardown_presence;
pub(crate) mod upload;
pub(crate) mod upload_admin;
pub(crate) mod upload_safety;

pub(crate) mod upload_maintenance;

pub(crate) mod sm_suspension;

pub(crate) mod api_queries;

pub(crate) mod omemo_recovery;

pub(crate) mod operation_effect_fence;
pub(crate) mod operation_journal_worker;
pub(crate) mod operation_muc_destroy;
pub(crate) mod operation_muc_wake;
pub(crate) mod operations;

pub(crate) mod api_mutations;

pub(crate) mod api_sessions;
pub(crate) mod http_login;

pub(crate) mod reports;
