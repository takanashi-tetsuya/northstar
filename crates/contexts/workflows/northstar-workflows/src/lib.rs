//! Transactions that span Northstar's bounded contexts. A workflow owns the transaction and calls each
//! context's persistence functions inside it, so no context's adapter has to name another's.

#![forbid(unsafe_code)]

pub mod account_admin_repository;
pub mod account_deletion;
pub mod account_lifecycle;
pub mod account_repository;
pub mod admin_accounts;
pub mod admin_command_repository;
pub mod admin_dispatch_repository;
pub mod admin_mutations;
pub mod api_pages;
pub mod api_queries;
pub mod governance_repository;
pub mod http_login_repository;
pub mod invitation_admin_repository;
pub mod metrics_snapshot_repository;
pub mod operation_admin_repository;
pub mod operation_muc_destroy_repository;
pub mod password_change_repository;
pub mod report_moderation_repository;
pub mod report_repository;
pub mod retention;
pub mod retention_policy_repository;
pub mod sm_teardown_muc_repository;
pub mod upload_admin_repository;
