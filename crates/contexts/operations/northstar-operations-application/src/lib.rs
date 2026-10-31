//! Application services of the operations context: administrative commands, reports and moderation,
//! governance and retention policy, the operation journal, readiness and metrics snapshots.

#![forbid(unsafe_code)]

pub mod admin_commands;
pub mod admin_dispatch;
pub mod admin_session_cleanup_worker;
pub mod api_queries;
pub mod governance;
pub mod maintenance_repositories;
pub mod metrics_snapshot;
pub mod operation_effect_fence;
pub mod operation_journal_worker;
pub mod operation_muc_destroy;
pub mod operations;
pub mod readiness;
pub mod report_moderation;
pub mod reports;
pub mod retention_policy;
pub mod runtime_control;
pub mod upload_admin;
