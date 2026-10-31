//! PostgreSQL persistence of the operations context. Functions take the caller's transaction where a use case
//! spans contexts; the transaction itself belongs to a repository or a workflow.

#![forbid(unsafe_code)]

pub mod admin_commands;
pub mod admin_session_cleanup_worker_repository;
pub mod api_control;
pub mod api_mutations;
pub mod api_operations;
pub mod data_lifecycle;
pub mod reports;
pub mod runtime_control_repository;
