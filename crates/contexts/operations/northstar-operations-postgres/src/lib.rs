//! PostgreSQL persistence of the operations context. Functions take the caller's transaction where a use case
//! spans contexts; the transaction itself belongs to a repository or a workflow.

#![forbid(unsafe_code)]

pub mod api_control;
pub mod api_mutations;
pub mod api_operations;
pub mod data_lifecycle;
pub mod reports;
