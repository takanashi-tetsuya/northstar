//! Transactions that span Northstar's bounded contexts. A workflow owns the transaction and calls each
//! context's persistence functions inside it, so no context's adapter has to name another's.

#![forbid(unsafe_code)]

pub mod admin_dispatch_repository;
pub mod admin_mutations;
pub mod governance_repository;
pub mod invitation_admin_repository;
pub mod operation_admin_repository;
pub mod report_moderation_repository;
pub mod report_repository;
pub mod upload_admin_repository;
