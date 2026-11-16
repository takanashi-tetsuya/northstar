//! This node's local route records and the operations on its live route tables: C2S sessions, MUC occupants and
//! suspended SM endpoints. The composition root owns the tables themselves.

pub mod admin_sessions;
pub mod muc;
pub mod muc_table;
pub mod push_targets;
pub mod session;
pub mod session_table;
pub mod sm_teardown;
pub mod suspended_muc;
