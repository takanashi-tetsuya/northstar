//! This node's local route records and the operations on its live route tables: C2S sessions, MUC occupants and
//! suspended SM endpoints. The composition root owns the tables themselves.

pub(crate) mod muc;
pub(crate) mod muc_table;
pub(crate) mod session;
pub(crate) mod session_table;
pub(crate) mod sm_teardown;
pub(crate) mod suspended_muc;
