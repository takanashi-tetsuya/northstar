//! This node's local route records: C2S sessions and MUC occupants, including suspended SM endpoints.
//! The composition root owns the live maps and every operation on them.

pub(crate) mod muc;
pub(crate) mod session;
