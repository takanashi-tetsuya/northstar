//! The node's implementations of the host traits the protocol crates are generic over.

pub(in crate::node) mod archive_session;
pub(in crate::node) mod bosh;
pub(in crate::node) mod c2s;
pub(in crate::node) mod discovery;
pub(crate) mod http;
pub(in crate::node) mod iq_route;
pub(in crate::node) mod message;
pub(in crate::node) mod mix;
pub(in crate::node) mod muc;
pub(in crate::node) mod muc_resume;
pub(in crate::node) mod operations_session;
pub(in crate::node) mod pubsub_session;
pub(crate) mod roster_session;
pub(in crate::node) mod s2s;
pub(in crate::node) mod s2s_inbound;
pub(in crate::node) mod session;
pub(in crate::node) mod upload_session;
