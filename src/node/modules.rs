//! One module per bounded context: its services and repositories, built once by construction.

pub(in crate::node) mod abuse;
pub(in crate::node) mod archive;
pub(in crate::node) mod auth;
pub(in crate::node) mod federation;
pub(in crate::node) mod message;
pub(in crate::node) mod operations;
pub(in crate::node) mod pubsub;
pub(in crate::node) mod room;
pub(in crate::node) mod roster;
pub(in crate::node) mod runtime;
pub(in crate::node) mod session;
pub(in crate::node) mod upload;
