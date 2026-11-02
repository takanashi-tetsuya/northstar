//! Session core for Northstar XMPP streams: transport-neutral stanza dispatch.
//!
//! Handlers and routers are generic over the session and reply types until
//! those types move into this crate in subsequent stages.

#![forbid(unsafe_code)]

pub mod auth_publication;
pub mod frame_execution;
pub mod handler;
pub mod host;
pub mod iq;
pub mod local_routes;
pub mod muc_delivery;
pub mod outbound;
pub mod replay;
pub mod resume;
pub mod session;
pub mod transport;

/// The largest XMPP frame any transport accepts and any cluster node forwards.
pub const MAX_XMPP_FRAME_BYTES: usize = 1024 * 1024;

pub use handler::{HandlerFuture, IqHandler};
pub use iq::{DuplicateIqRoute, IqKind, IqRequest, IqRoute, IqRouter};
