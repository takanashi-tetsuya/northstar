//! Session core for Northstar XMPP streams: transport-neutral stanza dispatch.
//!
//! Handlers and routers are generic over the session and reply types until
//! those types move into this crate in subsequent stages.

#![forbid(unsafe_code)]

pub mod handler;
pub mod iq;
pub mod local_routes;
pub mod outbound;

/// The largest XMPP frame any transport accepts and any cluster node forwards.
pub const MAX_XMPP_FRAME_BYTES: usize = 1024 * 1024;

pub use handler::{HandlerFuture, IqHandler};
pub use iq::{DuplicateIqRoute, IqKind, IqRequest, IqRoute, IqRouter};
