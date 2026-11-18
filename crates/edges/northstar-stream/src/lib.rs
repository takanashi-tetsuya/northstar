//! Session core for Northstar XMPP streams: transport-neutral stanza dispatch.
//!
//! Handlers and routers are generic over the session and reply types until
//! those types move into this crate in subsequent stages.

#![forbid(unsafe_code)]

pub mod auth_publication;
pub mod capacity_maintenance;
pub mod caps_effects;
pub mod client_admission;
pub mod frame_execution;
pub mod handler;
pub mod host;
pub mod iq;
pub mod local_routes;
pub mod muc_delivery;
pub use northstar_session_application::outbound;
pub mod protocol;
pub mod replay;
pub mod resume;
pub mod session;
pub mod session_cleanup;
pub mod transport;
pub mod transport_parsing;
pub mod wire;

/// The largest XMPP frame any transport accepts and any cluster node forwards.
pub const MAX_XMPP_FRAME_BYTES: usize = 1024 * 1024;

pub use handler::{HandlerFuture, IqHandler};
pub use iq::{DuplicateIqRoute, IqKind, IqRequest, IqRoute, IqRouter};
