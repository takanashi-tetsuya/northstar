//! XEP-0045 multi-user chat for local clients and federated room actors.
//!
//! The handlers stay generic over [`ports`], which the composition root
//! implements until the session, cluster, message and federation contexts own
//! those capabilities.

pub mod discovery;
pub mod federated_muc;
pub mod locked_room_expiry;
pub mod muc;
pub mod ports;
mod protocol_session;
pub mod resume;
pub mod shutdown;
pub mod sm_teardown_projection;
pub use self::protocol_session::MucHandlers;
