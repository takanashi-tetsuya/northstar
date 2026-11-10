//! What a protocol session needs from the node it runs in.

use super::ProtocolSession;

/// The node a [`ProtocolSession`] runs in. The composition root implements it; the session core reaches the node
/// through it as each part of the core becomes generic over the host.
pub trait SessionHost: Sized {
    /// Finalizes a session dropped without its asynchronous cleanup.
    fn drop_session(session: &mut ProtocolSession<Self>);
}
