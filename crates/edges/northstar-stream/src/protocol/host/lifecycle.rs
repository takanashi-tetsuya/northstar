use crate::protocol::{ProtocolSession, SessionHost};
use std::sync::Arc;

/// Session finalization, cleanup, and worker ownership.
pub trait SessionLifecycleHost: Send + Sync + 'static {
    /// Finalizes a session dropped without its asynchronous cleanup.
    fn drop_session(session: &mut ProtocolSession<Self>)
    where
        Self: SessionHost;
    /// See `ServerNode::worker_registry`.
    fn worker_registry(&self) -> &Arc<northstar_runtime::workers::WorkerRegistry>;
    /// The bounded cleanup service of a session finalization.
    type Cleanup: crate::session_cleanup::SessionCleanup;
    /// The bounded cleanup service of one session finalization.
    fn session_cleanup(self: Arc<Self>) -> Self::Cleanup;
}
