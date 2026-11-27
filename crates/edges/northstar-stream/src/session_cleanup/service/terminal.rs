use anyhow::Result;
use northstar_session_application::sm_teardown_presence::{
    TerminalPresenceAudience, TerminalPresenceRequest,
};
use std::future::Future;

/// Captures and publishes volatile presence during live finalization.
pub trait TerminalPresenceCleanup: Send + Sync {
    fn capture_terminal_presence(
        &self,
        request: TerminalPresenceRequest<'_>,
    ) -> impl Future<Output = Result<Option<TerminalPresenceAudience>>> + Send;

    fn publish_terminal_presence(
        &self,
        audience: TerminalPresenceAudience,
    ) -> impl Future<Output = Result<()>> + Send;
}
