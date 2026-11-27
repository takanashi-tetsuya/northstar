use super::*;
use northstar_session_application::replay::pending_presence::{
    PendingPresenceAuthority, PendingPresenceRepository,
};

impl PendingPresenceRepository for PostgresReplayRepository {
    async fn pending_presence_page(
        &self,
        authority: PendingPresenceAuthority<'_>,
        after: Option<&PendingPresenceCursor>,
        domain: &str,
    ) -> Result<PendingPresencePage> {
        crate::replay::pending_presence_replay_page_filtered(&self.pool, authority, domain, after)
            .await
    }

    async fn pending_presence_is_current(
        &self,
        authority: PendingPresenceAuthority<'_>,
        pending: &PendingPresenceReplay,
        domain: &str,
    ) -> Result<bool> {
        crate::replay::pending_presence_is_current(&self.pool, authority, domain, pending).await
    }
}
