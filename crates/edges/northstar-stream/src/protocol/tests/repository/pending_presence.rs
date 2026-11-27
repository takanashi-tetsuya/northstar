use super::UnusedRepository;
use anyhow::Result;
use northstar_session_application::replay::{
    pending_presence::{PendingPresenceAuthority, PendingPresenceRepository},
    PendingPresenceCursor, PendingPresencePage, PendingPresenceReplay,
};

impl PendingPresenceRepository for UnusedRepository {
    async fn pending_presence_page(
        &self,
        _: PendingPresenceAuthority<'_>,
        _: Option<&PendingPresenceCursor>,
        _: &str,
    ) -> Result<PendingPresencePage> {
        panic!("unexpected pending presence page")
    }

    async fn pending_presence_is_current(
        &self,
        _: PendingPresenceAuthority<'_>,
        _: &PendingPresenceReplay,
        _: &str,
    ) -> Result<bool> {
        panic!("unexpected pending presence revalidation")
    }
}
