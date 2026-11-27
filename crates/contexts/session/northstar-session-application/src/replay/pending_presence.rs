use super::{
    PendingPresenceCursor, PendingPresencePage, PendingPresenceReplay, ReplayRoute, ReplayService,
};
use anyhow::Result;
use std::future::Future;

/// The local selection is only evidence that a durable active lease must exist.
#[derive(Clone, Copy)]
pub struct PendingPresenceAuthority<'a> {
    pub route: &'a ReplayRoute,
    pub expects_active: bool,
}

pub trait PendingPresenceRepository: Send + Sync {
    fn pending_presence_page(
        &self,
        authority: PendingPresenceAuthority<'_>,
        after: Option<&PendingPresenceCursor>,
        domain: &str,
    ) -> impl Future<Output = Result<PendingPresencePage>> + Send;

    fn pending_presence_is_current(
        &self,
        authority: PendingPresenceAuthority<'_>,
        pending: &PendingPresenceReplay,
        domain: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
}

impl<R: PendingPresenceRepository> ReplayService<R> {
    pub async fn pending_presence_page(
        &self,
        authority: PendingPresenceAuthority<'_>,
        after: Option<&PendingPresenceCursor>,
    ) -> Result<PendingPresencePage> {
        self.repository
            .pending_presence_page(authority, after, &self.domain)
            .await
    }

    pub async fn pending_presence_is_current(
        &self,
        authority: PendingPresenceAuthority<'_>,
        pending: &PendingPresenceReplay,
    ) -> Result<bool> {
        self.repository
            .pending_presence_is_current(authority, pending, &self.domain)
            .await
    }
}
