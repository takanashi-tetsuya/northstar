//! Complete HTTP session commands. Transport code never owns their transaction.

use anyhow::Result;
use uuid::Uuid;

pub(crate) trait ApiSessionRepository: Send + Sync {
    fn logout(
        &self,
        bearer: &str,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

pub(crate) struct ApiSessionService<R> {
    repository: R,
}

impl<R: ApiSessionRepository> ApiSessionService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn logout(&self, bearer: &str, request_id: Uuid) -> Result<()> {
        self.repository.logout(bearer, request_id).await
    }
}
