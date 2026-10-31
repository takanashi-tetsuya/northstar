//! Complete HTTP session commands. Transport code never owns their transaction.

use anyhow::Result;
use uuid::Uuid;

pub trait ApiSessionRepository: Send + Sync {
    fn logout(
        &self,
        bearer: &str,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

pub struct ApiSessionService<R> {
    repository: R,
}

impl<R: ApiSessionRepository> ApiSessionService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn logout(&self, bearer: &str, request_id: Uuid) -> Result<()> {
        self.repository.logout(bearer, request_id).await
    }
}
