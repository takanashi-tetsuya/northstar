//! HTTP logout authority; the repository owns the audited session transaction.

use crate::repositories::HttpRepositories;
use northstar_auth_application::api_sessions::ApiSessionService;
use std::sync::Arc;
use uuid::Uuid;

pub struct ApiSessionHttpContext<R: HttpRepositories> {
    pub service: Arc<ApiSessionService<R::ApiSessions>>,
}

// A derived Clone would demand that the repository itself be Clone.
impl<R: HttpRepositories> Clone for ApiSessionHttpContext<R> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
        }
    }
}

impl<R: HttpRepositories> ApiSessionHttpContext<R> {
    pub async fn logout(&self, bearer: &str, request_id: Uuid) -> anyhow::Result<()> {
        self.service.logout(bearer, request_id).await
    }
}
