//! HTTP logout authority; the repository owns the audited session transaction.

use crate::{
    db::api_session_repository::PostgresApiSessionRepository,
    services::api_sessions::ApiSessionService,
};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct ApiSessionHttpContext {
    pub(crate) service: Arc<ApiSessionService<PostgresApiSessionRepository>>,
}

impl ApiSessionHttpContext {
    pub(crate) async fn logout(&self, bearer: &str, request_id: Uuid) -> anyhow::Result<()> {
        self.service.logout(bearer, request_id).await
    }
}
