//! HTTP logout authority; the repository owns the audited session transaction.

use super::AppState;
use crate::{
    db::api_session_repository::PostgresApiSessionRepository,
    services::api_sessions::ApiSessionService,
};
use axum::extract::FromRef;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct ApiSessionHttpContext {
    service: Arc<ApiSessionService<PostgresApiSessionRepository>>,
}

impl FromRef<Arc<AppState>> for ApiSessionHttpContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: Arc::new(state.api_session_service()),
        }
    }
}

impl ApiSessionHttpContext {
    pub(crate) async fn logout(&self, bearer: &str, request_id: Uuid) -> anyhow::Result<()> {
        self.service.logout(bearer, request_id).await
    }
}
