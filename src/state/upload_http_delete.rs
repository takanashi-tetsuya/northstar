//! Authenticated upload deletion can queue an authorized removal and time the request.

use super::{AppState, UploadService};
use crate::metrics::{DurationHistogram, DurationTimer};
use crate::services::upload::UserUploadDeleteOutcome;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct UploadHttpDeleteContext {
    service: Option<UploadService>,
    operation_duration: Arc<DurationHistogram>,
}

impl axum::extract::FromRef<Arc<AppState>> for UploadHttpDeleteContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.upload_service.clone(),
            operation_duration: Arc::clone(&state.metrics.upload_operation_duration_seconds),
        }
    }
}

impl UploadHttpDeleteContext {
    pub(crate) fn operation_timer(&self) -> DurationTimer<'_> {
        self.operation_duration.start_timer()
    }

    pub(crate) async fn delete_authorized(
        &self,
        user_id: Uuid,
        auth_generation: i64,
        session_token: &str,
        upload_id: Uuid,
        request_id: Uuid,
    ) -> anyhow::Result<UserUploadDeleteOutcome> {
        self.service
            .as_ref()
            .expect("upload routes require an enabled or draining storage runtime")
            .delete_authorized(
                user_id,
                auth_generation,
                session_token,
                upload_id,
                request_id,
            )
            .await
    }
}
