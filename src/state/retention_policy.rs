//! Retention endpoints receive policy operations and their read timers.
use crate::{
    metrics::Metrics,
    services::retention_policy::{
        RetentionPolicyError, RetentionPolicyRepository, RetentionPolicyService,
        UserRetentionPolicy,
    },
};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct RetentionPolicyContext<R> {
    service: RetentionPolicyService<R>,
    metrics: Arc<Metrics>,
}

impl<R: RetentionPolicyRepository> RetentionPolicyContext<R> {
    pub(super) fn new(service: RetentionPolicyService<R>, metrics: Arc<Metrics>) -> Self {
        Self { service, metrics }
    }

    pub(crate) fn retention_policy_service(&self) -> &RetentionPolicyService<R> {
        &self.service
    }

    pub(crate) async fn user_policy(
        &self,
        token: &str,
    ) -> Result<UserRetentionPolicy, RetentionPolicyError> {
        let _authentication = self.metrics.authentication_duration_seconds.start_timer();
        let _database = self
            .metrics
            .database_operation_duration_seconds
            .start_timer();
        self.service.user_policy(token).await
    }

    pub(crate) async fn muc_policy(
        &self,
        token: &str,
        room_id: Uuid,
    ) -> Result<Option<i32>, RetentionPolicyError> {
        let _authentication = self.metrics.authentication_duration_seconds.start_timer();
        let _database = self
            .metrics
            .database_operation_duration_seconds
            .start_timer();
        self.service.muc_policy(token, room_id).await
    }
}
