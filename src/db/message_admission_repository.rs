//! PostgreSQL-backed adapter for exact rated-message proof admission leases.
use crate::{
    abuse::{AbuseGuard, MessageAdmissionLease, MessageAdmissionRequest, MessageAdmissionStart},
    services::message_admission::MessageAdmissionRepository,
};
use anyhow::Result;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct PostgresMessageAdmissionRepository {
    guard: Arc<AbuseGuard>,
}

impl PostgresMessageAdmissionRepository {
    pub(crate) fn new(guard: Arc<AbuseGuard>) -> Self {
        Self { guard }
    }
}

impl MessageAdmissionRepository for PostgresMessageAdmissionRepository {
    async fn begin(&self, request: &MessageAdmissionRequest<'_>) -> Result<MessageAdmissionStart> {
        self.guard.begin_message_admission(request).await
    }

    async fn accept(&self, lease: &MessageAdmissionLease) -> Result<()> {
        self.guard.accept_message_admission(lease).await
    }
}
