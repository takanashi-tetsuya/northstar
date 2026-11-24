use super::PushDelivery;
use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

/// Revalidate a claimed subscription immediately before a route queue handoff.
pub trait PushHandoffAuthority: Send + Sync {
    fn validate_handoff(
        &self,
        user_id: Uuid,
        delivery: &PushDelivery,
    ) -> impl Future<Output = Result<bool>> + Send;
}
