//! Repository port traits for Federation outbox persistence and delivery lifecycle.

use northstar_federation_core::FederationDeliveryMode;
use uuid::Uuid;

pub type FederationRepoResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Staged outbound federation item to record or claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationOutboxItem {
    pub target_domain: String,
    pub stanza: String,
    pub bounce_to: Option<String>,
    pub delivery_mode: FederationDeliveryMode,
}

/// Repository port for durable S2S federation outbox queues.
pub trait FederationOutboxRepository: Send + Sync {
    /// Enqueue a message to the durable outbox queue.
    fn enqueue(
        &self,
        item: &FederationOutboxItem,
    ) -> impl std::future::Future<Output = FederationRepoResult<Uuid>> + Send;

    /// Claim up to `limit` pending outbox entries using a worker `lock_token`.
    fn claim_pending(
        &self,
        lock_token: Uuid,
        limit: usize,
    ) -> impl std::future::Future<Output = FederationRepoResult<Vec<Uuid>>> + Send;

    /// Acknowledge successful delivery and remove from outbox.
    fn acknowledge(
        &self,
        outbox_id: Uuid,
        lock_token: Uuid,
    ) -> impl std::future::Future<Output = FederationRepoResult<()>> + Send;

    /// Fail or release a delivery attempt with exponential backoff or dead-letter.
    fn release(
        &self,
        outbox_id: Uuid,
        lock_token: Uuid,
        error_message: &str,
    ) -> impl std::future::Future<Output = FederationRepoResult<()>> + Send;
}
