//! Re-admit an outstanding outbound subscribe without changing roster state.

use crate::{PresenceAccount, RosterActor, S2sOutboxPolicy};
use anyhow::Result;
use std::future::Future;

#[derive(Clone, Copy)]
pub enum SubscriptionRetryTarget<'a> {
    Local(&'a PresenceAccount),
    Federated { policy: S2sOutboxPolicy },
}

#[derive(Clone, Copy)]
pub struct SubscriptionRetryRequest<'a> {
    pub actor: &'a RosterActor,
    pub contact: &'a str,
    pub expects_active: bool,
    pub target: SubscriptionRetryTarget<'a>,
}

/// The observed roster row and, for local delivery, its exact pending row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionRetryIdentity {
    pub roster_updated_at_micros: i64,
    pub roster_version: Option<i64>,
    pub local_created_at_micros: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionRetryAdmission {
    Stale,
    Local { created_at_micros: i64 },
    FederatedQueued,
}

pub trait SubscriptionRetryRepository: Send + Sync {
    fn pending_retry_identity(
        &self,
        request: SubscriptionRetryRequest<'_>,
    ) -> impl Future<Output = Result<Option<SubscriptionRetryIdentity>>> + Send;

    fn retry_outbound_subscription(
        &self,
        request: SubscriptionRetryRequest<'_>,
        expected: SubscriptionRetryIdentity,
        minimal_stanza: &str,
    ) -> impl Future<Output = Result<SubscriptionRetryAdmission>> + Send;
}

impl<R: SubscriptionRetryRepository> SubscriptionRetryRepository
    for crate::presence::PresenceService<R>
{
    async fn pending_retry_identity(
        &self,
        request: SubscriptionRetryRequest<'_>,
    ) -> Result<Option<SubscriptionRetryIdentity>> {
        self.repository.pending_retry_identity(request).await
    }

    async fn retry_outbound_subscription(
        &self,
        request: SubscriptionRetryRequest<'_>,
        expected: SubscriptionRetryIdentity,
        minimal_stanza: &str,
    ) -> Result<SubscriptionRetryAdmission> {
        self.repository
            .retry_outbound_subscription(request, expected, minimal_stanza)
            .await
    }
}
