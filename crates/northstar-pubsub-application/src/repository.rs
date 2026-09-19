//! Fine-grained repository port traits for PubSub and PEP domain operations.
//!
//! Decomposed into cohesive, single-responsibility traits:
//! - [`PubSubNodeRepository`]: Node lifecycle, configuration, metadata
//! - [`PubSubItemRepository`]: Item publication, retraction, purging
//! - [`PubSubSubscriptionRepository`]: PubSub subscription management
//! - [`PubSubAffiliationRepository`]: PubSub affiliation management
//! - [`PubSubOutboxRepository`]: PubSub notification delivery persistence
//! - [`PepNodeRepository`]: PEP personal node management
//! - [`PepItemRepository`]: PEP item publication and retraction
//! - [`PepSubscriptionRepository`]: PEP presence subscription hooks
//! - [`PepAffiliationRepository`]: PEP personal affiliations

use anyhow::Result;
use northstar_pubsub_core::{
    CreateNodeOutcome, OwnerMutationOutcome, PepConfigureNodeWrite, PepDeleteNodeWrite,
    PepOwnerMutationOutcome, PepPublishOutcome, PepPublishWrite, PepPurgeNodeWrite,
    PepRetractWrite, PepSetAffiliationsWrite, PepSubscribeOutcome, PepSubscribeWrite,
    PepUnsubscribeOutcome, PepUnsubscribeWrite, PubSubConfigOutcome, PubSubConfigureNodeWrite,
    PubSubCreateNodeWrite, PubSubDeleteNodeWrite, PubSubNodeConfig, PubSubPublishOutcome,
    PubSubPublishWrite, PubSubPurgeNodeWrite, PubSubRetractOutcome, PubSubRetractWrite,
    PubSubSetAffiliationsWrite, PubSubSetSubscriptionsWrite, PubSubSubscribeOutcome,
    PubSubSubscribeWrite, PubSubUnsubscribeOutcome, PubSubUnsubscribeWrite, SetAffiliationsOutcome,
    SetSubscriptionsOutcome,
};
use uuid::Uuid;

/// Repository port for generic PubSub node lifecycle and configuration.
pub trait PubSubNodeRepository: Send + Sync {
    fn get_node_config(
        &self,
        node: &str,
    ) -> impl std::future::Future<Output = Result<Option<PubSubNodeConfig>>> + Send;

    fn create_node(
        &self,
        write: &PubSubCreateNodeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<CreateNodeOutcome>> + Send;

    fn delete_node(
        &self,
        write: &PubSubDeleteNodeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<OwnerMutationOutcome>> + Send;

    fn configure_node(
        &self,
        write: &PubSubConfigureNodeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PubSubConfigOutcome>> + Send;
}

/// Repository port for PubSub item operations.
pub trait PubSubItemRepository: Send + Sync {
    fn publish_items(
        &self,
        write: &PubSubPublishWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PubSubPublishOutcome>> + Send;

    fn retract_items(
        &self,
        write: &PubSubRetractWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PubSubRetractOutcome>> + Send;

    fn purge_node(
        &self,
        write: &PubSubPurgeNodeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<OwnerMutationOutcome>> + Send;
}

/// Repository port for PubSub subscription operations.
pub trait PubSubSubscriptionRepository: Send + Sync {
    fn subscribe(
        &self,
        write: &PubSubSubscribeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PubSubSubscribeOutcome>> + Send;

    fn unsubscribe(
        &self,
        write: &PubSubUnsubscribeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PubSubUnsubscribeOutcome>> + Send;

    fn set_subscriptions(
        &self,
        write: &PubSubSetSubscriptionsWrite<'_>,
    ) -> impl std::future::Future<Output = Result<SetSubscriptionsOutcome>> + Send;
}

/// Repository port for PubSub affiliation operations.
pub trait PubSubAffiliationRepository: Send + Sync {
    fn set_affiliations(
        &self,
        write: &PubSubSetAffiliationsWrite<'_>,
    ) -> impl std::future::Future<Output = Result<SetAffiliationsOutcome>> + Send;
}

/// Repository port for PubSub outbox delivery tracking.
pub trait PubSubOutboxRepository: Send + Sync {
    fn record_outbox(
        &self,
        recipient_jid: &str,
        payload: &str,
    ) -> impl std::future::Future<Output = Result<Uuid>> + Send;
}

/// Repository port for PEP personal node lifecycle operations.
pub trait PepNodeRepository: Send + Sync {
    fn delete_pep_node(
        &self,
        write: &PepDeleteNodeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;

    fn configure_pep_node(
        &self,
        write: &PepConfigureNodeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;

    fn purge_pep_node(
        &self,
        write: &PepPurgeNodeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;
}

/// Repository port for PEP item publication and retraction.
pub trait PepItemRepository: Send + Sync {
    fn publish_pep_items(
        &self,
        write: &PepPublishWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PepPublishOutcome>> + Send;

    fn retract_pep_items(
        &self,
        write: &PepRetractWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;
}

/// Repository port for PEP subscription operations.
pub trait PepSubscriptionRepository: Send + Sync {
    fn subscribe_pep(
        &self,
        write: &PepSubscribeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PepSubscribeOutcome>> + Send;

    fn unsubscribe_pep(
        &self,
        write: &PepUnsubscribeWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PepUnsubscribeOutcome>> + Send;
}

/// Repository port for PEP affiliation operations.
pub trait PepAffiliationRepository: Send + Sync {
    fn set_pep_affiliations(
        &self,
        write: &PepSetAffiliationsWrite<'_>,
    ) -> impl std::future::Future<Output = Result<PepOwnerMutationOutcome>> + Send;
}

/// Aggregate trait combining all fine-grained PubSub and PEP repository capabilities.
pub trait PubSubRepository:
    PubSubNodeRepository
    + PubSubItemRepository
    + PubSubSubscriptionRepository
    + PubSubAffiliationRepository
    + PubSubOutboxRepository
    + PepNodeRepository
    + PepItemRepository
    + PepSubscriptionRepository
    + PepAffiliationRepository
    + Send
    + Sync
{
}

impl<T> PubSubRepository for T where
    T: PubSubNodeRepository
        + PubSubItemRepository
        + PubSubSubscriptionRepository
        + PubSubAffiliationRepository
        + PubSubOutboxRepository
        + PepNodeRepository
        + PepItemRepository
        + PepSubscriptionRepository
        + PepAffiliationRepository
        + Send
        + Sync
{
}
