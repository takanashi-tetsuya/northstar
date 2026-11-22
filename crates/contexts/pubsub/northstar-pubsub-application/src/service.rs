//! PubSub command validation, mutation admission and publication policy.
use crate::{
    PepItemQueryRepository, PepNodeQueryRepository, PepSubscriptionQueryRepository,
    PubSubAffiliationMutationRepository, PubSubAffiliationQueryRepository,
    PubSubItemMutationRepository, PubSubItemQueryRepository, PubSubMutationAdmission,
    PubSubMutationPermit, PubSubNodeMutationRepository, PubSubNodeQueryRepository,
    PubSubOutboxRepository, PubSubOwnerRead, PubSubOwnerReadKind, PubSubRootDiscoQuery,
    PubSubRootDiscoResult, PubSubRootDiscoveryQueryRepository,
    PubSubSubscriptionMutationRepository, PubSubSubscriptionQueryRepository,
};
use anyhow::Result;
use northstar_pubsub_core::{
    ClaimedPubSubOutboxDelivery, CreateNodeOutcome, DuePubSubDigest, OwnerMutationOutcome, PepItem,
    PepNodeConfig, PepOutboxAuthorizationOutcome, PepPresenceSubscription, PepSubscription,
    PubSubAccount, PubSubAffiliation, PubSubConfigOutcome, PubSubItem, PubSubNode,
    PubSubNodeConfig, PubSubNodeMetadata, PubSubNotificationDelivery, PubSubOutboxDeliveryKind,
    PubSubOutboxFailureDisposition, PubSubOutboxInsert, PubSubOutboxSnapshot, PubSubOutboxSource,
    PubSubSubscription, PubSubSubscriptionOptions, PubSubTimeSources, PublishItemsOutcome,
    RetractItemsOutcome, SetAffiliationsOutcome, SetSubscriptionsOutcome, SubscribeOutcome,
    UnsubscribeOutcome,
};
use northstar_xml_builder::XmlElement;
use std::sync::Arc;
use uuid::Uuid;

#[cfg(test)]
use crate::{
    existing_node_publish_admission_outcome, publish_validation_outcome, AutoCreatePublishOutcome,
    PubSubPublishCommand,
};
#[cfg(test)]
use northstar_pubsub_core::{
    PubSubPublishOutcome, SubscriptionAuthorizationOutcome, SubscriptionOptionsOutcome,
};

mod discovery_queries;
mod generic_owner;
mod generic_publish;
mod generic_subscription;
mod item_queries;
mod outbox;
mod pep_commands;
mod pep_queries;
mod render;
mod repository_access;

pub use render::{
    pubsub_node_config_form, subscription_event_children, CollectionDiscoItems, LeafDiscoItems,
    PubSubEventRenderer,
};
use render::{NS_DATA, NS_PUBSUB_EVENT, SUBSCRIBE_AUTH_FORM};

#[derive(Clone)]
pub struct PubSubService<R> {
    pub(crate) repository: R,
    mutation_admission: Arc<PubSubMutationAdmission>,
    durable_outbox_database_admission:
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
    time: PubSubTimeSources,
}

impl<R> PubSubService<R> {
    pub fn new_with_durable_outbox_database_admission(
        repository: R,
        primary_pool_max_connections: u32,
        durable_outbox_database_admission: northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
    ) -> Self {
        Self {
            repository,
            mutation_admission: Arc::new(PubSubMutationAdmission::new(
                primary_pool_max_connections as usize,
            )),
            durable_outbox_database_admission,
            time: PubSubTimeSources::default(),
        }
    }

    /// Use the supplied clock and UUID source for this service.
    pub fn with_time_sources(mut self, time: PubSubTimeSources) -> Self {
        self.time = time;
        self
    }

    /// Return the clock and UUID source configured for this service.
    pub fn time_sources(&self) -> &PubSubTimeSources {
        &self.time
    }

    pub fn mutation_admission(&self) -> Arc<PubSubMutationAdmission> {
        Arc::clone(&self.mutation_admission)
    }
    async fn admit_mutation(
        &self,
        keys: &[&str],
        collection_graph: bool,
    ) -> Result<PubSubMutationPermit> {
        self.mutation_admission
            .acquire(keys, collection_graph)
            .await
    }
    async fn durable_outbox_database_turn(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.durable_outbox_database_admission.acquire().await
    }
}

#[cfg(test)]
mod tests;
