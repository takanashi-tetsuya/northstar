//! XMPP adapter of the pubsub context: XEP-0060 PubSub and PEP, XEP-0049 private XML with legacy bookmarks and
//! XEP-0054 vCards, as handlers of client sessions.

#![forbid(unsafe_code)]

pub mod payload;

use northstar_pubsub_application::{
    PepAffiliationRepository, PepItemMutationRepository, PepItemQueryRepository,
    PepNodeMutationRepository, PepNodeQueryRepository, PepSubscriptionMutationRepository,
    PepSubscriptionQueryRepository, PubSubAffiliationMutationRepository,
    PubSubAffiliationQueryRepository, PubSubItemMutationRepository, PubSubItemQueryRepository,
    PubSubNodeMutationRepository, PubSubNodeQueryRepository, PubSubRootDiscoveryQueryRepository,
    PubSubSubscriptionMutationRepository, PubSubSubscriptionQueryRepository,
};

/// The repository ports the PubSub and PEP handlers reach through the PubSub service.
pub trait PubSubRepositories:
    PubSubNodeQueryRepository
    + PubSubNodeMutationRepository
    + PubSubRootDiscoveryQueryRepository
    + PubSubItemQueryRepository
    + PubSubItemMutationRepository
    + PubSubSubscriptionQueryRepository
    + PubSubSubscriptionMutationRepository
    + PubSubAffiliationQueryRepository
    + PubSubAffiliationMutationRepository
    + PepNodeQueryRepository
    + PepNodeMutationRepository
    + PepItemQueryRepository
    + PepItemMutationRepository
    + PepSubscriptionQueryRepository
    + PepSubscriptionMutationRepository
    + PepAffiliationRepository
{
}

impl<R> PubSubRepositories for R where
    R: PubSubNodeQueryRepository
        + PubSubNodeMutationRepository
        + PubSubRootDiscoveryQueryRepository
        + PubSubItemQueryRepository
        + PubSubItemMutationRepository
        + PubSubSubscriptionQueryRepository
        + PubSubSubscriptionMutationRepository
        + PubSubAffiliationQueryRepository
        + PubSubAffiliationMutationRepository
        + PepNodeQueryRepository
        + PepNodeMutationRepository
        + PepItemQueryRepository
        + PepItemMutationRepository
        + PepSubscriptionQueryRepository
        + PepSubscriptionMutationRepository
        + PepAffiliationRepository
{
}
