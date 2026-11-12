//! XMPP adapter of the pubsub context: XEP-0060 PubSub and PEP, XEP-0049 private XML with legacy bookmarks and
//! XEP-0054 vCards, as handlers of client sessions.

#![forbid(unsafe_code)]

pub mod events;
pub mod payload;
pub mod pep;
pub mod private_xml;
mod protocol_session;
pub mod pubsub;
pub mod vcard;

pub use self::protocol_session::{PepHandlers, PrivateXmlHandlers, PubSubHandlers, VCardHandlers};
pub use self::session_host::PubSubSessionHost;

mod session_host;

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
