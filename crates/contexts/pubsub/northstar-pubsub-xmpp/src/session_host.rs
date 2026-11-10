//! What the node provides to the session side of the PubSub context.

use northstar_pubsub_application::private_storage::{
    PrivateStorageRepository, PrivateStorageService,
};
use northstar_pubsub_application::profile::{ProfileRepository, ProfileService};
use northstar_pubsub_core::PepQuotas;

/// What the node provides to the vCard, PEP and private XML handlers of a client session, beyond the PubSub
/// service and PEP fan-out hosts. The composition root implements it.
pub trait PubSubSessionHost:
    crate::pubsub::PubSubHost + crate::pep::PepAudienceRouting + Send + Sync
{
    /// The PEP node and storage quotas of one account.
    fn pep_account_quotas(&self) -> PepQuotas;
    /// The profile service, over the repository the composition root binds.
    fn profile_service(&self) -> &ProfileService<impl ProfileRepository>;
    /// The private XML storage service, over the repository the composition root binds.
    fn private_storage_service(&self) -> &PrivateStorageService<impl PrivateStorageRepository>;
    /// Counts `count` published PEP items.
    fn pep_record_published(&self, count: u64);
    /// Counts `count` retracted PEP items.
    fn pep_record_retracted(&self, count: u64);
    /// Counts one PEP retrieval.
    fn pep_record_retrieved(&self);
    /// Puts the new avatar hash (or none) into the last presence of every local session of `owner_bare`.
    fn refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>);
}
