//! What the node provides to the session side of the PubSub context.

use anyhow::Result;
use northstar_pubsub_application::private_storage::{
    PrivateStorageRepository, PrivateStorageService,
};
use northstar_pubsub_application::profile::{
    AvatarPresenceUpdate, ProfileRepository, ProfileService,
};
use northstar_pubsub_core::{PepQuotas, PubSubAccount, PubSubBareJid};
use std::future::Future;
use uuid::Uuid;

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
    /// Refreshes each local session's last presence from the owner's committed avatar.
    fn refresh_avatar_presence(
        &self,
        owner_id: Uuid,
        owner_bare: &PubSubBareJid,
    ) -> impl Future<Output = ()> + Send;
}

pub(super) async fn refresh_changed_avatar<F: Future<Output = ()>>(
    update: AvatarPresenceUpdate,
    owner: &PubSubAccount,
    domain: &str,
    refresh: impl FnOnce(Uuid, PubSubBareJid) -> F,
) -> Result<()> {
    if matches!(update, AvatarPresenceUpdate::Changed(_)) {
        let owner_bare = PubSubBareJid::parse(&format!("{}@{domain}", owner.username))?;
        refresh(owner.id, owner_bare).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn changed_avatar_awaits_refresh_with_the_canonical_owner() {
        let owner = PubSubAccount {
            id: Uuid::from_u128(1),
            username: "Alice".into(),
            auth_generation: 1,
        };
        let expected_owner = PubSubBareJid::parse("alice@example.test").unwrap();
        for (update, expected_calls) in [
            (AvatarPresenceUpdate::Changed(Some("stored-hash".into())), 1),
            (AvatarPresenceUpdate::Changed(None), 1),
            (AvatarPresenceUpdate::Unchanged, 0),
        ] {
            let mut calls = Vec::new();
            let recorded = &mut calls;
            refresh_changed_avatar(update, &owner, "EXAMPLE.TEST", move |id, bare| async move {
                tokio::task::yield_now().await;
                recorded.push((id, bare));
            })
            .await
            .unwrap();
            assert_eq!(
                calls,
                vec![(owner.id, expected_owner.clone()); expected_calls]
            );
        }
    }
}
