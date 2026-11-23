use super::{
    MixChannelAddress, MixChannelId, MixMucLinkOutcome, MixRealJid, MixRepository, MixService,
};
use anyhow::Result;
use northstar_room_core::mix::{MixAccessModel, MixAdministratorRetractionRights, MixRole};
use northstar_xmpp_types::jid::CanonicalJid;
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostedDiscoView {
    pub channel_id: MixChannelId,
    pub address: MixChannelAddress,
    pub name: Option<String>,
    pub revision: i64,
    pub discoverable: bool,
    pub access_model: MixAccessModel,
    pub actor_admitted: bool,
    pub visible_to_actor: bool,
    pub actor_role: Option<MixRole>,
    pub allow_user_message_retraction: bool,
    pub administrator_retraction_rights: MixAdministratorRetractionRights,
    pub allow_private_messages: bool,
    pub muc_room_id: Option<Uuid>,
}

pub trait MixHostedDiscoRepository {
    fn hosted_disco(
        &self,
        address: &MixChannelAddress,
        actor: &CanonicalJid,
    ) -> impl Future<Output = Result<Option<HostedDiscoView>>> + Send;

    fn link_created_mix(
        &self,
        channel_id: &MixChannelId,
        owner: &MixRealJid,
        local_domain: &str,
    ) -> impl Future<Output = Result<MixMucLinkOutcome>> + Send;
}

impl<R: MixRepository> MixService<R> {
    pub async fn hosted_disco(
        &self,
        address: &MixChannelAddress,
        actor: &CanonicalJid,
    ) -> Result<Option<HostedDiscoView>> {
        self.repository.hosted_disco(address, actor).await
    }

    pub(crate) async fn link_created_mix(
        &self,
        channel_id: &MixChannelId,
        owner: &MixRealJid,
        local_domain: &str,
    ) -> Result<MixMucLinkOutcome> {
        self.repository
            .link_created_mix(channel_id, owner, local_domain)
            .await
    }
}
