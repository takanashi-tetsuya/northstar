use crate::mix_service::{
    HostedDiscoView, MixChannelAddress, MixChannelId, MixHostedDiscoRepository, MixMucLinkOutcome,
    MixRealJid,
};
use anyhow::Result;
use northstar_xmpp_types::jid::CanonicalJid;

impl MixHostedDiscoRepository for super::Repository {
    async fn hosted_disco(
        &self,
        _address: &MixChannelAddress,
        _actor: &CanonicalJid,
    ) -> Result<Option<HostedDiscoView>> {
        panic!("unexpected repository call: hosted_disco")
    }

    async fn link_created_mix(
        &self,
        _channel_id: &MixChannelId,
        _owner: &MixRealJid,
        _local_domain: &str,
    ) -> Result<MixMucLinkOutcome> {
        panic!("unexpected repository call: link_created_mix")
    }
}
