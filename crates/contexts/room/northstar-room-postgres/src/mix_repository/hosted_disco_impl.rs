use super::*;
use northstar_xmpp_types::jid::CanonicalJid;

impl<E: RoomEffects> MixHostedDiscoRepository for PostgresMixRepository<E> {
    async fn hosted_disco(
        &self,
        address: &MixChannelAddress,
        actor: &CanonicalJid,
    ) -> Result<Option<HostedDiscoView>> {
        crate::mix::hosted_disco::hosted_disco(&self.pool, address, actor).await
    }

    async fn link_created_mix(
        &self,
        channel_id: &MixChannelId,
        owner: &MixRealJid,
        local_domain: &str,
    ) -> Result<MixMucLinkOutcome> {
        Ok(map_mix_muc_link_outcome(
            crate::mix_muc::link_created_mix(&self.pool, channel_id, owner, local_domain).await?,
        ))
    }
}
