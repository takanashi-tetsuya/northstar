use super::{
    MixRelayProfileQuery, MixRelayProfileResult, MixRepository, MixService, PamMembership,
};
use anyhow::Result;
use northstar_room_core::mix::{MixChannelId, MixParticipantId};
use northstar_room_core::mix_iq_relay::{
    RelayPamIncarnation, RelayReturnAuthority, RelayReturnRoute,
};

pub struct RelayProfileSnapshot {
    pub result: MixRelayProfileResult,
    pub channel_incarnation: Option<MixChannelId>,
}

pub trait MixRelayReturnRepository {
    fn relay_profile_with_incarnation(
        &self,
        query: MixRelayProfileQuery,
    ) -> impl std::future::Future<Output = Result<RelayProfileSnapshot>> + Send;
}

impl<R: MixRepository> MixService<R> {
    pub async fn relay_profile_with_incarnation(
        &self,
        query: MixRelayProfileQuery,
    ) -> Result<RelayProfileSnapshot> {
        self.repository.relay_profile_with_incarnation(query).await
    }

    pub async fn relay_return_is_current(&self, authority: &RelayReturnAuthority) -> Result<bool> {
        if let RelayReturnRoute::Local { jid, account, .. } = &authority.exact_route {
            let Some(username) = jid.localpart() else {
                return Ok(false);
            };
            if !self
                .find_enabled_user(username)
                .await?
                .is_some_and(|user| user.id == *account)
            {
                return Ok(false);
            }
            if authority.pam_incarnation.is_some() {
                let current = self
                    .pam_membership(*account, authority.channel.as_str())
                    .await?
                    .as_ref()
                    .map(PamMembership::relay_incarnation)
                    .transpose()?;
                return Ok(authority.accepts_pam(current.as_ref()));
            }
        }
        if authority.channel_incarnation.is_some() {
            let current = self
                .mix_channel(authority.channel.domain(), authority.channel.localpart())
                .await?;
            return Ok(
                authority.matches_channel(current.map(|channel| MixChannelId::new(channel.id)))
            );
        }
        Ok(true)
    }
}

impl PamMembership {
    pub fn relay_incarnation(&self) -> Result<RelayPamIncarnation> {
        Ok(RelayPamIncarnation {
            membership: self.id,
            participant: self
                .participant_id
                .as_deref()
                .map(MixParticipantId::parse_remote)
                .transpose()?,
        })
    }
}
