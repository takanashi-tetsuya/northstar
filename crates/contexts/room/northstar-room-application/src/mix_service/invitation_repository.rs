use super::{FederatedMixMutation, MixRepository, MixService};
use anyhow::Result;
use northstar_room_core::mix::{MixChannelAddress, MixChannelId, MixRealJid};
use northstar_time::Duration;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct IssueMixInvitation {
    pub channel: MixChannelAddress,
    pub channel_id: MixChannelId,
    pub inviter: MixRealJid,
    pub invitee: MixRealJid,
}

pub struct PreparedMixInvitationToken {
    id: Uuid,
    secret: String,
}

impl PreparedMixInvitationToken {
    pub fn prepare(mut entropy: impl FnMut() -> Uuid) -> Self {
        Self {
            id: entropy(),
            secret: format!("{}{}", entropy().simple(), entropy().simple()),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.secret.as_bytes()).into()
    }

    pub fn lifetime(&self) -> Duration {
        Duration::hours(1)
    }
}

impl std::fmt::Debug for PreparedMixInvitationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedMixInvitationToken([redacted])")
    }
}

pub trait MixInvitationRepository {
    fn execute_mix_invitation(
        &self,
        command: &IssueMixInvitation,
        token: &PreparedMixInvitationToken,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

impl<R: MixRepository> MixService<R> {
    pub async fn execute_mix_invitation(
        &self,
        command: &IssueMixInvitation,
        token: &PreparedMixInvitationToken,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        self.repository
            .execute_mix_invitation(command, token, federated)
            .await
    }
}

#[cfg(test)]
mod tests;
