use super::{LocalRecipient, MessageRepository, MessageService, ValidatedPersonalMessage};
use anyhow::Result;
use northstar_room_core::ClusterMucInviteAuthority;
use std::future::Future;
use uuid::Uuid;

pub struct DirectInvitation<'a> {
    pub room: &'a str,
    pub actor_id: Uuid,
    pub actor_jid: &'a str,
    pub invitee_jid: &'a str,
    pub local_recipient_name: Option<&'a str>,
    pub active_privacy: Option<&'a str>,
    pub actor: Option<&'a northstar_message_core::AuthenticatedMessageActor>,
}

pub struct DirectInvitationGrant<'a> {
    pub message: &'a ValidatedPersonalMessage<'a>,
    pub cluster_authority: Option<&'a ClusterMucInviteAuthority>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectInvitationRefusal {
    SenderBlocked,
    Unavailable,
    Forbidden,
    Stale,
    Conflict,
    Capacity,
}

#[derive(Debug)]
pub enum DirectInvitationOutcome {
    Open {
        recipient: Option<LocalRecipient>,
    },
    GrantRequired {
        recipient: Option<LocalRecipient>,
        room_epoch: Uuid,
        config_version: i64,
    },
    Granted {
        live_claim_id: Option<Uuid>,
    },
    Replay,
    Refused(DirectInvitationRefusal),
}

pub trait DirectInvitationRepository {
    fn admit_direct_invitation(
        &self,
        invitation: &DirectInvitation<'_>,
        grant: Option<DirectInvitationGrant<'_>>,
    ) -> impl Future<Output = Result<DirectInvitationOutcome>> + Send;
}

impl<R: MessageRepository> MessageService<R> {
    pub async fn admit_direct_invitation(
        &self,
        invitation: &DirectInvitation<'_>,
        grant: Option<DirectInvitationGrant<'_>>,
    ) -> Result<DirectInvitationOutcome> {
        self.repository
            .admit_direct_invitation(invitation, grant)
            .await
    }
}
