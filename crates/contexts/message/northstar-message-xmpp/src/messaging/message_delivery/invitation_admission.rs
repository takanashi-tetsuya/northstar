use super::{message_blocked_error, message_error, MessageHost, MessageOutcome};
use anyhow::Result;
use northstar_message_application::messaging::{
    invitation_admission::{
        DirectInvitation, DirectInvitationGrant, DirectInvitationOutcome, DirectInvitationRefusal,
    },
    PersonalMessageDestination, ValidatedPersonalMessage,
};
use northstar_room_core::{ClusterMucAffiliationSubject, ClusterMucInviteAuthority};
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Node;
use uuid::Uuid;

pub(super) enum GrantDelivery {
    Open,
    Granted {
        live_claim_id: Option<Uuid>,
        wake_operation: bool,
    },
    Replay,
}

pub(super) fn refused<A: MessageOutcome>(
    root: Node<'_, '_>,
    refusal: DirectInvitationRefusal,
) -> A {
    let (kind, condition) = match refusal {
        DirectInvitationRefusal::SenderBlocked => return message_blocked_error(root),
        DirectInvitationRefusal::Unavailable => ("cancel", "service-unavailable"),
        DirectInvitationRefusal::Forbidden => ("auth", "forbidden"),
        DirectInvitationRefusal::Stale => ("cancel", "item-not-found"),
        DirectInvitationRefusal::Conflict => ("cancel", "conflict"),
        DirectInvitationRefusal::Capacity => ("wait", "resource-constraint"),
    };
    message_error(root, kind, condition)
}

fn grant_delivery(
    outcome: DirectInvitationOutcome,
    expected_recipient: Option<Uuid>,
    wake_operation: bool,
) -> std::result::Result<GrantDelivery, DirectInvitationRefusal> {
    match outcome {
        DirectInvitationOutcome::Open { recipient }
            if recipient.as_ref().map(|value| value.id) == expected_recipient =>
        {
            Ok(GrantDelivery::Open)
        }
        DirectInvitationOutcome::Open { .. } => Err(DirectInvitationRefusal::Unavailable),
        DirectInvitationOutcome::GrantRequired { .. } => Err(DirectInvitationRefusal::Stale),
        DirectInvitationOutcome::Granted { live_claim_id } => Ok(GrantDelivery::Granted {
            live_claim_id,
            wake_operation,
        }),
        DirectInvitationOutcome::Replay => Ok(GrantDelivery::Replay),
        DirectInvitationOutcome::Refused(refusal) => Err(refusal),
    }
}

pub(super) struct PreparedGrant<'a> {
    invitation: &'a DirectInvitation<'a>,
    message: &'a ValidatedPersonalMessage<'a>,
    authority: Option<ClusterMucInviteAuthority>,
    recipient: Option<Uuid>,
}

impl PreparedGrant<'_> {
    pub(super) async fn admit(
        &self,
        host: &impl MessageHost,
    ) -> Result<std::result::Result<GrantDelivery, DirectInvitationRefusal>> {
        let outcome = host
            .message_service()
            .admit_direct_invitation(
                self.invitation,
                Some(DirectInvitationGrant {
                    message: self.message,
                    cluster_authority: self.authority.as_ref(),
                }),
            )
            .await?;
        Ok(grant_delivery(
            outcome,
            self.recipient,
            self.authority.is_some(),
        ))
    }
}

pub(super) fn prepare_grant<'a>(
    host: &impl MessageHost,
    invitation: &'a DirectInvitation<'a>,
    revision: (Uuid, i64),
    operation_id: Uuid,
    message: &'a ValidatedPersonalMessage<'a>,
) -> Result<PreparedGrant<'a>> {
    let (subject, expected_recipient) = match message.destination {
        PersonalMessageDestination::Local(delivery) => (
            ClusterMucAffiliationSubject::Local {
                user_id: delivery.recipient_id,
                bare_jid: delivery.recipient_bare_jid.to_owned(),
            },
            Some(delivery.recipient_id),
        ),
        PersonalMessageDestination::Federation(_) => (
            ClusterMucAffiliationSubject::Federated {
                bare_jid: CanonicalJid::parse(invitation.invitee_jid)?.bare(),
            },
            None,
        ),
    };
    let authority = host.direct_muc_invite_cluster_authority(
        operation_id,
        revision.0,
        revision.1,
        invitation.actor_id,
        invitation.actor_jid,
        subject,
    )?;
    Ok(PreparedGrant {
        invitation,
        message,
        authority,
        recipient: expected_recipient,
    })
}

#[cfg(test)]
mod tests;
