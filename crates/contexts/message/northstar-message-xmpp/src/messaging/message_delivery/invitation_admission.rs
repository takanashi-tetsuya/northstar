use super::{
    finalize_admission, message_blocked_error, message_error, MessageFrameStage, MessageHost,
    MessageOutcome, MessageSession,
};
use anyhow::Result;
use northstar_abuse_policy::message_admission::MessageAdmissionLease;
use northstar_message_application::messaging::{
    invitation_admission::{
        DirectInvitation, DirectInvitationGrant, DirectInvitationOutcome, DirectInvitationRefusal,
    },
    ArchiveCandidate, IdentityAuthority, LocalDelivery, LocalRecipient, MessageIdentity,
    OutboundPolicyDecision, PersonalMessageDestination, ValidatedPersonalMessage,
};
use northstar_message_core::ActorGenerationFence;
use northstar_room_core::{ClusterMucAffiliationSubject, ClusterMucInviteAuthority};
use northstar_xml_builder::message_policy::add_delay_from;
use northstar_xmpp_types::jid::CanonicalJid;
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;
use std::ops::ControlFlow::{self, Break, Continue};
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

pub(super) async fn check<H: MessageHost, A: MessageOutcome>(
    state: &H,
    root: Node<'_, '_>,
    invitation: &Option<DirectInvitation<'_>>,
) -> Result<ControlFlow<A, Option<DirectInvitationOutcome>>> {
    let invitation_outcome = match invitation {
        Some(invitation) => Some(
            state
                .message_service()
                .admit_direct_invitation(invitation, None)
                .await?,
        ),
        None => None,
    };
    if matches!(
        invitation_outcome,
        Some(DirectInvitationOutcome::Refused(
            DirectInvitationRefusal::Forbidden
        ))
    ) {
        return Ok(Break(refused(root, DirectInvitationRefusal::Forbidden)));
    }
    Ok(Continue(invitation_outcome))
}

pub(super) struct OutboundAuthorization {
    pub(super) invitation_recipient: Option<LocalRecipient>,
    pub(super) grant_revision: Option<(Uuid, i64)>,
}

pub(super) async fn authorize<H: MessageHost, A: MessageOutcome>(
    state: &H,
    root: Node<'_, '_>,
    invitation_outcome: Option<DirectInvitationOutcome>,
    user_id: Uuid,
    from: &str,
    active_privacy: &Option<String>,
    to: &str,
) -> Result<ControlFlow<A, OutboundAuthorization>> {
    // XEP-0191 is account scoped and applies to every outbound stanza,
    // including local service addresses such as MUC and MIX. The service
    // always evaluates that non-overridable rule before XEP-0016.
    let (invitation_recipient, grant_revision) = if let Some(admission) = invitation_outcome {
        match admission {
            DirectInvitationOutcome::Open { recipient } => (recipient, None),
            DirectInvitationOutcome::GrantRequired {
                recipient,
                room_epoch,
                config_version,
            } => (recipient, Some((room_epoch, config_version))),
            DirectInvitationOutcome::Refused(refusal) => {
                return Ok(Break(refused(root, refusal)));
            }
            DirectInvitationOutcome::Granted { .. } | DirectInvitationOutcome::Replay => {
                unreachable!("an invitation without a grant projection cannot grant access")
            }
        }
    } else {
        match state
            .message_service()
            .authorize_outbound_message(user_id, bare_jid(from), active_privacy.as_deref(), to)
            .await?
        {
            OutboundPolicyDecision::Allowed => {}
            OutboundPolicyDecision::Blocked => return Ok(Break(message_blocked_error(root))),
            OutboundPolicyDecision::PrivacyDenied => {
                return Ok(Break(message_error(root, "cancel", "service-unavailable")));
            }
        }
        (None, None)
    };
    Ok(Continue(OutboundAuthorization {
        invitation_recipient,
        grant_revision,
    }))
}

#[expect(
    clippy::too_many_arguments,
    reason = "retain the exact local invitation inputs and outer admission state"
)]
pub(super) async fn commit_local<S: MessageSession>(
    session: &S,
    state: &S::Host,
    root: Node<'_, '_>,
    invitation: &Option<DirectInvitation<'_>>,
    grant_revision: Option<(Uuid, i64)>,
    message_type: &str,
    persistence_allowed: bool,
    exact_full_target_can_route: bool,
    recipient_delivery: &str,
    from: &str,
    origin_id: Option<&str>,
    to: &str,
    rewritten: &str,
    user_id: Uuid,
    local_actor_fence: Option<ActorGenerationFence>,
    candidates: &[ArchiveCandidate<'_>],
    recipient_stable_id: Uuid,
    recipient: &LocalRecipient,
    recipient_by: &str,
    encrypted: bool,
    live_claim_id: &mut Option<Uuid>,
    message_admission_lease: &mut Option<MessageAdmissionLease>,
) -> Result<ControlFlow<S::Action, Option<Uuid>>> {
    let durable_direct_invite = if let (Some(invitation), Some(revision)) =
        (invitation, grant_revision)
    {
        if !matches!(message_type, "normal" | "chat") {
            return Ok(Break(message_error(root, "modify", "bad-request")));
        }
        if !persistence_allowed {
            return Ok(Break(message_error(root, "wait", "service-unavailable")));
        }
        if !exact_full_target_can_route {
            return Ok(Break(message_error(root, "cancel", "service-unavailable")));
        }
        let delayed = add_delay_from(
            recipient_delivery,
            state.message_events().now(),
            Some(bare_jid(from)),
        );
        let identity = origin_id.map(|identity_value| {
            let actor_scope = bare_jid(from);
            MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: actor_scope,
                actor_scope,
                target_scope: bare_jid(to),
                value: identity_value,
                payload: rewritten,
            }
        });
        let grant = ValidatedPersonalMessage {
            local_actor_id: Some(user_id),
            local_actor_fence,
            identity,
            archives: candidates,
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: recipient_stable_id,
                recipient_id: recipient.id,
                recipient_bare_jid: recipient_by,
                sender_jid: from,
                stanza: &delayed,
                encrypted,
            }),
        };
        let grant = prepare_grant(state, invitation, revision, recipient_stable_id, &grant)?;
        session.enter_frame_stage(MessageFrameStage::Admission);
        match grant.admit(state).await? {
            Ok(GrantDelivery::Open) => None,
            Ok(GrantDelivery::Granted {
                live_claim_id: admitted_claim_id,
                wake_operation,
            }) => {
                *live_claim_id = admitted_claim_id;
                if wake_operation {
                    if let Err(error) = state
                        .wake_committed_direct_muc_invite(recipient_stable_id)
                        .await
                    {
                        state.personal_message_telemetry().post_accept_failed();
                        tracing::warn!(?error, %recipient_stable_id, "accepted local direct MUC invite cluster wake failed");
                    }
                }
                finalize_admission(session, message_admission_lease, "local-muc-invite").await;
                Some(recipient_stable_id)
            }
            Ok(GrantDelivery::Replay) => {
                finalize_admission(session, message_admission_lease, "local-muc-invite-replay")
                    .await;
                return Ok(Break(S::Action::none()));
            }
            Err(refusal) => return Ok(Break(refused(root, refusal))),
        }
    } else {
        None
    };
    Ok(Continue(durable_direct_invite))
}

#[cfg(test)]
mod tests;
