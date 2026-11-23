use super::*;
use crate::iq_parse::{remote_pam_join_stanza, JoinData};
use northstar_room_application::mix_service::{HostedMixOutcome, RemotePamJoinOptions};
use northstar_room_core::mix::{MixChannelAddress, MixChannelId, MixRealJid};

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_pam_join(
    session: &impl MixSession,
    request_id: &str,
    user_id: Uuid,
    _username: &str,
    actor_bare: &str,
    full_jid: &str,
    request_digest: [u8; 32],
    channel: String,
    join: JoinData,
) -> Result<MixAction> {
    let channel_address = match CanonicalJid::parse_bare(&channel) {
        Ok(channel) if channel.localpart().is_some() => channel,
        _ => {
            return Ok(MixAction::Send(iq_error_to(
                request_id,
                actor_bare,
                full_jid,
                "modify",
                "jid-malformed",
            )));
        }
    };
    let channel = channel_address.to_string();
    let domain = channel_address.domainpart();
    if domain == mix_domain(session) {
        let channel_localpart = channel_address
            .localpart()
            .expect("MIX channel localpart was checked above");
        let Some(mix_channel) = session
            .host()
            .mix_service()
            .mix_channel(domain, channel_localpart)
            .await?
        else {
            return Ok(MixAction::Send(iq_error_to(
                request_id,
                actor_bare,
                full_jid,
                "cancel",
                "item-not-found",
            )));
        };
        let committed = match session
            .host()
            .mix_service()
            .join_hosted_mix_committed(
                &MixChannelId::new(mix_channel.id),
                JoinMixRequest {
                    actor_jid: actor_bare.to_owned(),
                    nick: join.nick.clone(),
                    nodes: join.nodes.clone(),
                    pam_user_id: Some(user_id),
                    invitation: join.invitation.clone(),
                    preference: join.preference.clone(),
                    anonymous_profile: join.anonymous_profile,
                },
                None,
            )
            .await?
        {
            HostedMixOutcome::Present(committed) => committed,
            HostedMixOutcome::MissingChannel => {
                return Ok(MixAction::Send(iq_error_to(
                    request_id,
                    actor_bare,
                    full_jid,
                    "cancel",
                    "item-not-found",
                )));
            }
        };
        match committed.outcome {
            JoinChannelOutcome::Joined {
                participant,
                preference,
                subscriptions,
                newly_joined: _,
                roster_change: _,
            } => {
                for delta in &committed.roster {
                    push_mix_roster_update(session.host(), delta).await?;
                }
                let payload = XmlElement::namespaced("client-join", PAM_NS)
                    .validated_fragment(&pam_join_payload(
                        &channel,
                        &participant,
                        &subscriptions,
                        join.preference.as_ref().map(|_| &preference),
                        join.anonymous_profile,
                    )?)?
                    .finish();
                Ok(MixAction::Send(iq_result_to(
                    request_id, actor_bare, full_jid, &payload,
                )))
            }
            outcome => Ok(MixAction::Send(join_error(
                request_id, actor_bare, full_jid, outcome,
            ))),
        }
    } else {
        match session
            .host()
            .mix_service()
            .lookup_remote_pam_operation(user_id, full_jid, request_id, &request_digest)
            .await?
        {
            PamOperationReplay::Replay(response) => return Ok(MixAction::Send(response)),
            PamOperationReplay::Pending => {
                session.host().federation_outbox().wake_outbox();
                return Ok(MixAction::None);
            }
            PamOperationReplay::Conflict => {
                return Ok(MixAction::Send(iq_error_to(
                    request_id, actor_bare, full_jid, "cancel", "conflict",
                )));
            }
            PamOperationReplay::Miss => {}
        }
        // Exact retries are journal reads, not new federation
        // attempts. A later policy change must not replace the
        // original byte-stable result or strand a pending request.
        if !session.host().federation_domain_allowed(domain) {
            return Ok(MixAction::Send(iq_error_to(
                request_id,
                actor_bare,
                full_jid,
                "cancel",
                "remote-server-not-found",
            )));
        }
        let options = RemotePamJoinOptions::new(join.anonymous_profile, join.preference.as_ref())?;
        let federation_id = options.request_id(Uuid::new_v4());
        let outbound = remote_pam_join_stanza(
            &MixRealJid::parse(actor_bare)?,
            &MixChannelAddress::parse(&channel)?,
            &federation_id,
            &join,
            &options,
        );
        let admitted = session
            .host()
            .mix_service()
            .begin_remote_pam_join(BeginRemotePamJoin {
                user_id,
                actor_jid: actor_bare.to_owned(),
                channel_jid: channel.clone(),
                nick: join.nick.clone(),
                nodes: join.nodes.clone(),
                request_id: federation_id,
                client_request_id: request_id.to_owned(),
                requester_full_jid: full_jid.to_owned(),
                request_digest,
                remote_domain: domain.to_owned(),
                outbound_stanza: outbound,
                policy: session.host().federation_outbox().outbox_policy(),
            })
            .await?;
        match admitted {
            PamOperationReplay::Replay(response) => return Ok(MixAction::Send(response)),
            PamOperationReplay::Conflict => {
                return Ok(MixAction::Send(iq_error_to(
                    request_id, actor_bare, full_jid, "cancel", "conflict",
                )));
            }
            PamOperationReplay::Pending => {
                session.host().federation_outbox().wake_outbox();
            }
            PamOperationReplay::Miss => {
                return Ok(MixAction::Send(iq_error_to(
                    request_id,
                    actor_bare,
                    full_jid,
                    "wait",
                    "resource-constraint",
                )));
            }
        }
        Ok(MixAction::None)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_pam_leave(
    session: &impl MixSession,
    request_id: &str,
    user_id: Uuid,
    _username: &str,
    actor_bare: &str,
    full_jid: &str,
    request_digest: [u8; 32],
    channel: String,
) -> Result<MixAction> {
    let channel_address = match CanonicalJid::parse_bare(&channel) {
        Ok(channel) if channel.localpart().is_some() => channel,
        _ => {
            return Ok(MixAction::Send(iq_error_to(
                request_id,
                actor_bare,
                full_jid,
                "modify",
                "jid-malformed",
            )));
        }
    };
    let channel = channel_address.to_string();
    let domain = channel_address.domainpart();
    if domain == mix_domain(session) {
        let channel_localpart = channel_address
            .localpart()
            .expect("MIX channel localpart was checked above");
        let Some(mix_channel) = session
            .host()
            .mix_service()
            .mix_channel(domain, channel_localpart)
            .await?
        else {
            return Ok(MixAction::Send(iq_error_to(
                request_id,
                actor_bare,
                full_jid,
                "cancel",
                "item-not-found",
            )));
        };
        let left = match session
            .host()
            .mix_service()
            .leave_mix_channel_committed(
                &MixChannelId::new(mix_channel.id),
                &MixRealJid::parse(actor_bare)?,
                Some(user_id),
                None,
            )
            .await?
        {
            HostedMixOutcome::Present(left) => left,
            HostedMixOutcome::MissingChannel => {
                return Ok(MixAction::Send(iq_error_to(
                    request_id,
                    actor_bare,
                    full_jid,
                    "cancel",
                    "item-not-found",
                )));
            }
        };
        for delta in &left.roster {
            push_mix_roster_update(session.host(), delta).await?;
        }
        let payload = XmlElement::namespaced("client-leave", PAM_NS)
            .attr("channel", &channel)
            .child(XmlElement::namespaced("leave", CORE_NS))
            .finish();
        Ok(MixAction::Send(iq_result_to(
            request_id, actor_bare, full_jid, &payload,
        )))
    } else {
        match session
            .host()
            .mix_service()
            .lookup_remote_pam_operation(user_id, full_jid, request_id, &request_digest)
            .await?
        {
            PamOperationReplay::Replay(response) => return Ok(MixAction::Send(response)),
            PamOperationReplay::Pending => {
                session.host().federation_outbox().wake_outbox();
                return Ok(MixAction::None);
            }
            PamOperationReplay::Conflict => {
                return Ok(MixAction::Send(iq_error_to(
                    request_id, actor_bare, full_jid, "cancel", "conflict",
                )));
            }
            PamOperationReplay::Miss => {}
        }
        if !session.host().federation_domain_allowed(domain) {
            return Ok(MixAction::Send(iq_error_to(
                request_id,
                actor_bare,
                full_jid,
                "cancel",
                "remote-server-not-found",
            )));
        }
        let federation_id = Uuid::new_v4().to_string();
        let outbound = XmlElement::namespaced("iq", "jabber:server")
            .attr("type", "set")
            .attr("from", actor_bare)
            .attr("to", &channel)
            .attr("id", &federation_id)
            .child(XmlElement::namespaced("leave", CORE_NS))
            .finish();
        let admitted = session
            .host()
            .mix_service()
            .begin_remote_pam_leave(BeginRemotePamLeave {
                user_id,
                actor_jid: actor_bare.to_owned(),
                channel_jid: channel.clone(),
                request_id: federation_id,
                client_request_id: request_id.to_owned(),
                requester_full_jid: full_jid.to_owned(),
                request_digest,
                remote_domain: domain.to_owned(),
                outbound_stanza: outbound,
                policy: session.host().federation_outbox().outbox_policy(),
            })
            .await?;
        match admitted {
            PamOperationReplay::Replay(response) => return Ok(MixAction::Send(response)),
            PamOperationReplay::Conflict => {
                return Ok(MixAction::Send(iq_error_to(
                    request_id, actor_bare, full_jid, "cancel", "conflict",
                )));
            }
            PamOperationReplay::Pending => session.host().federation_outbox().wake_outbox(),
            PamOperationReplay::Miss => {
                return Ok(MixAction::Send(iq_error_to(
                    request_id,
                    actor_bare,
                    full_jid,
                    "cancel",
                    "item-not-found",
                )));
            }
        }
        Ok(MixAction::None)
    }
}
