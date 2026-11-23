//! Route mediated invitation declines.

use super::*;
use crate::muc::message::addressed::{self, AddressedDeliveryKind};
use northstar_room_application::muc_service::{MucAddressedOutcome, MucAddressedRequest};

pub(super) async fn handle_invitation_decline<S: MucHost>(
    state: &S,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
) -> Result<MessageStep<()>> {
    let &MessageAddress {
        from,
        ref actor_full_jid,
        ref to_jid,
        ref room_jid,
        ..
    } = address;
    let decline = match &request.decline {
        Ok(decline) => decline.clone(),
        Err(MalformedMucStanza) => {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    if let Some((target_raw, reason)) = decline {
        if to_jid.resourcepart().is_some()
            || !matches!(request.stanza.kind.as_deref(), None | Some("normal"))
        {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            )));
        }
        let Ok(target) = northstar_xmpp_types::jid::CanonicalJid::parse(&target_raw) else {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            )));
        };
        let occupant_target = target.bare() == *room_jid && target.resourcepart().is_some();
        let nick = target.resourcepart().filter(|_| occupant_target);
        let MucAddressedOutcome::Decline { target: route } = state
            .muc_service()
            .muc_addressed_authority(localpart(room_jid), MucAddressedRequest::Decline { nick })
            .await?
        else {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        let Some(target_localpart) = target.localpart() else {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            )));
        };
        let mut decline = XmlElement::new("decline").attr("from", bare_jid(actor_full_jid));
        if let Some(reason) = reason.as_deref() {
            decline.push_child(XmlElement::new("reason").text(reason.to_owned()));
        }
        let forwarded = XmlElement::namespaced("message", "jabber:client")
            .attr("from", room_jid)
            .attr("to", &target_raw)
            .attr("type", "normal")
            .attr(
                "id",
                request
                    .stanza
                    .id
                    .as_deref()
                    .filter(|id| !id.is_empty() && id.len() <= 128)
                    .unwrap_or("muc-decline"),
            )
            .child(
                XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user").child(decline),
            )
            .validated_fragment(&request.hints)?
            .finish();
        if occupant_target {
            if let Some(route) = route {
                addressed::send_addressed(
                    state,
                    room_jid,
                    &route,
                    forwarded,
                    actor_full_jid,
                    AddressedDeliveryKind::Decline,
                    true,
                )
                .await?;
            }
            return Ok(MessageStep::Done(None));
        }
        if target.domainpart() == state.local_domain() {
            let Some(recipient) = state
                .muc_service()
                .enabled_local_account(target_localpart)
                .await?
            else {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            };
            let target_bare = target.bare();
            if state
                .muc_service()
                .is_blocked_for_account(recipient.id, &target_bare, room_jid)
                .await?
                || state
                    .muc_service()
                    .is_blocked_for_account(recipient.id, &target_bare, actor_full_jid)
                    .await?
            {
                return Ok(MessageStep::Done(None));
            }
            let mut targets = state.session_entries_for(&target_raw);
            if target.resourcepart().is_none() {
                targets.retain(|(_, session)| session.is_available() && session.priority() >= 0);
                targets.sort_by(|(left_jid, left), (right_jid, right)| {
                    right
                        .priority()
                        .cmp(&left.priority())
                        .then_with(|| left_jid.cmp(right_jid))
                });
            }
            let mut delivered = targets
                .into_iter()
                .any(|(_, session)| session.sender().try_send(forwarded.clone()).is_ok());
            if !delivered {
                delivered = state
                    .route_federated_muc_account_message_remote(&target_raw, &forwarded, None)
                    .await
                    .is_some();
            }
            if !delivered && request.temporary_storage {
                let delayed =
                    add_delay_from(&forwarded, northstar_time::Utc::now(), Some(room_jid));
                let outcome = state
                    .muc_service()
                    .store_federated_muc_offline(
                        recipient.id,
                        room_jid,
                        &delayed,
                        false,
                        crate::muc::temporary_muc_offline_policy(state),
                    )
                    .await?;
                if outcome == OfflineStoreOutcome::QuotaExceeded {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "wait",
                        "resource-constraint",
                    )));
                }
                if outcome == OfflineStoreOutcome::RecipientUnavailable {
                    return Ok(MessageStep::Done(None));
                }
                if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                    tracing::warn!(?error, recipient_id = %recipient.id, %room_jid, "accepted federated offline MUC invitation decline could not trigger push notification");
                }
            }
            return Ok(MessageStep::Done(None));
        }
        if !state.xmpp_external_route_domain_allowed(target.domainpart())
            || !state
                .send_federated(target.domainpart(), forwarded, Some(room_jid.clone()))
                .await
        {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "wait",
                "remote-server-timeout",
            )));
        }
        return Ok(MessageStep::Done(None));
    }
    Ok(MessageStep::Next(()))
}
