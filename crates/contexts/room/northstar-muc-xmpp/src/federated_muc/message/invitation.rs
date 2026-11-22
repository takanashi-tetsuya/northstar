//! Handle non-groupchat messages and route mediated invitations.

use super::*;
use northstar_room_core::MucLocalAccount;

pub(super) struct PreparedInvitation<'a> {
    invitee: &'a CanonicalJid,
    invitee_localpart: &'a str,
    invitee_jid: &'a String,
    invitee_bare: &'a String,
    invitee_domain: &'a str,
    reason: Option<&'a str>,
    invitation: &'a String,
}

pub(super) struct LocalInvitationAdmission {
    local_user: MucLocalAccount,
    live_claim_id: Option<uuid::Uuid>,
    durable_invite: Option<uuid::Uuid>,
}

pub(super) async fn handle_non_groupchat<S: MucHost>(
    state: &S,
    authenticated_domain: &str,
    connection_id: &uuid::Uuid,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
    occupancy: &RoomOccupancy<S>,
) -> Result<MessageStep<()>> {
    let &MessageAddress {
        from,
        ref actor_full_jid,
        ref room_jid,
        ..
    } = address;
    let RoomOccupancy { own, room } = occupancy;
    if request.stanza.kind.as_deref() != Some("groupchat") {
        let privileged_inviter = matches!(own.affiliation.as_str(), "owner" | "admin");
        if !request.invites.is_empty()
            && !privileged_inviter
            && (own.role == "visitor" || !room.allow_invites)
        {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "auth",
                "forbidden",
            )));
        }
        let mut delivered_invitation = false;
        for invite in &request.invites {
            let Some(invitee_raw) = invite.invitee.as_deref() else {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "bad-request",
                )));
            };
            let Ok(invitee) = northstar_xmpp_types::jid::CanonicalJid::parse(invitee_raw) else {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "jid-malformed",
                )));
            };
            let Some(invitee_localpart) = invitee.localpart() else {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "jid-malformed",
                )));
            };
            let invitee_jid = invitee.to_string();
            let invitee_bare = invitee.bare();
            let invitee_domain = invitee.domainpart();
            if invitee_domain == state.local_domain() {
                if let Some(local_user) = state
                    .muc_service()
                    .enabled_local_account(invitee_localpart)
                    .await?
                {
                    let blocked_room = state
                        .muc_service()
                        .is_blocked_for_account(local_user.id, &invitee_bare, room_jid)
                        .await?;
                    let blocked_inviter = state
                        .muc_service()
                        .is_blocked_for_account(local_user.id, &invitee_bare, actor_full_jid)
                        .await?;
                    if blocked_room || blocked_inviter {
                        delivered_invitation = true;
                        continue;
                    }
                }
            }
            let reason = invite.reason.as_deref();
            let mut invite_out = XmlElement::new("invite").attr("from", from);
            if let Some(reason) = reason {
                invite_out.push_child(XmlElement::new("reason").text(reason.to_owned()));
            }
            let local_durable_invite_id =
                if room.members_only && invitee_domain == state.local_domain() {
                    Some(northstar_room_application::muc_service::operation_id(
                        &serde_json::json!({
                            "kind":"muc_invitation","stream":*connection_id,
                            "stanza_id":request.stanza.id,"room":room_jid,
                            "actor":actor_full_jid,"invitee":invitee_bare,"reason":reason,
                        }),
                    )?)
                } else {
                    None
                };
            let invitation = set_muc_occupant_id(
                &add_stanza_id(
                    &XmlElement::namespaced("message", "jabber:client")
                        .attr("from", room_jid)
                        .attr("to", &invitee_jid)
                        .attr("type", "normal")
                        .child(
                            XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
                                .child(invite_out),
                        )
                        .validated_fragment(&request.hints)?
                        .finish(),
                    room_jid,
                    uuid::Uuid::new_v4(),
                ),
                &own.occupant_id,
            );
            let invitation = local_durable_invite_id.map_or(invitation.clone(), |id| {
                add_stanza_id(&invitation, &invitee_bare, id)
            });
            let prepared = PreparedInvitation {
                invitee: &invitee,
                invitee_localpart,
                invitee_jid: &invitee_jid,
                invitee_bare: &invitee_bare,
                invitee_domain,
                reason,
                invitation: &invitation,
            };
            if invitee_domain == state.local_domain() {
                let mut admission = match admit_local_invitation(
                    state,
                    authenticated_domain,
                    request,
                    address,
                    occupancy,
                    &prepared,
                    local_durable_invite_id,
                )
                .await?
                {
                    MessageStep::Next(admission) => admission,
                    MessageStep::Done(value) => return Ok(MessageStep::Done(value)),
                };
                if let MessageStep::Done(value) =
                    deliver_local_invitation(state, request, address, &prepared, &mut admission)
                        .await?
                {
                    return Ok(MessageStep::Done(value));
                }
            } else if room.members_only {
                if let MessageStep::Done(value) = admit_federated_invitation(
                    state,
                    authenticated_domain,
                    connection_id,
                    request,
                    address,
                    occupancy,
                    &prepared,
                )
                .await?
                {
                    return Ok(MessageStep::Done(value));
                }
            } else if !state
                .send_federated(invitee_domain, invitation, Some(room_jid.clone()))
                .await
            {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "remote-server-timeout",
                )));
            }
            delivered_invitation = true;
        }
        return if delivered_invitation {
            Ok(MessageStep::Done(None))
        } else {
            Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            )))
        };
    }
    Ok(MessageStep::Next(()))
}

pub(super) async fn admit_local_invitation<S: MucHost>(
    state: &S,
    authenticated_domain: &str,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
    occupancy: &RoomOccupancy<S>,
    prepared: &PreparedInvitation<'_>,
    local_durable_invite_id: Option<uuid::Uuid>,
) -> Result<MessageStep<LocalInvitationAdmission>> {
    let &MessageAddress {
        from,
        ref actor_full_jid,
        ref actor_bare_jid,
        ref room_jid,
        ..
    } = address;
    let RoomOccupancy { own, room } = occupancy;
    let &PreparedInvitation {
        invitee_localpart,
        invitee_bare,
        reason,
        invitation,
        ..
    } = prepared;
    let Some(local_user) = state
        .muc_service()
        .enabled_local_account(invitee_localpart)
        .await?
    else {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        )));
    };
    if room.members_only && !request.temporary_storage {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "wait",
            "service-unavailable",
        )));
    }
    let mut live_claim_id = None;
    let durable_invite = if room.members_only {
        let delayed = add_delay_from(invitation, northstar_time::Utc::now(), Some(room_jid));
        let cluster_authority = if state.federated_muc_pg_authority_enabled() {
            state.federated_muc_admit_mutation()?;
            let Some(actor_target) = state
                .muc_service()
                .local_cluster_occupancy_target(room.id, own.cluster_epoch, own.connection_id)
                .await?
            else {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "forbidden",
                )));
            };
            Some(ClusterMucInviteAuthority {
                operation_id: local_durable_invite_id
                    .expect("local members-only invite allocates a fence"),
                expected_room_epoch: room.room_epoch,
                expected_config_version: room.config_version,
                actor: ClusterMucPrincipal::Federated {
                    bare_jid: actor_bare_jid.clone(),
                    authenticated_domain: authenticated_domain.to_owned(),
                },
                actor_full_jid: actor_full_jid.clone(),
                actor_target: Some(actor_target),
                subject: ClusterMucAffiliationSubject::Local {
                    user_id: local_user.id,
                    bare_jid: invitee_bare.clone(),
                },
                reason: reason.map(str::to_owned),
            })
        } else {
            None
        };
        match state
            .muc_service()
            .admit_local_invite_command(
                local_durable_invite_id.expect("local members-only invite allocates a fence"),
                room.id,
                local_user.id,
                room_jid,
                &delayed,
                false,
                crate::muc::temporary_muc_offline_policy(state),
                cluster_authority.as_ref(),
            )
            .await?
        {
            DurableMucInviteOutcome::Stored {
                id,
                live_claim_id: admitted_claim_id,
                ..
            } => {
                live_claim_id = admitted_claim_id;
                if let Some(authority) = &cluster_authority {
                    if let Err(error) = state
                        .wake_committed_muc_operation(authority.operation_id)
                        .await
                    {
                        tracing::warn!(?error, operation_id = %authority.operation_id,
                            "committed federated MUC invitation wake failed");
                    }
                }
                Some(id)
            }
            DurableMucInviteOutcome::Replay { .. } => {
                if let Some(authority) = &cluster_authority {
                    state
                        .wake_committed_muc_operation(authority.operation_id)
                        .await?;
                }
                return Ok(MessageStep::Done(None));
            }
            DurableMucInviteOutcome::QuotaExceeded => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "resource-constraint",
                )));
            }
            DurableMucInviteOutcome::RecipientUnavailable => {
                // The local invitee disappeared after the initial
                // route lookup.  Suppress the invitation without
                // exposing account lifecycle state to the remote
                // room occupant.
                return Ok(MessageStep::Done(None));
            }
            DurableMucInviteOutcome::Outcast => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            DurableMucInviteOutcome::AuthorityRejected => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            DurableMucInviteOutcome::Stale => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            }
        }
    } else {
        None
    };
    Ok(MessageStep::Next(LocalInvitationAdmission {
        local_user,
        live_claim_id,
        durable_invite,
    }))
}

pub(super) async fn deliver_local_invitation<S: MucHost>(
    state: &S,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
    prepared: &PreparedInvitation<'_>,
    admission: &mut LocalInvitationAdmission,
) -> Result<MessageStep<()>> {
    let &MessageAddress {
        from, ref room_jid, ..
    } = address;
    let &PreparedInvitation {
        invitee,
        invitee_jid,
        invitee_bare,
        invitation,
        ..
    } = prepared;
    let &mut LocalInvitationAdmission {
        ref local_user,
        ref mut live_claim_id,
        durable_invite,
    } = admission;
    let mut targets = state.session_entries_for(invitee_jid);
    if invitee.resourcepart().is_none() {
        targets.retain(|(_, session)| session.is_available() && session.priority() >= 0);
        targets.sort_by(|(left_jid, left), (right_jid, right)| {
            right
                .priority()
                .cmp(&left.priority())
                .then_with(|| left_jid.cmp(right_jid))
        });
    }
    if let Some(message_id) = durable_invite {
        if state.federated_muc_pg_authority_enabled()
            && (!northstar_message_core::live_reservation_valid(true, message_id, *live_claim_id)
                || state.message_direct_mode()
                    != northstar_message_core::DirectPostCommitMode::Live)
        {
            state
                .rearm_unrouted_live_direct(local_user.id, message_id, live_claim_id)
                .await;
            return Ok(MessageStep::Done(None));
        }
    }
    let live_delivery = durable_invite.map(|message_id| northstar_delivery_core::DurableDelivery {
        recipient_id: local_user.id,
        message_id,
        claim_id: *live_claim_id,
    });
    let mut delivered = false;
    let mut delivered_full_jid = None;
    for (full_jid, session) in targets {
        let accepted = if let Some(delivery) = live_delivery {
            session
                .sender()
                .try_send_durable(invitation.clone(), delivery)
                .is_ok()
        } else {
            session.sender().try_send(invitation.clone()).is_ok()
        };
        if accepted {
            state
                .federated_muc_telemetry()
                .online_queue_result(true, live_delivery.is_some());
            delivered = true;
            delivered_full_jid = Some(full_jid);
            break;
        }
    }
    if !delivered {
        if let Some(message_id) = durable_invite {
            if state.federated_muc_pg_authority_enabled()
                && state.message_direct_mode() != northstar_message_core::DirectPostCommitMode::Live
            {
                state
                    .rearm_unrouted_live_direct(local_user.id, message_id, live_claim_id)
                    .await;
                return Ok(MessageStep::Done(None));
            }
        }
        if let Some(route) = state
            .route_federated_muc_account_message_remote(invitee_jid, invitation, live_delivery)
            .await
        {
            delivered = true;
            delivered_full_jid = route.accepted_full_jid;
        }
    }
    if !delivered {
        if let Some(message_id) = durable_invite {
            state
                .rearm_unrouted_live_direct(local_user.id, message_id, live_claim_id)
                .await;
        }
    }
    if delivered {
        if request.carbon_eligible
            && state.message_direct_mode() == northstar_message_core::DirectPostCommitMode::Live
        {
            state
                .send_received_carbons(invitee_bare, delivered_full_jid.as_deref(), invitation)
                .await;
        }
    } else if durable_invite.is_none() && request.temporary_storage {
        let delayed = add_delay_from(invitation, northstar_time::Utc::now(), Some(room_jid));
        let offline_outcome = state
            .muc_service()
            .store_federated_muc_offline(
                local_user.id,
                room_jid,
                &delayed,
                false,
                crate::muc::temporary_muc_offline_policy(state),
            )
            .await?;
        if offline_outcome == OfflineStoreOutcome::QuotaExceeded {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "wait",
                "resource-constraint",
            )));
        }
        if offline_outcome == OfflineStoreOutcome::RecipientUnavailable {
            return Ok(MessageStep::Done(None));
        }
    }
    if !delivered
        && request.temporary_storage
        && state.message_direct_mode() == northstar_message_core::DirectPostCommitMode::Live
    {
        if let Err(error) = state.dispatch_push_notification(local_user.id).await {
            tracing::warn!(?error, recipient_id = %local_user.id, %room_jid, "accepted federated offline mediated MUC invitation could not trigger push notification");
        }
    }
    Ok(MessageStep::Next(()))
}

pub(super) async fn admit_federated_invitation<S: MucHost>(
    state: &S,
    authenticated_domain: &str,
    connection_id: &uuid::Uuid,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
    occupancy: &RoomOccupancy<S>,
    prepared: &PreparedInvitation<'_>,
) -> Result<MessageStep<()>> {
    let &MessageAddress {
        from,
        ref actor_full_jid,
        ref actor_bare_jid,
        ref room_jid,
        ..
    } = address;
    let RoomOccupancy { own, room } = occupancy;
    let &PreparedInvitation {
        invitee_bare,
        invitee_domain,
        reason,
        invitation,
        ..
    } = prepared;
    let operation_id = northstar_room_application::muc_service::operation_id(&serde_json::json!({
        "kind":"muc_invitation","stream":*connection_id,
        "stanza_id":request.stanza.id,"room":room_jid,
        "actor":actor_full_jid,"invitee":invitee_bare,"reason":reason,
    }))?;
    let cluster_authority = if state.federated_muc_pg_authority_enabled() {
        state.federated_muc_admit_mutation()?;
        let Some(actor_target) = state
            .muc_service()
            .local_cluster_occupancy_target(room.id, own.cluster_epoch, own.connection_id)
            .await?
        else {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "auth",
                "forbidden",
            )));
        };
        Some(ClusterMucInviteAuthority {
            operation_id,
            expected_room_epoch: room.room_epoch,
            expected_config_version: room.config_version,
            actor: ClusterMucPrincipal::Federated {
                bare_jid: actor_bare_jid.clone(),
                authenticated_domain: authenticated_domain.to_owned(),
            },
            actor_full_jid: actor_full_jid.clone(),
            actor_target: Some(actor_target),
            subject: ClusterMucAffiliationSubject::Federated {
                bare_jid: invitee_bare.clone(),
            },
            reason: reason.map(str::to_owned),
        })
    } else {
        None
    };
    match state
        .muc_service()
        .admit_federated_invite_command(
            room.id,
            invitee_bare,
            invitee_domain,
            invitation,
            Some(room_jid),
            state.federation_outbox_policy(),
            cluster_authority.as_ref(),
        )
        .await
    {
        Ok(true) => {
            state.wake_federation_outbox();
            if cluster_authority.is_some() {
                state.wake_committed_muc_operation(operation_id).await?;
            }
        }
        Ok(false) => {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "auth",
                "forbidden",
            )));
        }
        Err(error) => {
            tracing::warn!(?error, %invitee_bare, %room_jid, "federated mediated MUC invite admission failed atomically");
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "wait",
                "resource-constraint",
            )));
        }
    }
    Ok(MessageStep::Next(()))
}
