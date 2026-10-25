//! Federated MUC moderation handling.

use super::*;

pub(super) async fn federated_muc_moderate(
    state: &AppState,
    stanza: &FederatedStanza,
    room: &MucRoom,
    moderator: &MucOccupant,
    target: Option<String>,
    reason: Option<String>,
    has_retract: bool,
) -> Result<Option<String>> {
    let authenticated_domain = match &moderator.endpoint {
        MucOccupantEndpoint::Federated {
            authenticated_domain,
            ..
        } => authenticated_domain.clone(),
        _ => return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden")),
    };
    let local_authority_guard = if state.federated_muc_pg_authority_enabled() {
        None
    } else {
        Some(state.muc_service().lock_local_room_mutation(room.id).await)
    };
    let Some(refreshed_room) = state
        .muc_service()
        .federated_room_snapshot(localpart(&moderator.room_jid))
        .await?
    else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        ));
    };
    if refreshed_room.id != room.id || refreshed_room.room_epoch != room.room_epoch {
        return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
    }
    let Some((_, refreshed_moderator)) = state
        .muc_occupants_for(&moderator.room_jid)
        .into_iter()
        .find(|(_, current)| {
            current.full_jid == moderator.full_jid
                && current.connection_id == moderator.connection_id
                && current.cluster_epoch == moderator.cluster_epoch
                && current.nick == moderator.nick
        })
    else {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    };
    if !federated_endpoint_matches(&refreshed_moderator, &authenticated_domain) {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "auth",
            "not-authorized",
        ));
    }
    let room = &refreshed_room;
    let moderator = &refreshed_moderator;
    let actor_scope = northstar_xmpp_types::jid::canonical_bare_key(&moderator.full_jid)?;
    let current_affiliation = state
        .muc_service()
        .federated_affiliation(room.id, &actor_scope)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if current_affiliation != moderator.affiliation || current_affiliation == "outcast" {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    let cluster_target = if state.federated_muc_pg_authority_enabled() {
        let Some(target) = state
            .muc_service()
            .local_cluster_occupancy_target(
                room.id,
                moderator.cluster_epoch,
                moderator.connection_id,
            )
            .await?
            .filter(|target| {
                target.room_epoch == room.room_epoch
                    && target.full_jid == moderator.full_jid
                    && target.nick == moderator.nick
                    && target.connection_uuid == moderator.connection_id
            })
        else {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        };
        Some(target)
    } else {
        None
    };
    if moderator.role != "moderator" {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    if !has_retract {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }
    let Some(target) = target else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    };
    let Ok(target_id) = uuid::Uuid::parse_str(&target) else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        ));
    };
    let reason = reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if reason.is_some_and(|value| value.len() > 1024) {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "not-acceptable",
        ));
    }
    let Some(original) = state
        .muc_service()
        .federated_message_by_id(room.id, target_id)
        .await?
    else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        ));
    };
    let Some((original_from, original_client_id)) = (|| {
        let document = roxmltree::Document::parse(&original.stanza).ok()?;
        let root = document.root_element();
        (root.tag_name().name() == "message" && root.attribute("type") == Some("groupchat")).then(
            || {
                (
                    root.attribute("from")
                        .unwrap_or(&moderator.room_jid)
                        .to_owned(),
                    root.attribute("id").unwrap_or(&target).to_owned(),
                )
            },
        )
    })() else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "not-acceptable",
        ));
    };
    let moderator_occupant = format!("{}/{}", moderator.room_jid, moderator.nick);
    let author_occupant_id = muc_occupant_id(&room.occupant_id_secret, &original.sender_jid);
    let stamp = chrono::Utc::now();
    let moderated = XmlElement::namespaced("moderated", "urn:xmpp:message-moderate:1")
        .attr("by", &moderator_occupant)
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &moderator.occupant_id),
        );
    let mut retracted = XmlElement::namespaced("retracted", "urn:xmpp:message-retract:1")
        .attr("stamp", stamp.format("%Y-%m-%dT%H:%M:%SZ"))
        .child(moderated.clone());
    if let Some(reason) = reason {
        retracted.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    let tombstone = XmlElement::namespaced("message", "jabber:client")
        .attr("from", &original_from)
        .attr("to", &moderator.room_jid)
        .attr("type", "groupchat")
        .attr("id", &original_client_id)
        .child(
            XmlElement::namespaced("stanza-id", "urn:xmpp:sid:0")
                .attr("id", target_id)
                .attr("by", &moderator.room_jid),
        )
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &author_occupant_id),
        )
        .child(retracted)
        .finish();
    let action_id = uuid::Uuid::new_v4();
    let mut retract = XmlElement::namespaced("retract", "urn:xmpp:message-retract:1")
        .attr("id", target_id)
        .child(moderated);
    if let Some(reason) = reason {
        retract.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    let notice_xml = XmlElement::namespaced("message", "jabber:client")
        .attr("from", &moderator.room_jid)
        .attr("to", &moderator.room_jid)
        .attr("type", "groupchat")
        .attr("id", action_id)
        .child(retract)
        .finish();
    let notice = add_stanza_id(
        &set_muc_occupant_id(&notice_xml, &moderator.occupant_id),
        &moderator.room_jid,
        action_id,
    );
    match state
        .muc_service()
        .retract_local_message_and_archive_action(MucRetractionMutation {
            action_id,
            room_id: room.id,
            target_id,
            expected_stanza: &original.stanza,
            actor_scope: &actor_scope,
            sender_jid: &moderator.full_jid,
            nick: &moderator.nick,
            tombstone: &tombstone,
            action_stanza: &notice,
            reason,
            kind: MucRetractionKind::Moderator,
            authority: MucActorAuthority {
                clustered: state.federated_muc_pg_authority_enabled(),
                expected_room_epoch: room.room_epoch,
                principal: MucActorPrincipal::Federated {
                    bare_jid: actor_scope.clone(),
                    authenticated_domain: authenticated_domain.clone(),
                },
                actor_scope: actor_scope.clone(),
                full_jid: moderator.full_jid.clone(),
                nick: moderator.nick.clone(),
                occupant_incarnation: moderator.cluster_epoch,
                connection_uuid: moderator.connection_id,
                expected_role: moderator.role.clone(),
                expected_affiliation: current_affiliation.clone(),
                cluster_target,
            },
        })
        .await?
    {
        MucRetractionOutcome::Applied => {}
        MucRetractionOutcome::Unauthorized => {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        }
        MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
            return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
        }
    }
    match state
        .federated_muc_publish_room_message(&moderator.room_jid, &notice, None)
        .await
    {
        Ok(()) => {}
        Err(_) => record_federated_muc_post_commit_failure(
            state,
            &moderator.room_jid,
            "*",
            "cluster moderation fan-out",
        ),
    }
    for (_, occupant) in state.muc_occupants_for(&moderator.room_jid) {
        let delivery = set_to(&notice, &occupant.full_jid);
        if !state.deliver_to_muc_occupant(&occupant, delivery).await {
            record_federated_muc_post_commit_failure(
                state,
                &moderator.room_jid,
                &occupant.full_jid,
                "moderation occupant queue",
            );
        }
    }
    drop(local_authority_guard);
    Ok(Some(federated_iq_result(
        stanza,
        &moderator.room_jid,
        &moderator.full_jid,
        "",
    )))
}
