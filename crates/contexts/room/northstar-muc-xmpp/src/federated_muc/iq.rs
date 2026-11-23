//! Federated MUC IQ handling for remote room actors.

use super::admin::{
    federated_muc_admin_get, federated_muc_admin_set, publish_occupant_change,
    FederatedMucAdminActor, OccupantChange,
};
use super::mam::render_federated_mam_stream;
use super::moderate::federated_muc_moderate;
use super::owner::{
    federated_muc_owner, federated_muc_owner_get, parse_federated_registration_action,
    FederatedRegistrationAction,
};
use super::*;
use northstar_archive_core::{MamOccupancyProof, MamRoomAccessOutcome, MamRoomReadAuthority};
use northstar_room_application::muc_service::{
    MucManagementViewer, MucOccupancyProof, MucReadPrincipal, MucRoomView, MucRoomViewKind,
    MucRoomViewer,
};

mod authorized;
use self::authorized::{
    committed_registration_reply, deliver_occupant_iq, federated_liveness_reply,
    federated_read_route, FederatedReadActor,
};

/// Handle room/service IQs from an authenticated remote room actor. XML is
/// converted to owned data before this future is created, so S2S connection
/// tasks remain `Send` across database and network awaits.
pub fn federated_muc_iq<'a>(
    state: &'a impl MucHost,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    root: Node<'_, '_>,
    raw: &str,
) -> impl std::future::Future<Output = Result<Option<String>>> + Send + 'a {
    let authenticated_domain = authenticated_domain.to_owned();
    let request = FederatedIqRequest::from_node(root, raw);
    async move { federated_muc_iq_owned(state, &authenticated_domain, connection_id, request).await }
}

async fn federated_muc_iq_owned(
    state: &impl MucHost,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    request: FederatedIqRequest,
) -> Result<Option<String>> {
    let from = request.stanza.from.as_str();
    let to = request.stanza.to.as_str();
    if !authenticated_remote_actor(authenticated_domain, from) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    let actor_full_jid = northstar_xmpp_types::jid::canonicalize(from)
        .expect("authenticated_remote_actor already validated the full JID");
    let actor_bare_jid = northstar_xmpp_types::jid::canonical_bare_key(&actor_full_jid)?;
    let conference_domain = muc_domain(state);
    let Ok(to_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        ));
    };
    let room_jid = to_jid.bare();
    let service_request = to_jid.localpart().is_none() && to_jid.domainpart() == conference_domain;
    if !service_request && to_jid.domainpart() != conference_domain {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    if matches!(request.payload, FederatedIqPayload::Ping)
        && !state.xmpp_extension_enabled(northstar_xep_0199::XEP_ID)
    {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "service-unavailable",
        ));
    }
    if matches!(request.payload, FederatedIqPayload::PingError) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "bad-request",
        ));
    }

    if service_request {
        let payload = match request.payload {
            FederatedIqPayload::Ping => {
                return Ok(Some(federated_liveness_reply(
                    &request.stanza,
                    &conference_domain,
                    &actor_full_jid,
                )))
            }
            FederatedIqPayload::DiscoInfo { node: None } => {
                let mut query =
                    XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info").child(
                        XmlElement::new("identity")
                            .attr("category", "conference")
                            .attr("type", "text")
                            .attr("name", format!("{} Group Chat", state.server_name())),
                    );
                for feature in [
                    "http://jabber.org/protocol/disco#info",
                    "http://jabber.org/protocol/disco#items",
                    "http://jabber.org/protocol/muc",
                    "http://jabber.org/protocol/muc#unique",
                    "http://jabber.org/protocol/rsm",
                    "urn:xmpp:occupant-id:0",
                    "urn:xmpp:message-moderate:1",
                    "urn:xmpp:message-retract:1",
                    "urn:xmpp:message-retract:1#tombstone",
                    "urn:xmpp:sid:0",
                ] {
                    query.push_child(XmlElement::new("feature").attr("var", feature));
                }
                if state.xmpp_extension_enabled(northstar_xep_0313::XEP_ID) {
                    query.push_child(
                        XmlElement::new("feature")
                            .attr("var", northstar_xep_0313::DISCO_FEATURE_MAM),
                    );
                    query.push_child(
                        XmlElement::new("feature")
                            .attr("var", northstar_xep_0313::DISCO_FEATURE_MAM_EXTENDED),
                    );
                }
                if state.xmpp_extension_enabled(northstar_xep_0199::XEP_ID) {
                    query.push_child(
                        XmlElement::new("feature").attr("var", northstar_xep_0199::NAMESPACE),
                    );
                }
                query.finish()
            }
            FederatedIqPayload::DiscoInfo { node: Some(_) } => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
            FederatedIqPayload::DiscoInfoError => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "bad-request",
                ));
            }
            FederatedIqPayload::DiscoItems(disco) if disco.node.is_none() => {
                let page = match state
                    .muc_service()
                    .federated_public_room_page(
                        disco.after.as_deref(),
                        disco.before.as_ref().map(|value| value.as_deref()),
                        disco.max,
                    )
                    .await?
                {
                    Some(page) => page,
                    None => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                };
                let mut query =
                    XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
                for room in &page.rooms {
                    query.push_child(
                        XmlElement::new("item")
                            .attr("jid", format!("{}@{}", room.localpart, conference_domain))
                            .attr("name", room.title.as_deref().unwrap_or(&room.localpart)),
                    );
                }
                query.push_validated_fragment(&northstar_xml_builder::disco::disco_rsm_result(
                    page.rooms.first().map(|room| room.localpart.as_str()),
                    page.rooms.last().map(|room| room.localpart.as_str()),
                    page.first_index,
                    page.total,
                ))?;
                query.finish()
            }
            FederatedIqPayload::DiscoItemsError(condition) => {
                return Ok(federated_error(&request.stanza, from, "modify", condition));
            }
            FederatedIqPayload::Unique => {
                XmlElement::namespaced("unique", "http://jabber.org/protocol/muc#unique")
                    .text(uuid::Uuid::new_v4().simple().to_string())
                    .finish()
            }
            _ => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "feature-not-implemented",
                ));
            }
        };
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &conference_domain,
            &actor_full_jid,
            &payload,
        )));
    }

    if !valid_muc_room(localpart(&room_jid)) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        ));
    }
    if matches!(
        &request.payload,
        FederatedIqPayload::MamForm
            | FederatedIqPayload::MamQuery(_)
            | FederatedIqPayload::MamMetadata
            | FederatedIqPayload::MamError(_)
    ) {
        return federated_muc_mam_iq(
            state,
            authenticated_domain,
            &request,
            &room_jid,
            &actor_full_jid,
        )
        .await;
    }

    let domain = canonical_authenticated_domain(authenticated_domain);
    let room_localpart = localpart(&room_jid);
    let target_nick = to_jid.resourcepart();
    let view_kind = match &request.payload {
        FederatedIqPayload::DiscoInfo { node: Some(_) } => MucRoomViewKind::ReservedNick,
        FederatedIqPayload::RegisterGet => MucRoomViewKind::Registration,
        FederatedIqPayload::DiscoItems(disco) if target_nick.is_none() && disco.node.is_none() => {
            MucRoomViewKind::Items
        }
        FederatedIqPayload::DiscoItemsError(_) if target_nick.is_none() => MucRoomViewKind::Items,
        _ => MucRoomViewKind::Info {
            include_mirror: false,
        },
    };
    let needs_route = view_kind == MucRoomViewKind::Items
        || matches!(
            &request.payload,
            FederatedIqPayload::OwnerGet | FederatedIqPayload::AdminGet { .. }
        )
        || (target_nick.is_some()
            && !matches!(
                &request.payload,
                FederatedIqPayload::DiscoInfo { .. }
                    | FederatedIqPayload::DiscoInfoError
                    | FederatedIqPayload::RegisterGet
                    | FederatedIqPayload::RegisterSet
            ));
    let actor = FederatedReadActor {
        full_jid: &actor_full_jid,
        bare_jid: &actor_bare_jid,
        domain: &domain,
        node_id: state.muc_cluster_node_id(),
        route: if needs_route {
            federated_read_route(state, &room_jid, &actor_full_jid, &domain)
        } else {
            None
        },
    };
    if let Some(nick) = target_nick.filter(|_| needs_route) {
        return deliver_occupant_iq(state, &request, &room_jid, nick, &actor).await;
    }
    if matches!(&request.payload, FederatedIqPayload::Ping) {
        let room = state.muc_service().read_room(room_localpart).await?;
        return Ok(
            if room.is_some_and(|view| {
                !view.room.is_locked()
                    || (!view.configuration_expired
                        && view.room.configuration_owner_jid.as_deref()
                            == Some(actor_full_jid.as_str()))
            }) {
                Some(federated_liveness_reply(
                    &request.stanza,
                    &room_jid,
                    &actor_full_jid,
                ))
            } else {
                federated_error(&request.stanza, from, "cancel", "item-not-found")
            },
        );
    }
    match &request.payload {
        FederatedIqPayload::AdminGet { affiliation, role } => {
            return federated_muc_admin_get(
                state,
                &request.stanza,
                &room_jid,
                actor.management_viewer(),
                affiliation.as_deref(),
                role.as_deref(),
            )
            .await;
        }
        FederatedIqPayload::OwnerGet => {
            return federated_muc_owner_get(
                state,
                &request.stanza,
                &room_jid,
                actor.management_viewer(),
            )
            .await;
        }
        _ => {}
    }
    let command = matches!(
        &request.payload,
        FederatedIqPayload::RegisterSet
            | FederatedIqPayload::AdminSet { .. }
            | FederatedIqPayload::OwnerSet
            | FederatedIqPayload::Moderate { .. }
    );
    let (room, reserved_nick, nicks) = if command {
        let Some(room) = state
            .muc_service()
            .federated_room_snapshot(room_localpart)
            .await?
        else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        };
        if room.is_locked()
            && !room.can_configure_locked_room(&actor_full_jid, northstar_time::Utc::now())
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        (room, None, Vec::new())
    } else {
        match state
            .muc_service()
            .room_view(
                room_localpart,
                MucRoomViewer {
                    full_jid: Some(&actor_full_jid),
                    principal: Some(actor.principal()),
                    federated: true,
                    occupancy: actor.proof(),
                },
                view_kind,
            )
            .await?
        {
            MucRoomView::Found {
                room,
                reserved_nick,
                nicks,
                ..
            } => (room.room, reserved_nick, nicks),
            MucRoomView::Missing => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ))
            }
            MucRoomView::Unauthorized => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "not-authorized",
                ))
            }
        }
    };
    if matches!(&request.payload, FederatedIqPayload::DiscoInfoError) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "bad-request",
        ));
    }
    if let FederatedIqPayload::DiscoInfo { node: Some(node) } = &request.payload {
        if node != "x-roomuser-item" {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        let mut payload = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
            .attr("node", "x-roomuser-item");
        if let Some(nick) = reserved_nick {
            payload.push_child(
                XmlElement::new("identity")
                    .attr("category", "conference")
                    .attr("type", "text")
                    .attr("name", nick),
            );
        }
        let payload = payload.finish();
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &room_jid,
            &actor_full_jid,
            &payload,
        )));
    }
    if matches!(
        &request.payload,
        FederatedIqPayload::DiscoInfo { node: None }
    ) {
        let mut payload = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
            .child(
                XmlElement::new("identity")
                    .attr("category", "conference")
                    .attr("type", "text")
                    .attr("name", room.title.as_deref().unwrap_or(&room.localpart)),
            );
        let mut features = vec![
            "http://jabber.org/protocol/disco#info".to_owned(),
            "http://jabber.org/protocol/disco#items".to_owned(),
            "http://jabber.org/protocol/muc".to_owned(),
            "http://jabber.org/protocol/rsm".to_owned(),
            "urn:xmpp:sid:0".to_owned(),
            "urn:xmpp:occupant-id:0".to_owned(),
            "urn:xmpp:message-moderate:1".to_owned(),
            "urn:xmpp:message-retract:1".to_owned(),
            format!("muc_{}", if room.public { "public" } else { "hidden" }),
            format!(
                "muc_{}",
                if room.persistent {
                    "persistent"
                } else {
                    "temporary"
                }
            ),
            format!(
                "muc_{}",
                if room.members_only {
                    "membersonly"
                } else {
                    "open"
                }
            ),
            format!(
                "muc_{}",
                if room.moderated {
                    "moderated"
                } else {
                    "unmoderated"
                }
            ),
            format!(
                "muc_{}",
                if room.non_anonymous {
                    "nonanonymous"
                } else {
                    "semianonymous"
                }
            ),
            format!(
                "muc_{}",
                if room.password_hash.is_some() {
                    "passwordprotected"
                } else {
                    "unsecured"
                }
            ),
        ];
        if state.xmpp_extension_enabled(northstar_xep_0313::XEP_ID) {
            features.push(northstar_xep_0313::DISCO_FEATURE_MAM.to_owned());
            features.push(northstar_xep_0313::DISCO_FEATURE_MAM_EXTENDED.to_owned());
        }
        for feature in features {
            payload.push_child(XmlElement::new("feature").attr("var", feature));
        }
        if state.xmpp_extension_enabled(northstar_xep_0199::XEP_ID) {
            payload
                .push_child(XmlElement::new("feature").attr("var", northstar_xep_0199::NAMESPACE));
        }
        let payload = payload.finish();
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &room_jid,
            &actor_full_jid,
            &payload,
        )));
    }
    if matches!(
        &request.payload,
        FederatedIqPayload::RegisterGet | FederatedIqPayload::RegisterSet
    ) {
        if command
            && room.is_locked()
            && !room.can_configure_locked_room(&actor_full_jid, northstar_time::Utc::now())
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        if !room.allow_registration {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "not-allowed",
            ));
        }
        if matches!(&request.payload, FederatedIqPayload::RegisterGet) {
            let payload = if let Some(nick) = reserved_nick {
                XmlElement::namespaced("query", "jabber:iq:register")
                    .child(XmlElement::new("registered"))
                    .child(XmlElement::new("username").text(nick))
                    .finish()
            } else {
                XmlElement::namespaced("query", "jabber:iq:register")
                    .child(
                        XmlElement::namespaced("x", "jabber:x:data")
                            .attr("type", "form")
                            .child(XmlElement::new("title").text(format!(
                                "{} Registration",
                                room.title.as_deref().unwrap_or(&room.localpart)
                            )))
                            .child(
                                XmlElement::new("instructions")
                                    .text("Choose the nickname to reserve in this room."),
                            )
                            .child(xdata_value_field(
                                "FORM_TYPE",
                                "hidden",
                                "http://jabber.org/protocol/muc#register",
                            ))
                            .child(
                                XmlElement::new("field")
                                    .attr("var", "muc#register_roomnick")
                                    .attr("type", "text-single")
                                    .child(XmlElement::new("required")),
                            ),
                    )
                    .finish()
            };
            return Ok(Some(federated_iq_result(
                &request.stanza,
                &room_jid,
                &actor_full_jid,
                &payload,
            )));
        }
        let action = match parse_federated_registration_action(&request.stanza.raw) {
            Ok(action) => action,
            Err(condition) => {
                return Ok(federated_error(&request.stanza, from, "modify", condition));
            }
        };
        let local_registration_guard = if state.federated_muc_pg_authority_enabled() {
            None
        } else {
            Some(state.muc_service().lock_local_room_mutation(room.id).await)
        };
        let room = if local_registration_guard.is_some() {
            let Some(refreshed_room) = state
                .muc_service()
                .federated_room_snapshot(localpart(&room_jid))
                .await?
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            };
            if refreshed_room.room_epoch != room.room_epoch {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
            if !refreshed_room.allow_registration {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "not-allowed",
                ));
            }
            refreshed_room
        } else {
            room
        };
        let (affiliation_changed, previous_affiliation, affiliation, notice_nick) = match action {
            FederatedRegistrationAction::Remove => {
                if state.federated_muc_pg_authority_enabled() {
                    state.federated_muc_admit_mutation()?;
                    let operation_id = uuid::Uuid::new_v4();
                    let outcome = state
                        .muc_service()
                        .mutate_local_cluster_registration(
                            operation_id,
                            room.id,
                            room.room_epoch,
                            room.config_version,
                            &ClusterMucPrincipal::Federated {
                                bare_jid: actor_bare_jid.clone(),
                                authenticated_domain: authenticated_domain.to_owned(),
                            },
                            &actor_full_jid,
                            None,
                        )
                        .await?;
                    return match outcome {
                        ClusterMucRegistrationOutcome::Applied { .. }
                        | ClusterMucRegistrationOutcome::Replay { .. } => {
                            Ok(committed_registration_reply(
                                state.wake_committed_muc_operation(operation_id),
                                operation_id,
                                &request.stanza,
                                &room_jid,
                                &actor_full_jid,
                            )
                            .await)
                        }
                        ClusterMucRegistrationOutcome::Conflict => {
                            Ok(federated_error(&request.stanza, from, "cancel", "conflict"))
                        }
                        ClusterMucRegistrationOutcome::Outcast
                        | ClusterMucRegistrationOutcome::NotAllowed => {
                            Ok(federated_error(&request.stanza, from, "auth", "forbidden"))
                        }
                        ClusterMucRegistrationOutcome::Stale
                        | ClusterMucRegistrationOutcome::Destroyed => Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        )),
                    };
                }
                let changed = state
                    .muc_service()
                    .unregister_federated_member(room.id, &actor_bare_jid)
                    .await?;
                (changed, "member", "none", None)
            }
            FederatedRegistrationAction::Register(nick) => {
                if state.federated_muc_pg_authority_enabled() {
                    state.federated_muc_admit_mutation()?;
                    let operation_id = uuid::Uuid::new_v4();
                    let outcome = state
                        .muc_service()
                        .mutate_local_cluster_registration(
                            operation_id,
                            room.id,
                            room.room_epoch,
                            room.config_version,
                            &ClusterMucPrincipal::Federated {
                                bare_jid: actor_bare_jid.clone(),
                                authenticated_domain: authenticated_domain.to_owned(),
                            },
                            &actor_full_jid,
                            Some(&nick),
                        )
                        .await?;
                    return match outcome {
                        ClusterMucRegistrationOutcome::Applied { .. }
                        | ClusterMucRegistrationOutcome::Replay { .. } => {
                            Ok(committed_registration_reply(
                                state.wake_committed_muc_operation(operation_id),
                                operation_id,
                                &request.stanza,
                                &room_jid,
                                &actor_full_jid,
                            )
                            .await)
                        }
                        ClusterMucRegistrationOutcome::Conflict => {
                            Ok(federated_error(&request.stanza, from, "cancel", "conflict"))
                        }
                        ClusterMucRegistrationOutcome::Outcast
                        | ClusterMucRegistrationOutcome::NotAllowed => {
                            Ok(federated_error(&request.stanza, from, "auth", "forbidden"))
                        }
                        ClusterMucRegistrationOutcome::Stale
                        | ClusterMucRegistrationOutcome::Destroyed => Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        )),
                    };
                }
                let mut occupants = state.federated_muc_global_occupants(&room_jid).await?;
                for (_, occupant) in state.muc_occupants_for(&room_jid) {
                    occupants.insert(
                        occupant.nick.clone(),
                        serde_json::to_string(&SerializableMucOccupant::from(&occupant))?,
                    );
                }
                if occupants.get(&nick).is_some_and(|json| {
                    serde_json::from_str::<SerializableMucOccupant>(json)
                        .ok()
                        .is_some_and(|occupant| {
                            northstar_xmpp_types::jid::canonical_bare_key(&occupant.full_jid)
                                .ok()
                                .as_deref()
                                != Some(actor_bare_jid.as_str())
                        })
                }) {
                    return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                }
                let changed = match state
                    .muc_service()
                    .register_federated_member(room.id, &actor_bare_jid, &nick)
                    .await?
                {
                    MucRegistrationOutcome::Registered {
                        affiliation_changed,
                    } => affiliation_changed,
                    MucRegistrationOutcome::Conflict => {
                        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                    }
                    MucRegistrationOutcome::Outcast => {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                };
                (changed, "none", "member", Some(nick))
            }
        };
        let joined = state
            .muc_occupants_for(&room_jid)
            .into_iter()
            .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid));
        let target_is_occupant = joined.is_some();
        if let Some((_, own)) = joined {
            let affiliation = state
                .muc_service()
                .federated_affiliation(room.id, &actor_bare_jid)
                .await?
                .unwrap_or_else(|| "none".to_owned());
            publish_occupant_change(
                state,
                &room,
                &own,
                own.clone(),
                OccupantChange {
                    affiliation: Some(&affiliation),
                    role: None,
                    reason: None,
                },
            )
            .await?;
        }
        drop(local_registration_guard);
        if affiliation_changed
            && super::super::muc::should_broadcast_offline_affiliation_change(
                room.non_anonymous,
                target_is_occupant,
                previous_affiliation,
                affiliation,
            )
        {
            super::super::muc::deliver_muc_offline_affiliation_change_notice(
                state,
                &room_jid,
                &actor_bare_jid,
                affiliation,
                notice_nick.as_deref(),
                None,
            )
            .await;
        }
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &room_jid,
            &actor_full_jid,
            "",
        )));
    }

    let own = if view_kind == MucRoomViewKind::Items {
        None
    } else {
        let own = state
            .muc_occupants_for(&room_jid)
            .into_iter()
            .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid));
        match own {
            Some((_, own)) if federated_endpoint_matches(&own, authenticated_domain) => Some(own),
            None if !to.contains('/')
                && state.federated_muc_pg_authority_enabled()
                && matches!(&request.payload, FederatedIqPayload::AdminSet { .. }) =>
            {
                let FederatedIqPayload::AdminSet { items } = request.payload else {
                    unreachable!()
                };
                return federated_muc_admin_set(
                    state,
                    &request.stanza,
                    &room,
                    FederatedMucAdminActor {
                        requester: None,
                        authenticated_domain,
                        connection_id,
                        full_jid: &actor_full_jid,
                    },
                    items,
                )
                .await;
            }
            _ => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "not-authorized",
                ));
            }
        }
    };
    match request.payload {
        FederatedIqPayload::DiscoItems(disco) if disco.node.is_none() => {
            let occupants = nicks;
            let cursor = disco
                .after
                .as_deref()
                .or_else(|| disco.before.as_ref().and_then(|value| value.as_deref()));
            if cursor.is_some_and(|cursor| !occupants.iter().any(|nick| nick == cursor)) {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
            let total = occupants.len() as i64;
            let mut page = occupants
                .iter()
                .filter(|nick| {
                    disco
                        .after
                        .as_deref()
                        .is_none_or(|after| nick.as_str() > after)
                        && disco
                            .before
                            .as_ref()
                            .and_then(|value| value.as_deref())
                            .is_none_or(|before| nick.as_str() < before)
                })
                .collect::<Vec<_>>();
            if disco.before.is_some() {
                page.reverse();
            }
            page.truncate(disco.max.clamp(0, 100) as usize);
            if disco.before.is_some() {
                page.reverse();
            }
            let first_index = page
                .first()
                .and_then(|first| occupants.iter().position(|nick| nick == *first))
                .map_or(0, |index| index as i64);
            let mut payload =
                XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
            for nick in &page {
                payload
                    .push_child(XmlElement::new("item").attr("jid", format!("{room_jid}/{nick}")));
            }
            payload.push_validated_fragment(&northstar_xml_builder::disco::disco_rsm_result(
                page.first().map(|nick| nick.as_str()),
                page.last().map(|nick| nick.as_str()),
                first_index,
                total,
            ))?;
            let payload = payload.finish();
            Ok(Some(federated_iq_result(
                &request.stanza,
                &room_jid,
                &actor_full_jid,
                &payload,
            )))
        }
        FederatedIqPayload::DiscoItemsError(condition) => {
            Ok(federated_error(&request.stanza, from, "modify", condition))
        }
        FederatedIqPayload::OwnerSet => {
            federated_muc_owner(
                state,
                &request.stanza,
                &room,
                own.as_ref().expect("owner set has an actor"),
            )
            .await
        }
        FederatedIqPayload::AdminSet { items } => {
            federated_muc_admin_set(
                state,
                &request.stanza,
                &room,
                FederatedMucAdminActor {
                    requester: own.as_ref(),
                    authenticated_domain,
                    connection_id,
                    full_jid: &actor_full_jid,
                },
                items,
            )
            .await
        }
        FederatedIqPayload::AdminError(condition) => {
            Ok(federated_error(&request.stanza, from, "modify", condition))
        }
        FederatedIqPayload::Moderate {
            target,
            reason,
            has_retract,
        } => {
            federated_muc_moderate(
                state,
                &request.stanza,
                &room,
                own.as_ref().expect("moderation has an actor"),
                target,
                reason,
                has_retract,
            )
            .await
        }
        _ => Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "feature-not-implemented",
        )),
    }
}

fn federated_mam_occupancy_proof<L, S>(
    occupants: &[(String, MucOccupant<L, S>)],
    actor_full_jid: &str,
) -> Option<MamOccupancyProof> {
    occupants
        .iter()
        .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, actor_full_jid))
        .map(|(_, occupant)| MamOccupancyProof {
            occupant_incarnation: occupant.cluster_epoch,
            connection_uuid: occupant.connection_id,
        })
}

async fn federated_muc_mam_iq(
    state: &impl MucHost,
    authenticated_domain: &str,
    request: &FederatedIqRequest,
    room_jid: &str,
    actor_full_jid: &str,
) -> Result<Option<String>> {
    let from = request.stanza.from.as_str();
    let room_localpart = localpart(room_jid);
    if !state.xmpp_extension_enabled(northstar_xep_0313::XEP_ID) {
        let visible = state
            .federated_mam_room_visible(room_localpart, actor_full_jid)
            .await?;
        let condition = if visible {
            "feature-not-implemented"
        } else {
            "item-not-found"
        };
        return Ok(federated_error(&request.stanza, from, "cancel", condition));
    }
    let occupancy =
        federated_mam_occupancy_proof(&state.muc_occupants_for(room_jid), actor_full_jid);
    let authority = MamRoomReadAuthority {
        full_jid: actor_full_jid.to_owned(),
        occupancy,
    };
    match &request.payload {
        FederatedIqPayload::MamForm => match state
            .authorize_federated_room(room_localpart, &authority)
            .await?
        {
            MamRoomAccessOutcome::Allowed(_) => Ok(Some(federated_iq_result(
                &request.stanza,
                room_jid,
                actor_full_jid,
                mam_extended_form(),
            ))),
            MamRoomAccessOutcome::Missing => Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            )),
            MamRoomAccessOutcome::Forbidden | MamRoomAccessOutcome::StaleAccount => {
                Ok(federated_error(&request.stanza, from, "auth", "forbidden"))
            }
        },
        FederatedIqPayload::MamMetadata => {
            let Some(command) = FederatedMamMetadataCommand::from_authenticated_actor(
                room_localpart.to_owned(),
                authenticated_domain,
                actor_full_jid,
                occupancy,
            ) else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "not-authorized",
                ));
            };
            let (access, first, last) = match state.execute_federated_mam_metadata(command).await? {
                MamMetadataResult::Boundaries {
                    room: Some(access),
                    start,
                    end,
                } => (access, start, end),
                MamMetadataResult::Boundaries { room: None, .. } => {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                }
                MamMetadataResult::ItemNotFound => {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                }
                MamMetadataResult::Forbidden | MamMetadataResult::StaleAccount => {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                }
            };
            debug_assert_eq!(access.localpart(), room_localpart);
            let mut metadata = XmlElement::namespaced("metadata", "urn:xmpp:mam:2");
            if let Some(value) = first {
                metadata.push_child(
                    XmlElement::new("start").attr("id", value.id).attr(
                        "timestamp",
                        value
                            .created_at
                            .to_rfc3339_opts(northstar_time::SecondsFormat::Millis, true),
                    ),
                );
            }
            if let Some(value) = last {
                metadata.push_child(
                    XmlElement::new("end").attr("id", value.id).attr(
                        "timestamp",
                        value
                            .created_at
                            .to_rfc3339_opts(northstar_time::SecondsFormat::Millis, true),
                    ),
                );
            }
            Ok(Some(federated_iq_result(
                &request.stanza,
                room_jid,
                actor_full_jid,
                &metadata.finish(),
            )))
        }
        FederatedIqPayload::MamError(condition) => {
            match state
                .authorize_federated_room(room_localpart, &authority)
                .await?
            {
                MamRoomAccessOutcome::Allowed(_) => {}
                MamRoomAccessOutcome::Missing => {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                }
                MamRoomAccessOutcome::Forbidden | MamRoomAccessOutcome::StaleAccount => {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                }
            }
            let error_type = if *condition == "resource-constraint" {
                "wait"
            } else if matches!(*condition, "bad-request" | "jid-malformed") {
                "modify"
            } else {
                "cancel"
            };
            Ok(federated_error(
                &request.stanza,
                from,
                error_type,
                condition,
            ))
        }
        FederatedIqPayload::MamQuery(query) => {
            federated_muc_mam(
                state,
                authenticated_domain,
                &request.stanza,
                (room_localpart, &authority),
                (room_jid, actor_full_jid),
                query.clone(),
            )
            .await
        }
        _ => unreachable!(),
    }
}

async fn federated_muc_mam(
    state: &impl MucHost,
    authenticated_domain: &str,
    stanza: &FederatedStanza,
    authorization: (&str, &MamRoomReadAuthority),
    delivery: (&str, &str),
    query: FederatedMamQuery,
) -> Result<Option<String>> {
    let (room_localpart, authority) = authorization;
    let (room_jid, recipient) = delivery;
    let result_id_seed = uuid::Uuid::new_v4();
    let outcome = state
        .admit_federated_room_stream(
            northstar_archive_core::FederatedMamStreamRequest::new(
                authenticated_domain,
                room_localpart,
                authority,
                &query.query,
            ),
            |page| {
                render_federated_mam_stream(
                    page,
                    room_jid,
                    recipient,
                    stanza.id.as_deref().unwrap_or_default(),
                    query.query_id.as_deref(),
                    query.flip_page,
                    result_id_seed,
                )
            },
        )
        .await;
    let outcome = match outcome {
        Err(error) if error.is::<MucMamProjectionError>() => {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "wait",
                "internal-server-error",
            ));
        }
        result => result?,
    };
    match outcome {
        northstar_archive_core::FederatedMamAdmissionOutcome::Queued => Ok(None),
        northstar_archive_core::FederatedMamAdmissionOutcome::Missing
        | northstar_archive_core::FederatedMamAdmissionOutcome::PageMissing => Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        )),
        northstar_archive_core::FederatedMamAdmissionOutcome::Forbidden => {
            Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"))
        }
        northstar_archive_core::FederatedMamAdmissionOutcome::OutboxRejected => Ok(
            federated_error(stanza, &stanza.from, "wait", "remote-server-timeout"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn occupant(
        full_jid: &str,
        incarnation: u128,
        connection: u128,
    ) -> (String, MucOccupant<(), ()>) {
        let nick = format!("nick-{incarnation}");
        let connection_id = Uuid::from_u128(connection);
        (
            nick.clone(),
            MucOccupant {
                full_jid: full_jid.to_owned(),
                room_jid: "room@conference.local.test".to_owned(),
                nick,
                endpoint: MucOccupantEndpoint::Federated {
                    authenticated_domain: "remote.test".to_owned(),
                    connection_id,
                },
                affiliation: "member".to_owned(),
                role: "participant".to_owned(),
                room_non_anonymous: false,
                occupant_id: String::new(),
                cluster_epoch: Uuid::from_u128(incarnation),
                connection_id,
                sm_session_id: None,
                payload: String::new(),
            },
        )
    }

    #[test]
    fn federated_mam_proof_comes_from_the_matching_full_actor() {
        let occupants = [
            occupant("bob@remote.test/Phone", 1, 11),
            occupant("alice@remote.test/Tablet", 2, 22),
            occupant("Alice@REMOTE.test/Phone", 3, 33),
        ];
        assert_eq!(
            federated_mam_occupancy_proof(&occupants, "alice@remote.test/Phone"),
            Some(MamOccupancyProof {
                occupant_incarnation: Uuid::from_u128(3),
                connection_uuid: Uuid::from_u128(33),
            })
        );
        assert_eq!(
            federated_mam_occupancy_proof(&occupants, "alice@remote.test/phone"),
            None
        );
    }
}
