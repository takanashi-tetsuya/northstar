//! Federated MUC IQ handling for remote room actors.

use super::admin::{
    federated_muc_admin_get, federated_muc_admin_set, publish_occupant_change,
    FederatedMucAdminActor, OccupantChange,
};
use super::moderate::federated_muc_moderate;
use super::owner::{
    federated_muc_owner, parse_federated_registration_action, FederatedRegistrationAction,
};
use super::*;

/// Handle room/service IQs from an authenticated remote room actor. XML is
/// converted to owned data before this future is created, so S2S connection
/// tasks remain `Send` across database and network awaits.
pub(crate) fn federated_muc_iq<'a>(
    state: &'a AppState,
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
    state: &AppState,
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
    let actor_full_jid = crate::jid::canonicalize(from)
        .expect("authenticated_remote_actor already validated the full JID");
    let actor_bare_jid = crate::jid::canonical_bare_key(&actor_full_jid)?;
    let conference_domain = muc_domain(state);
    let Ok(to_jid) = crate::jid::CanonicalJid::parse(to) else {
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
            FederatedIqPayload::Ping => String::new(),
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
                query.push_validated_fragment(&super::super::discovery::disco_rsm_result(
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
    let Some(room) = state
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
    // Keep an unconfigured room invisible to every remote session except the
    // exact full JID that created it.  This matches the locked-room join and
    // owner-query boundary instead of leaking a reserved room via disco.
    if room.is_locked() && !room.can_configure_locked_room(&actor_full_jid, chrono::Utc::now()) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
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
        if let Some(nick) = state
            .muc_service()
            .federated_reserved_nick(room.id, &actor_bare_jid)
            .await?
        {
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
    if matches!(&request.payload, FederatedIqPayload::Ping) {
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &room_jid,
            &actor_full_jid,
            "",
        )));
    }

    if matches!(
        &request.payload,
        FederatedIqPayload::RegisterGet | FederatedIqPayload::RegisterSet
    ) {
        if room.is_locked() && !room.can_configure_locked_room(&actor_full_jid, chrono::Utc::now())
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
            let payload = if let Some(nick) = state
                .muc_service()
                .federated_reserved_nick(room.id, &actor_bare_jid)
                .await?
            {
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
                            state.wake_committed_muc_operation(operation_id).await?;
                            Ok(Some(federated_iq_result(
                                &request.stanza,
                                &room_jid,
                                &actor_full_jid,
                                "",
                            )))
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
                            state.wake_committed_muc_operation(operation_id).await?;
                            Ok(Some(federated_iq_result(
                                &request.stanza,
                                &room_jid,
                                &actor_full_jid,
                                "",
                            )))
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
                            crate::jid::canonical_bare_key(&occupant.full_jid)
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

    if matches!(
        &request.payload,
        FederatedIqPayload::MamForm
            | FederatedIqPayload::MamQuery(_)
            | FederatedIqPayload::MamMetadata
            | FederatedIqPayload::MamError(_)
    ) {
        if !state.xmpp_extension_enabled(northstar_xep_0313::XEP_ID) {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "feature-not-implemented",
            ));
        }
        let joined = state
            .muc_occupants_for(&room_jid)
            .iter()
            .any(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid));
        return match &request.payload {
            FederatedIqPayload::MamForm => match state
                .mam_service()
                .authorize_federated_room(&room.localpart, &actor_bare_jid, joined)
                .await?
            {
                crate::services::mam::MamRoomAccessOutcome::Allowed(_) => {
                    Ok(Some(federated_iq_result(
                        &request.stanza,
                        &room_jid,
                        &actor_full_jid,
                        mam_extended_form(),
                    )))
                }
                crate::services::mam::MamRoomAccessOutcome::Missing => Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                )),
                crate::services::mam::MamRoomAccessOutcome::Forbidden => {
                    Ok(federated_error(&request.stanza, from, "auth", "forbidden"))
                }
            },
            FederatedIqPayload::MamMetadata => {
                let Some(command) = FederatedMamMetadataCommand::from_authenticated_actor(
                    room.localpart.clone(),
                    authenticated_domain,
                    &actor_full_jid,
                    joined,
                ) else {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "auth",
                        "not-authorized",
                    ));
                };
                let (access, first, last) = match state
                    .mam_service()
                    .execute_federated_mam_metadata(command)
                    .await?
                {
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
                    MamMetadataResult::Forbidden => {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                };
                debug_assert_eq!(access.localpart(), room.localpart);
                let mut metadata = XmlElement::namespaced("metadata", "urn:xmpp:mam:2");
                if let Some(value) = first {
                    metadata.push_child(
                        XmlElement::new("start").attr("id", value.id).attr(
                            "timestamp",
                            value
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ),
                    );
                }
                if let Some(value) = last {
                    metadata.push_child(
                        XmlElement::new("end").attr("id", value.id).attr(
                            "timestamp",
                            value
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ),
                    );
                }
                Ok(Some(federated_iq_result(
                    &request.stanza,
                    &room_jid,
                    &actor_full_jid,
                    &metadata.finish(),
                )))
            }
            FederatedIqPayload::MamError(condition) => {
                match state
                    .mam_service()
                    .authorize_federated_room(&room.localpart, &actor_bare_jid, joined)
                    .await?
                {
                    crate::services::mam::MamRoomAccessOutcome::Allowed(_) => {}
                    crate::services::mam::MamRoomAccessOutcome::Missing => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                    crate::services::mam::MamRoomAccessOutcome::Forbidden => {
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
                    (&room.localpart, &actor_bare_jid, joined),
                    (&room_jid, &actor_full_jid),
                    query.clone(),
                )
                .await
            }
            _ => unreachable!(),
        };
    }

    let own = state
        .muc_occupants_for(&room_jid)
        .into_iter()
        .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid));
    let own = match own {
        Some((_, own)) => own,
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
        None => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "auth",
                "not-authorized",
            ));
        }
    };
    if !federated_endpoint_matches(&own, authenticated_domain) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    // An IQ does not refresh occupancy ownership. Presence is the sole path
    // which can rebind a federated endpoint after exact authority checks.

    if to.contains('/') {
        let Some(target_nick) = to_jid.resourcepart() else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            ));
        };
        let Some(target) = state.local_muc_occupant_by_nick(&room_jid, target_nick) else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        };
        let forwarded = set_to(
            &set_from(&request.stanza.raw, &format!("{room_jid}/{}", own.nick)),
            &target.full_jid,
        );
        let blocked = state
            .blocked_muc_recipient_accounts(
                std::slice::from_ref(&target),
                &[format!("{room_jid}/{}", own.nick), actor_full_jid.clone()],
            )
            .await;
        if !crate::jid::canonical_bare_key(&target.full_jid)
            .is_ok_and(|owner| blocked.contains(&owner))
        {
            let _ = state
                .deliver_to_muc_occupant_unchecked(&target, forwarded)
                .await;
        }
        return Ok(None);
    }

    match request.payload {
        FederatedIqPayload::DiscoItems(disco) if disco.node.is_none() => {
            let mut occupant_map = state
                .federated_muc_global_occupants(&room_jid)
                .await?
                .into_values()
                .filter_map(|json| serde_json::from_str::<SerializableMucOccupant>(&json).ok())
                .map(|occupant| (occupant.nick.clone(), occupant))
                .collect::<std::collections::HashMap<_, _>>();
            for (_, occupant) in state.muc_occupants_for(&room_jid) {
                let occupant = SerializableMucOccupant::from(&occupant);
                occupant_map.insert(occupant.nick.clone(), occupant);
            }
            let mut occupants = occupant_map.into_values().collect::<Vec<_>>();
            occupants.sort_by(|left, right| left.nick.cmp(&right.nick));
            let cursor = disco
                .after
                .as_deref()
                .or_else(|| disco.before.as_ref().and_then(|value| value.as_deref()));
            if cursor.is_some_and(|cursor| !occupants.iter().any(|item| item.nick == cursor)) {
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
                .filter(|occupant| {
                    disco
                        .after
                        .as_deref()
                        .is_none_or(|after| occupant.nick.as_str() > after)
                        && disco
                            .before
                            .as_ref()
                            .and_then(|value| value.as_deref())
                            .is_none_or(|before| occupant.nick.as_str() < before)
                })
                .cloned()
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
                .and_then(|first| occupants.iter().position(|item| item.nick == first.nick))
                .map_or(0, |index| index as i64);
            let mut payload =
                XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
            for occupant in &page {
                payload.push_child(
                    XmlElement::new("item").attr("jid", format!("{}/{}", room_jid, occupant.nick)),
                );
            }
            payload.push_validated_fragment(&super::super::discovery::disco_rsm_result(
                page.first().map(|occupant| occupant.nick.as_str()),
                page.last().map(|occupant| occupant.nick.as_str()),
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
        FederatedIqPayload::AdminGet { affiliation, role } => {
            federated_muc_admin_get(state, &request.stanza, &room, &own, affiliation, role).await
        }
        FederatedIqPayload::OwnerGet => {
            federated_muc_owner(state, &request.stanza, &room, &own, false).await
        }
        FederatedIqPayload::OwnerSet => {
            federated_muc_owner(state, &request.stanza, &room, &own, true).await
        }
        FederatedIqPayload::AdminSet { items } => {
            federated_muc_admin_set(
                state,
                &request.stanza,
                &room,
                FederatedMucAdminActor {
                    requester: Some(&own),
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
                &own,
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

async fn federated_muc_mam(
    state: &AppState,
    authenticated_domain: &str,
    stanza: &FederatedStanza,
    authorization: (&str, &str, bool),
    delivery: (&str, &str),
    query: FederatedMamQuery,
) -> Result<Option<String>> {
    let (room_localpart, actor_bare_jid, joined) = authorization;
    let (room_jid, recipient) = delivery;
    let flip_page = query.flip_page;
    let query_id = query.query_id.clone();
    let outcome = state
        .mam_service()
        .admit_federated_room_stream(
            crate::services::mam::FederatedMamStreamRequest::new(
                authenticated_domain,
                room_localpart,
                actor_bare_jid,
                joined,
                &query.query,
            ),
            |page| {
                let access = page.access();
                let rows: Box<dyn Iterator<Item = _>> = if flip_page {
                    Box::new(page.rows().iter().rev())
                } else {
                    Box::new(page.rows().iter())
                };
                let mut responses = Vec::with_capacity(page.rows().len() + 1);
                for item in rows {
                    let occupant_id = muc_occupant_id(access.occupant_id_secret(), item.peer_jid());
                    let authoritative = set_muc_occupant_id(item.stanza(), &occupant_id);
                    let archived = if access.reveal_real_jid() {
                        add_muc_sender(&authoritative, item.peer_jid())
                    } else {
                        authoritative
                    };
                    let forwarded = XmlElement::namespaced("forwarded", "urn:xmpp:forward:0")
                        .child(
                            XmlElement::namespaced("delay", "urn:xmpp:delay").attr(
                                "stamp",
                                item.created_at()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                            ),
                        )
                        .validated_fragment(&archived)?;
                    let result = XmlElement::namespaced("result", "urn:xmpp:mam:2")
                        .attr("id", item.id())
                        .optional_attr("queryid", query_id.as_deref())
                        .child(forwarded);
                    responses.push(
                        XmlElement::namespaced("message", "jabber:client")
                            .attr("from", room_jid)
                            .attr("to", recipient)
                            .attr("id", uuid::Uuid::new_v4())
                            .child(result)
                            .finish(),
                    );
                }
                let mut rsm = XmlElement::namespaced("set", "http://jabber.org/protocol/rsm");
                if let (Some(first), Some(last)) = (page.rows().first(), page.rows().last()) {
                    rsm.push_child(
                        XmlElement::new("first")
                            .attr("index", page.first_index())
                            .text(first.id().to_string()),
                    );
                    rsm.push_child(XmlElement::new("last").text(last.id().to_string()));
                }
                rsm.push_child(XmlElement::new("count").text(page.total().to_string()));
                let fin = XmlElement::namespaced("fin", "urn:xmpp:mam:2")
                    .attr("complete", page.complete())
                    .attr("stable", "true")
                    .child(rsm)
                    .finish();
                responses.push(federated_iq_result(stanza, room_jid, recipient, &fin));
                Ok(responses)
            },
        )
        .await?;
    match outcome {
        crate::services::mam::FederatedMamAdmissionOutcome::Queued => Ok(None),
        crate::services::mam::FederatedMamAdmissionOutcome::Missing
        | crate::services::mam::FederatedMamAdmissionOutcome::PageMissing => Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        )),
        crate::services::mam::FederatedMamAdmissionOutcome::Forbidden => {
            Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"))
        }
        crate::services::mam::FederatedMamAdmissionOutcome::OutboxRejected => Ok(federated_error(
            stanza,
            &stanza.from,
            "wait",
            "remote-server-timeout",
        )),
    }
}
