//! Federated MUC owner handling for remote room actors.

use super::admin::{publish_occupant_change, OccupantChange};
use super::*;

#[derive(Debug)]
pub(super) struct FederatedRoomConfig {
    pub(super) title: Option<String>,
    description: Option<String>,
    persistent: bool,
    members_only: bool,
    pub(super) public: bool,
    moderated: bool,
    pub(super) non_anonymous: bool,
    max_occupants: i32,
    password_secret: Option<String>,
    keep_password_hash: bool,
    allow_subject_change: bool,
    allow_invites: bool,
    allow_private_messages: bool,
    logging_enabled: bool,
    allow_registration: bool,
}

pub(super) enum FederatedOwnerAction {
    Cancel,
    Destroy {
        alternate: Option<String>,
        reason: Option<String>,
    },
    Configure(FederatedRoomConfig),
}

pub(super) enum FederatedRegistrationAction {
    Remove,
    Register(String),
}

pub(super) fn parse_federated_registration_action(
    raw: &str,
) -> std::result::Result<FederatedRegistrationAction, &'static str> {
    let document = roxmltree::Document::parse(raw).map_err(|_| "bad-request")?;
    let query = document
        .root_element()
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "query"
                && node.tag_name().namespace() == Some("jabber:iq:register")
        })
        .ok_or("bad-request")?;
    let elements = query
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if elements.len() == 1
        && elements[0].tag_name().name() == "remove"
        && elements[0].tag_name().namespace() == Some("jabber:iq:register")
        && !elements[0].children().any(|node| node.is_element())
    {
        return Ok(FederatedRegistrationAction::Remove);
    }
    if elements.len() != 1
        || elements[0].tag_name().name() != "x"
        || elements[0].tag_name().namespace() != Some("jabber:x:data")
        || elements[0].attribute("type") != Some("submit")
        || xdata_field(elements[0], "FORM_TYPE") != Some("http://jabber.org/protocol/muc#register")
    {
        return Err("bad-request");
    }
    let nick = xdata_field(elements[0], "muc#register_roomnick").ok_or("bad-request")?;
    let nick = prepare_muc_nick(nick).map_err(|_| "not-acceptable")?;
    Ok(FederatedRegistrationAction::Register(nick))
}

fn federated_owner_form(room: &MucRoom) -> String {
    super::super::muc::muc_room_configuration_form(
        room,
        if room.non_anonymous {
            "anyone"
        } else {
            "moderators"
        },
    )
}

pub(super) fn parse_federated_owner_action(
    raw: &str,
    room: &MucRoom,
) -> std::result::Result<FederatedOwnerAction, &'static str> {
    let document = roxmltree::Document::parse(raw).map_err(|_| "bad-request")?;
    let root = document.root_element();
    let query = root
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "query"
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#owner")
        })
        .ok_or("bad-request")?;
    let children = query
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if children.len() != 1 {
        return Err("bad-request");
    }
    let child = children[0];
    if child.tag_name().name() == "destroy"
        && child.tag_name().namespace() == Some("http://jabber.org/protocol/muc#owner")
    {
        if child
            .children()
            .filter(|node| node.is_element())
            .any(|node| {
                node.tag_name().name() != "reason"
                    || node.tag_name().namespace() != Some("http://jabber.org/protocol/muc#owner")
            })
        {
            return Err("bad-request");
        }
        let alternate = child
            .attribute("jid")
            .map(northstar_xmpp_types::jid::canonicalize_bare)
            .transpose()
            .map_err(|_| "jid-malformed")?;
        let reason = child_text(child, "reason").map(str::to_owned);
        if reason.as_ref().is_some_and(|value| value.len() > 4096) {
            return Err("not-acceptable");
        }
        return Ok(FederatedOwnerAction::Destroy { alternate, reason });
    }
    if child.tag_name().name() != "x" || child.tag_name().namespace() != Some("jabber:x:data") {
        return Err("bad-request");
    }
    if child.attribute("type") == Some("cancel") {
        return Ok(FederatedOwnerAction::Cancel);
    }
    if !matches!(child.attribute("type"), None | Some("submit"))
        || xdata_field(child, "FORM_TYPE")
            .is_some_and(|value| value != "http://jabber.org/protocol/muc#roomconfig")
    {
        return Err("bad-request");
    }
    let title = xdata_field(child, "muc#roomconfig_roomname")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| room.title.clone())
        .or_else(|| Some(room.localpart.clone()));
    if title.as_ref().is_some_and(|value| value.len() > 255) {
        return Err("not-acceptable");
    }
    let description = xdata_field(child, "muc#roomconfig_roomdesc")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| room.description.clone());
    if description.as_ref().is_some_and(|value| value.len() > 4096) {
        return Err("not-acceptable");
    }
    let read_bool = |name, fallback| {
        xdata_bool(child, name)
            .map(|value| value.unwrap_or(fallback))
            .map_err(|()| "bad-request")
    };
    let persistent = read_bool("muc#roomconfig_persistentroom", room.persistent)?;
    let members_only = read_bool("muc#roomconfig_membersonly", room.members_only)?;
    let public = read_bool("muc#roomconfig_publicroom", room.public)?;
    let moderated = read_bool("muc#roomconfig_moderatedroom", room.moderated)?;
    let allow_subject_change =
        read_bool("muc#roomconfig_changesubject", room.allow_subject_change)?;
    let allow_invites = read_bool("muc#roomconfig_allowinvites", room.allow_invites)?;
    let logging_enabled = read_bool("muc#roomconfig_enablelogging", room.logging_enabled)?;
    let allow_registration = read_bool("muc#roomconfig_allowregister", room.allow_registration)?;
    let non_anonymous = match xdata_field(child, "muc#roomconfig_whois") {
        None => room.non_anonymous,
        Some("anyone") => true,
        Some("moderators") => false,
        Some(_) => return Err("bad-request"),
    };
    let allow_private_messages = match xdata_field(child, "muc#roomconfig_allowpm") {
        None => room.allow_private_messages,
        Some("anyone") => true,
        Some("none") => false,
        Some(_) => return Err("bad-request"),
    };
    let max_occupants = match xdata_field(child, "muc#roomconfig_maxusers") {
        None => room.max_occupants,
        Some(value) => value
            .parse::<i32>()
            .ok()
            .filter(|value| (2..=1000).contains(value))
            .ok_or("not-acceptable")?,
    };
    let password_protected = read_bool(
        "muc#roomconfig_passwordprotectedroom",
        room.password_hash.is_some(),
    )?;
    let password_secret = xdata_field(child, "muc#roomconfig_roomsecret")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if password_protected && password_secret.is_none() && room.password_hash.is_none() {
        return Err("bad-request");
    }
    Ok(FederatedOwnerAction::Configure(FederatedRoomConfig {
        title,
        description,
        persistent,
        members_only,
        public,
        moderated,
        non_anonymous,
        max_occupants,
        password_secret,
        keep_password_hash: password_protected && room.password_hash.is_some(),
        allow_subject_change,
        allow_invites,
        allow_private_messages,
        logging_enabled,
        allow_registration,
    }))
}

pub(super) async fn federated_muc_owner(
    state: &AppState,
    stanza: &FederatedStanza,
    room: &MucRoom,
    requester: &MucOccupant,
    set: bool,
) -> Result<Option<String>> {
    let mut guarded_room = None;
    let mut guarded_requester = None;
    let _local_room_guard = if set && !state.federated_muc_pg_authority_enabled() {
        let guard = state.muc_service().lock_local_room_mutation(room.id).await;
        let Some(refreshed_room) = state
            .muc_service()
            .federated_room_snapshot(&room.localpart)
            .await?
        else {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "cancel",
                "item-not-found",
            ));
        };
        if refreshed_room.room_epoch != room.room_epoch {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "cancel",
                "item-not-found",
            ));
        }
        let Some(mut current_requester) = state
            .muc_occupants_for(&requester.room_jid)
            .into_iter()
            .map(|(_, occupant)| occupant)
            .find(|occupant| {
                occupant.full_jid == requester.full_jid
                    && occupant.connection_id == requester.connection_id
                    && occupant.cluster_epoch == requester.cluster_epoch
            })
        else {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        };
        current_requester.affiliation = state
            .muc_service()
            .federated_affiliation(refreshed_room.id, bare_jid(&current_requester.full_jid))
            .await?
            .unwrap_or_else(|| "none".to_owned());
        guarded_room = Some(refreshed_room);
        guarded_requester = Some(current_requester);
        Some(guard)
    } else {
        None
    };
    let room = guarded_room.as_ref().unwrap_or(room);
    let requester = guarded_requester.as_ref().unwrap_or(requester);
    if requester.affiliation != "owner" {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    if room.configuration_is_expired(chrono::Utc::now()) {
        let _ = state
            .muc_service()
            .delete_expired_locked_room(room.id)
            .await?;
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        ));
    }
    if room.is_locked() && !room.can_configure_locked_room(&requester.full_jid, chrono::Utc::now())
    {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    if !set {
        return Ok(Some(federated_iq_result(
            stanza,
            &requester.room_jid,
            &requester.full_jid,
            &federated_owner_form(room),
        )));
    }
    let action = match parse_federated_owner_action(&stanza.raw, room) {
        Ok(action) => action,
        Err(condition) => {
            return Ok(federated_error(stanza, &stanza.from, "modify", condition));
        }
    };
    match action {
        FederatedOwnerAction::Cancel => {
            if room.is_locked() {
                state
                    .muc_service()
                    .cancel_locked_room(room.id, &requester.full_jid)
                    .await?;
                for (_, occupant) in state.muc_occupants_for(&requester.room_jid) {
                    let Some(occupant) = state.remove_local_muc_occupant_exact((&occupant).into())
                    else {
                        continue;
                    };
                    let serializable = SerializableMucOccupant::from(&occupant);
                    state.remove_live_muc_membership(&serializable);
                    if !state.federated_muc_pg_authority_enabled() {
                        let unavailable = muc_destroy_presence(&serializable, None, None);
                        let _ = state.deliver_to_muc_occupant(&occupant, unavailable).await;
                    }
                }
            }
        }
        FederatedOwnerAction::Destroy { alternate, reason } => {
            let mut cluster_operation = None;
            if state.federated_muc_pg_authority_enabled() {
                state.federated_muc_admit_mutation()?;
                let Some(actor_target) = state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        requester.cluster_epoch,
                        requester.connection_id,
                    )
                    .await?
                else {
                    return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
                };
                let operation_id = uuid::Uuid::new_v4();
                match state
                    .muc_service()
                    .destroy_local_cluster_room(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        Some(&actor_target),
                        "federated_verified",
                        Some(&requester.full_jid),
                        alternate.as_deref(),
                        reason.as_deref(),
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        cluster_operation = Some(operation_id)
                    }
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
                    }
                    ClusterMucTransitionOutcome::Stale
                    | ClusterMucTransitionOutcome::Destroyed
                    | ClusterMucTransitionOutcome::Conflict => {
                        return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
                    }
                }
            } else {
                state.muc_service().delete_room(room.id).await?;
            }
            for (_, occupant) in state.muc_occupants_for(&requester.room_jid) {
                let Some(occupant) = state.remove_local_muc_occupant_exact((&occupant).into())
                else {
                    continue;
                };
                let serializable = SerializableMucOccupant::from(&occupant);
                state.remove_live_muc_membership(&serializable);
                if cluster_operation.is_none() {
                    let unavailable = muc_destroy_presence(
                        &serializable,
                        alternate.as_deref(),
                        reason.as_deref(),
                    );
                    let _ = state.deliver_to_muc_occupant(&occupant, unavailable).await;
                }
            }
            if let Some(operation_id) = cluster_operation {
                if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                    tracing::warn!(?error, %operation_id, room=%requester.room_jid,
                        "federated MUC destroy committed; signed wake will be recovered by polling");
                }
            }
        }
        FederatedOwnerAction::Configure(config) => {
            let replacement_password_hash = if let Some(secret) = config.password_secret {
                let secret = zeroize::Zeroizing::new(secret);
                match crate::security::password_work::run(move || {
                    crate::services::muc::hash_room_password(&secret)
                })
                .await
                {
                    Ok(hash) => Some(hash),
                    Err(error) if error.is_overloaded() => {
                        return Ok(federated_error(
                            stanza,
                            &stanza.from,
                            "wait",
                            "resource-constraint",
                        ));
                    }
                    Err(error) => {
                        return Err(anyhow::anyhow!("room password hashing failed: {error}"));
                    }
                }
            } else if config.keep_password_hash {
                room.password_hash.clone()
            } else {
                None
            };
            let mut cluster_operation = None;
            let outcome = if state.federated_muc_pg_authority_enabled() {
                state.federated_muc_admit_mutation()?;
                let authenticated_domain = match &requester.endpoint {
                    crate::xmpp::local_routes::muc::MucOccupantEndpoint::Federated {
                        authenticated_domain,
                        ..
                    } => authenticated_domain.clone(),
                    _ => anyhow::bail!("federated MUC owner lost its S2S domain proof"),
                };
                let Some(actor_target) = state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        requester.cluster_epoch,
                        requester.connection_id,
                    )
                    .await?
                else {
                    return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
                };
                let operation_id = uuid::Uuid::new_v4();
                let clustered = state
                    .muc_service()
                    .update_local_cluster_config(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        room.config_version,
                        &actor_target,
                        &ClusterMucPrincipal::Federated {
                            bare_jid: bare_jid(&requester.full_jid).to_owned(),
                            authenticated_domain,
                        },
                        &requester.full_jid,
                        MucConfigUpdate {
                            title: config.title.as_deref(),
                            description: config.description.as_deref(),
                            persistent: config.persistent,
                            members_only: config.members_only,
                            public: config.public,
                            moderated: config.moderated,
                            non_anonymous: config.non_anonymous,
                            max_occupants: config.max_occupants,
                            password_hash: replacement_password_hash.as_deref(),
                            allow_subject_change: config.allow_subject_change,
                            allow_invites: config.allow_invites,
                            allow_private_messages: config.allow_private_messages,
                            logging_enabled: config.logging_enabled,
                            allow_registration: config.allow_registration,
                        },
                    )
                    .await?;
                cluster_operation = Some(operation_id);
                match clustered {
                    ClusterMucConfigurationOutcome::Applied
                    | ClusterMucConfigurationOutcome::Replay => MucConfigurationOutcome::Applied,
                    ClusterMucConfigurationOutcome::LockedByAnother
                    | ClusterMucConfigurationOutcome::Unauthorized => {
                        MucConfigurationOutcome::LockedByAnother
                    }
                    ClusterMucConfigurationOutcome::Expired => MucConfigurationOutcome::Expired,
                    ClusterMucConfigurationOutcome::Missing
                    | ClusterMucConfigurationOutcome::Stale
                    | ClusterMucConfigurationOutcome::Destroyed => MucConfigurationOutcome::Missing,
                }
            } else {
                state
                    .muc_service()
                    .update_local_legacy_config(
                        room.id,
                        &requester.full_jid,
                        MucConfigUpdate {
                            title: config.title.as_deref(),
                            description: config.description.as_deref(),
                            persistent: config.persistent,
                            members_only: config.members_only,
                            public: config.public,
                            moderated: config.moderated,
                            non_anonymous: config.non_anonymous,
                            max_occupants: config.max_occupants,
                            password_hash: replacement_password_hash.as_deref(),
                            allow_subject_change: config.allow_subject_change,
                            allow_invites: config.allow_invites,
                            allow_private_messages: config.allow_private_messages,
                            logging_enabled: config.logging_enabled,
                            allow_registration: config.allow_registration,
                        },
                    )
                    .await?
            };
            if outcome != MucConfigurationOutcome::Applied {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    if outcome == MucConfigurationOutcome::LockedByAnother {
                        "auth"
                    } else {
                        "cancel"
                    },
                    if outcome == MucConfigurationOutcome::LockedByAnother {
                        "forbidden"
                    } else {
                        "item-not-found"
                    },
                ));
            }
            if let Some(operation_id) = cluster_operation {
                if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                    tracing::warn!(?error, %operation_id, room=%requester.room_jid,
                        "federated MUC config committed; signed wake will be recovered by polling");
                }
                return Ok(Some(federated_iq_result(
                    stanza,
                    &requester.room_jid,
                    &requester.full_jid,
                    "",
                )));
            }
            let updated_room = state
                .muc_service()
                .federated_room_snapshot(&room.localpart)
                .await?
                .ok_or_else(|| anyhow::anyhow!("configured MUC room disappeared"))?;
            if state.federated_muc_pg_authority_enabled()
                && ((updated_room.members_only && !room.members_only)
                    || updated_room.moderated != room.moderated
                    || updated_room.non_anonymous != room.non_anonymous)
            {
                let global = state
                    .federated_muc_global_occupants(&requester.room_jid)
                    .await?;
                for (nick, raw) in global {
                    let Ok(mut occupant) =
                        serde_json::from_str::<crate::services::muc::SerializableMucOccupant>(&raw)
                    else {
                        continue;
                    };
                    if occupant.room_jid != requester.room_jid
                        || occupant.nick != nick
                        || occupant.cluster_epoch.is_nil()
                        || occupant.connection_id.is_nil()
                    {
                        continue;
                    }
                    let locally_owned =
                        state.local_muc_occupant_exact((&occupant).into()).is_some();
                    if locally_owned {
                        continue;
                    }
                    if updated_room.members_only
                        && !room.members_only
                        && occupant.affiliation == "none"
                    {
                        occupant.role = "none".to_owned();
                        if state
                            .federated_muc_evict_occupant(
                                &occupant,
                                322,
                                Some(&requester.nick),
                                None,
                            )
                            .await?
                        {
                            state
                                .federated_muc_publish_removal_presence(
                                    &requester.room_jid,
                                    &occupant,
                                    Some(322),
                                    Some(&requester.nick),
                                    None,
                                )
                                .await?;
                        }
                        continue;
                    }
                    let desired_role = if matches!(occupant.affiliation.as_str(), "owner" | "admin")
                    {
                        "moderator"
                    } else if updated_room.moderated && occupant.affiliation == "none" {
                        "visitor"
                    } else {
                        "participant"
                    };
                    if occupant.role != desired_role
                        || occupant.room_non_anonymous != updated_room.non_anonymous
                    {
                        let _ = state
                            .federated_muc_change_occupant_policy(
                                &requester.room_jid,
                                &occupant,
                                desired_role,
                                updated_room.non_anonymous,
                            )
                            .await?;
                    }
                }
            }
            for (_, mut occupant) in state.muc_occupants_for(&requester.room_jid) {
                if updated_room.members_only && !room.members_only && occupant.affiliation == "none"
                {
                    publish_occupant_change(
                        state,
                        &updated_room,
                        requester,
                        occupant,
                        OccupantChange {
                            affiliation: None,
                            role: Some("none"),
                            reason: None,
                        },
                    )
                    .await?;
                    continue;
                }
                let desired_role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                    "moderator"
                } else if updated_room.moderated && occupant.affiliation == "none" {
                    "visitor"
                } else {
                    "participant"
                };
                let visibility_changed = occupant.room_non_anonymous != updated_room.non_anonymous;
                occupant.room_non_anonymous = updated_room.non_anonymous;
                if occupant.role != desired_role || visibility_changed {
                    publish_occupant_change(
                        state,
                        &updated_room,
                        requester,
                        occupant,
                        OccupantChange {
                            affiliation: None,
                            role: Some(desired_role),
                            reason: None,
                        },
                    )
                    .await?;
                }
            }
            let mut statuses = vec!["104"];
            if config.logging_enabled != room.logging_enabled {
                statuses.push(if config.logging_enabled { "170" } else { "171" });
            }
            if config.non_anonymous != room.non_anonymous {
                statuses.push(if config.non_anonymous { "172" } else { "173" });
            }
            for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                let mut extension =
                    XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user");
                for code in &statuses {
                    extension.push_child(XmlElement::new("status").attr("code", code));
                }
                let notice = XmlElement::namespaced("message", "jabber:client")
                    .attr("from", &requester.room_jid)
                    .attr("to", &recipient.full_jid)
                    .attr("type", "groupchat")
                    .child(extension)
                    .finish();
                let _ = state.deliver_to_muc_occupant(&recipient, notice).await;
            }
        }
    }
    Ok(Some(federated_iq_result(
        stanza,
        &requester.room_jid,
        &requester.full_jid,
        "",
    )))
}
