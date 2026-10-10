//! Federated MUC admin handling.

use super::*;

pub(super) async fn federated_muc_admin_get(
    state: &AppState,
    stanza: &FederatedStanza,
    room: &MucRoom,
    requester: &MucOccupant,
    requested_affiliation: Option<String>,
    requested_role: Option<String>,
) -> Result<Option<String>> {
    if requested_affiliation.is_some() == requested_role.is_some() {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }
    if let Some(requested) = requested_role {
        if !matches!(requested.as_str(), "moderator" | "participant" | "visitor") {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "modify",
                "bad-request",
            ));
        }
        if requester.role != "moderator"
            && !matches!(requester.affiliation.as_str(), "owner" | "admin")
        {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        }
        let mut occupant_map = state
            .federated_muc_global_occupants(&requester.room_jid)
            .await?
            .into_values()
            .filter_map(|json| serde_json::from_str::<SerializableMucOccupant>(&json).ok())
            .map(|occupant| (occupant.nick.clone(), occupant))
            .collect::<std::collections::HashMap<_, _>>();
        for (_, occupant) in state.muc_occupants_for(&requester.room_jid) {
            let occupant = SerializableMucOccupant::from(&occupant);
            occupant_map.insert(occupant.nick.clone(), occupant);
        }
        let mut occupants = occupant_map
            .into_values()
            .filter(|occupant| occupant.role == requested)
            .collect::<Vec<_>>();
        occupants.sort_by(|left, right| left.nick.cmp(&right.nick));
        let mut payload = XmlElement::namespaced("query", "http://jabber.org/protocol/muc#admin");
        for occupant in occupants {
            payload.push_child(
                XmlElement::new("item")
                    .attr("nick", &occupant.nick)
                    .attr("role", &requested)
                    .optional_attr(
                        "jid",
                        (room.non_anonymous || requester.role == "moderator")
                            .then(|| bare_jid(&occupant.full_jid)),
                    ),
            );
        }
        let payload = payload.finish();
        return Ok(Some(federated_iq_result(
            stanza,
            &requester.room_jid,
            &requester.full_jid,
            &payload,
        )));
    }
    let requested = requested_affiliation.expect("exclusive affiliation/role check");
    if !can_retrieve_affiliations(
        &requester.affiliation,
        &requested,
        room.members_only,
        room.non_anonymous,
    ) {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    let mut payload = XmlElement::namespaced("query", "http://jabber.org/protocol/muc#admin");
    for username in state
        .muc_service()
        .local_affiliations(room.id, &requested)
        .await?
    {
        payload.push_child(
            XmlElement::new("item")
                .attr("affiliation", &requested)
                .attr("jid", format!("{}@{}", username, state.local_domain())),
        );
    }
    for jid in state
        .muc_service()
        .federated_affiliations(room.id, &requested)
        .await?
    {
        payload.push_child(
            XmlElement::new("item")
                .attr("affiliation", &requested)
                .attr("jid", &jid),
        );
    }
    let payload = payload.finish();
    Ok(Some(federated_iq_result(
        stanza,
        &requester.room_jid,
        &requester.full_jid,
        &payload,
    )))
}

pub(super) struct OccupantChange<'a> {
    pub(super) affiliation: Option<&'a str>,
    pub(super) role: Option<&'a str>,
    pub(super) reason: Option<&'a str>,
}

pub(super) async fn publish_occupant_change(
    state: &AppState,
    room: &MucRoom,
    actor: &MucOccupant,
    mut target: MucOccupant,
    change: OccupantChange<'_>,
) -> Result<()> {
    let proposed_affiliation = change.affiliation.unwrap_or(&target.affiliation).to_owned();
    let proposed_role = if let Some(role) = change.role {
        role
    } else {
        if matches!(proposed_affiliation.as_str(), "owner" | "admin") {
            "moderator"
        } else if room.moderated && proposed_affiliation == "none" {
            "visitor"
        } else {
            "participant"
        }
    };
    let removal_status = if proposed_affiliation == "outcast" {
        Some(301)
    } else if proposed_affiliation == "none" && room.members_only {
        Some(321)
    } else if proposed_role == "none" {
        Some(307)
    } else {
        None
    };
    let actor_nick = actor.nick.as_str();
    if let Some(status) = removal_status {
        let Some(mut departed) = state
            .remove_local_muc_occupant_exact(crate::state::LocalMucOccupantIdentity::from(&target))
        else {
            return Ok(());
        };
        departed.affiliation = proposed_affiliation.to_owned();
        departed.role = proposed_role.to_owned();
        departed.room_non_anonymous = target.room_non_anonymous;
        target = departed;
        let serializable = SerializableMucOccupant::from(&target);
        state
            .federated_muc_evict_occupant(&serializable, status, Some(actor_nick), change.reason)
            .await?;
        if state.muc_occupants_for(&target.room_jid).is_empty() {
            state.federated_muc_leave_room(&target.room_jid).await?;
        }
        state
            .federated_muc_publish_removal_presence(
                &target.room_jid,
                &serializable,
                Some(status),
                Some(actor_nick),
                change.reason,
            )
            .await?;
        for (_, recipient) in state.muc_occupants_for(&target.room_jid) {
            let presence = muc_presence_stanza_with_status(
                &serializable,
                &recipient.full_jid,
                true,
                false,
                false,
                None,
                target.room_non_anonymous || recipient.role == "moderator",
                Some(status),
                Some(actor_nick),
                change.reason,
            );
            let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
        }
        let self_presence = muc_presence_stanza_with_status(
            &serializable,
            &target.full_jid,
            true,
            true,
            false,
            None,
            true,
            Some(status),
            Some(actor_nick),
            change.reason,
        );
        let _ = state.deliver_to_muc_occupant(&target, self_presence).await;
    } else {
        let Some(updated) = (if let Some(affiliation) = change.affiliation {
            state.set_local_muc_affiliation_exact(
                crate::state::LocalMucOccupantIdentity::from(&target),
                affiliation,
                room.moderated,
                false,
                Some(&target.affiliation),
            )
        } else {
            state.set_local_muc_role_exact(
                crate::state::LocalMucOccupantIdentity::from(&target),
                &target.role,
                proposed_role,
                Some(target.room_non_anonymous),
            )
        }) else {
            return Ok(());
        };
        target = updated;
        let serializable = SerializableMucOccupant::from(&target);
        let json = serde_json::to_string(&serializable)?;
        state
            .federated_muc_register_occupant(&target.room_jid, &target.nick, &json)
            .await?;
        state
            .federated_muc_publish_presence(&target.room_jid, &serializable, false, false, None)
            .await?;
        for (_, recipient) in state.muc_occupants_for(&target.room_jid) {
            let self_presence = same_remote_actor(&recipient.full_jid, &target.full_jid);
            let presence = muc_presence_stanza(
                &serializable,
                &recipient.full_jid,
                false,
                self_presence,
                false,
                None,
                target.room_non_anonymous || self_presence || recipient.role == "moderator",
            );
            let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
        }
    }
    Ok(())
}

pub(super) struct FederatedMucAdminActor<'a> {
    pub(super) requester: Option<&'a MucOccupant>,
    pub(super) authenticated_domain: &'a str,
    pub(super) connection_id: uuid::Uuid,
    pub(super) full_jid: &'a str,
}

pub(super) async fn federated_muc_admin_set(
    state: &AppState,
    stanza: &FederatedStanza,
    room: &MucRoom,
    actor: FederatedMucAdminActor<'_>,
    items: Vec<FederatedAdminItem>,
) -> Result<Option<String>> {
    let FederatedMucAdminActor {
        requester,
        authenticated_domain,
        connection_id,
        full_jid: actor_full_jid,
    } = actor;
    let mut guarded_room = None;
    let mut guarded_requester = None;
    let _local_room_guard = if state.federated_muc_pg_authority_enabled() {
        None
    } else {
        let Some(requester) = requester else {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "auth",
                "not-authorized",
            ));
        };
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
    };
    let room = guarded_room.as_ref().unwrap_or(room);
    let requester = guarded_requester.as_ref().or(requester);
    if !state.federated_muc_pg_authority_enabled()
        && !requester
            .is_some_and(|occupant| matches!(occupant.affiliation.as_str(), "owner" | "admin"))
    {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    if items.is_empty() {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }
    if items.iter().any(|item| {
        item.affiliation.is_some() == item.role.is_some()
            || (item.affiliation.is_some() && item.jid.is_none())
            || (item.role.is_some() && item.nick.is_none())
    }) {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }
    let affiliation_count = items
        .iter()
        .filter(|item| item.affiliation.is_some())
        .count();
    let role_count = items.len().saturating_sub(affiliation_count);
    if !state.federated_muc_pg_authority_enabled()
        && ((affiliation_count > 0 && role_count > 0) || role_count > 1)
    {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }
    let raw_items = items
        .iter()
        .map(|item| super::super::muc::MucAdminRawItem {
            jid: item.jid.as_deref(),
            nick: item.nick.as_deref(),
            affiliation: item.affiliation.as_deref(),
            role: item.role.as_deref(),
            reason: item.reason.as_deref(),
        })
        .collect::<Vec<_>>();
    let parsed_batch = match super::super::muc::parse_muc_admin_raw_items(&raw_items) {
        Ok(batch) => batch,
        Err(error) => {
            let condition = match error {
                super::super::muc::MucAdminParseError::BadRequest => "bad-request",
                super::super::muc::MucAdminParseError::JidMalformed => "jid-malformed",
                super::super::muc::MucAdminParseError::NotAcceptable => "not-acceptable",
            };
            return Ok(federated_error(stanza, &stanza.from, "modify", condition));
        }
    };
    if state.federated_muc_pg_authority_enabled() {
        // Federated affiliation JIDs have always required a bare address.
        // Keep that validation when the shared parser normalizes targets.
        if items.iter().any(|item| {
            item.affiliation.is_some()
                && item
                    .jid
                    .as_deref()
                    .is_some_and(|jid| crate::jid::CanonicalJid::parse_bare(jid).is_err())
        }) {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "modify",
                "jid-malformed",
            ));
        }
        let Some(iq_id) = stanza
            .id
            .as_deref()
            .filter(|id| !id.is_empty() && id.len() <= 256)
        else {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "modify",
                "bad-request",
            ));
        };
        let room_jid = crate::jid::CanonicalJid::parse(&stanza.to)?.bare();
        state.federated_muc_admit_mutation()?;
        let actor_target = if let Some(requester) = requester.filter(|occupant| {
            occupant.connection_id == connection_id
                && federated_endpoint_matches(occupant, authenticated_domain)
        }) {
            state
                .muc_service()
                .local_cluster_occupancy_target(
                    room.id,
                    requester.cluster_epoch,
                    requester.connection_id,
                )
                .await?
        } else {
            None
        };
        let changes = match parsed_batch.service_changes(state.local_domain()) {
            Ok(changes) => changes,
            Err(error) => {
                let condition = match error {
                    super::super::muc::MucAdminParseError::BadRequest => "bad-request",
                    super::super::muc::MucAdminParseError::JidMalformed => "jid-malformed",
                    super::super::muc::MucAdminParseError::NotAcceptable => "not-acceptable",
                };
                return Ok(federated_error(stanza, &stanza.from, "modify", condition));
            }
        };
        let result = state
            .muc_service()
            .apply_local_cluster_admin_batch(
                connection_id,
                iq_id,
                &room_jid,
                room.id,
                room.room_epoch,
                room.config_version,
                actor_target.as_ref(),
                &ClusterMucPrincipal::Federated {
                    bare_jid: bare_jid(actor_full_jid).to_owned(),
                    authenticated_domain: canonical_authenticated_domain(authenticated_domain),
                },
                actor_full_jid,
                &changes,
            )
            .await?;
        if let Some(condition) = super::super::muc::muc_admin_batch_error(result.outcome) {
            let kind = match condition {
                "bad-request" | "jid-malformed" => "modify",
                "forbidden" => "auth",
                "resource-constraint" => "wait",
                _ => "cancel",
            };
            return Ok(federated_error(stanza, &stanza.from, kind, condition));
        }
        if result.outcome == crate::services::muc::MucAdminBatchOutcome::Applied {
            if let Err(error) = state
                .wake_committed_muc_operation(result.operation_id)
                .await
            {
                tracing::warn!(?error, operation_id=%result.operation_id, room=%room_jid,
                    "federated MUC admin batch committed; event wake will be recovered by polling");
            }
        }
        return Ok(Some(federated_iq_result(
            stanza,
            &room_jid,
            actor_full_jid,
            "",
        )));
    }

    let Some(requester) = requester else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "auth",
            "not-authorized",
        ));
    };

    // Preflight the complete IQ, then commit every durable affiliation in a
    // single room-serialized transaction.  A remote administrator must never
    // observe a successful prefix if a later item is malformed, stale, or
    // would revoke the final owner.
    let mut durable_changes = Vec::new();
    let mut previous_affiliations = std::collections::HashMap::new();
    let global_occupants = if state.federated_muc_pg_authority_enabled() {
        std::collections::HashMap::new()
    } else {
        state
            .federated_muc_global_occupants(&requester.room_jid)
            .await?
            .into_values()
            .filter_map(|json| serde_json::from_str::<SerializableMucOccupant>(&json).ok())
            .map(|occupant| (occupant.nick.clone(), occupant))
            .collect::<std::collections::HashMap<_, _>>()
    };
    for item in &items {
        if let (Some(target_jid), Some(affiliation)) =
            (item.jid.as_deref(), item.affiliation.as_deref())
        {
            if !matches!(
                affiliation,
                "owner" | "admin" | "member" | "outcast" | "none"
            ) {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "bad-request",
                ));
            }
            if (affiliation == "owner" && requester.affiliation != "owner")
                || (requester.affiliation == "admin" && matches!(affiliation, "owner" | "admin"))
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            let Ok(target) = crate::jid::CanonicalJid::parse_bare(target_jid) else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let Some(target_localpart) = target.localpart() else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let target_bare = target.to_string();
            if affiliation == "outcast" && same_bare_jid(&requester.full_jid, &target_bare) {
                return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
            }
            let (target, current) = if target.domainpart() == state.local_domain() {
                let Some(target_user) = state
                    .muc_service()
                    .enabled_local_account(target_localpart)
                    .await?
                else {
                    return Ok(federated_error(
                        stanza,
                        &stanza.from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                (
                    MucAffiliationTarget::LocalUsername(target_localpart.to_owned()),
                    state
                        .muc_service()
                        .local_affiliation(room.id, target_user.id)
                        .await?,
                )
            } else {
                (
                    MucAffiliationTarget::FederatedBareJid(target_bare.clone()),
                    state
                        .muc_service()
                        .federated_affiliation(room.id, &target_bare)
                        .await?,
                )
            };
            if requester.affiliation == "admin"
                && matches!(current.as_deref(), Some("owner" | "admin"))
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            previous_affiliations.insert(target_bare, current.unwrap_or_else(|| "none".to_owned()));
            durable_changes.push(MucAffiliationChange {
                target,
                affiliation: affiliation.to_owned(),
            });
        } else if let (Some(target_nick), Some(role)) = (item.nick.as_deref(), item.role.as_deref())
        {
            if !matches!(role, "moderator" | "participant" | "visitor" | "none") {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "bad-request",
                ));
            }
            let Ok(target_nick) = prepare_muc_nick(target_nick) else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let target = if state.federated_muc_pg_authority_enabled() {
                let authoritative = state
                    .muc_service()
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &target_nick)
                    .await?;
                if let Some(authoritative) = authoritative {
                    state
                        .muc_service()
                        .exact_local_cluster_occupancy_snapshot(&authoritative)
                        .await?
                        .map(|occupancy| SerializableMucOccupant {
                            full_jid: occupancy.full_jid,
                            room_jid: requester.room_jid.clone(),
                            nick: occupancy.nick,
                            affiliation: occupancy.affiliation,
                            role: occupancy.role,
                            room_non_anonymous: room.non_anonymous,
                            occupant_id: String::new(),
                            cluster_epoch: occupancy.occupant_incarnation,
                            connection_id: occupancy.connection_uuid,
                            federated_domain: None,
                            sm_session_id: occupancy.sm_session_id,
                            payload: String::new(),
                        })
                } else {
                    None
                }
            } else {
                state
                    .local_muc_occupant_by_nick(&requester.room_jid, &target_nick)
                    .as_ref()
                    .map(SerializableMucOccupant::from)
                    .or_else(|| global_occupants.get(&target_nick).cloned())
            };
            let Some(target) = target else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "item-not-found",
                ));
            };
            if requester.affiliation == "admin"
                && matches!(target.affiliation.as_str(), "owner" | "admin")
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
        }
    }
    let mut cluster_affiliation_operation = None;
    let affiliation_outcome =
        if state.federated_muc_pg_authority_enabled() && !durable_changes.is_empty() {
            state.federated_muc_admit_mutation()?;
            let authenticated_domain = match &requester.endpoint {
                crate::state::MucOccupantEndpoint::Federated {
                    authenticated_domain,
                    ..
                } => authenticated_domain.clone(),
                _ => anyhow::bail!("federated MUC admin lost its S2S domain proof"),
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
            let operation_id = crate::services::muc::operation_id(&serde_json::json!({
                "kind":"admin_affiliation_batch","stream":requester.connection_id,
                "iq_id":stanza.id,"room":requester.room_jid,"actor":requester.full_jid,
                "changes":durable_changes,
            }))?;
            let outcome = state
                .muc_service()
                .apply_local_cluster_affiliations_batch(
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
                    &durable_changes,
                )
                .await?;
            cluster_affiliation_operation = Some(operation_id);
            outcome
        } else {
            state
                .muc_service()
                .set_local_legacy_affiliations_batch(room.id, &durable_changes)
                .await?
        };
    match affiliation_outcome {
        MucAffiliationBatchOutcome::Applied => {}
        MucAffiliationBatchOutcome::DuplicateTarget => {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "modify",
                "bad-request",
            ));
        }
        MucAffiliationBatchOutcome::LastOwner => {
            return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
        }
        MucAffiliationBatchOutcome::MissingTarget => {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "cancel",
                "item-not-found",
            ));
        }
        MucAffiliationBatchOutcome::Unauthorized => {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        }
        MucAffiliationBatchOutcome::Stale | MucAffiliationBatchOutcome::Destroyed => {
            return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
        }
    }
    if let Some(operation_id) = cluster_affiliation_operation {
        if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
            tracing::warn!(?error, %operation_id, room=%requester.room_jid,
                "federated MUC affiliation batch committed; signed wake will be recovered by polling");
        }
    }
    if state.federated_muc_pg_authority_enabled() {
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
        for item in items.iter().filter(|item| item.role.is_some()) {
            let target_nick =
                prepare_muc_nick(item.nick.as_deref().expect("role item validated above"))
                    .expect("role nickname validated above");
            let Some(target) = state
                .muc_service()
                .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &target_nick)
                .await?
            else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "item-not-found",
                ));
            };
            let new_role = item.role.as_deref().expect("role item validated above");
            let operation_id = crate::services::muc::operation_id(&serde_json::json!({
                "kind":"admin_role","stream":requester.connection_id,"iq_id":stanza.id,
                "room":requester.room_jid,"actor":actor_target,"target":target,
                "role":new_role,"reason":item.reason,
            }))?;
            let outcome = if new_role == "none" {
                state
                    .muc_service()
                    .kick_local_cluster_occupancy(
                        operation_id,
                        &actor_target,
                        &target,
                        item.reason.as_deref(),
                    )
                    .await?
            } else {
                state
                    .muc_service()
                    .change_local_cluster_role(
                        operation_id,
                        &actor_target,
                        &target,
                        new_role,
                        item.reason.as_deref(),
                    )
                    .await?
            };
            match outcome {
                ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                ClusterMucTransitionOutcome::Unauthorized => {
                    return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
                }
                ClusterMucTransitionOutcome::Stale | ClusterMucTransitionOutcome::Destroyed => {
                    return Ok(federated_error(
                        stanza,
                        &stanza.from,
                        "cancel",
                        "item-not-found",
                    ));
                }
                ClusterMucTransitionOutcome::Conflict => {
                    return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
                }
            }
            if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                tracing::warn!(?error, %operation_id, room=%requester.room_jid,
                    "federated MUC role operation committed; signed wake will be recovered by polling");
            }
        }
        return Ok(Some(federated_iq_result(
            stanza,
            &requester.room_jid,
            &requester.full_jid,
            "",
        )));
    }
    for item in items {
        if let (Some(target_jid), Some(affiliation)) =
            (item.jid.as_deref(), item.affiliation.as_deref())
        {
            if !matches!(
                affiliation,
                "owner" | "admin" | "member" | "outcast" | "none"
            ) {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "bad-request",
                ));
            }
            if (affiliation == "owner" && requester.affiliation != "owner")
                || (requester.affiliation == "admin" && matches!(affiliation, "owner" | "admin"))
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            let Ok(target) = crate::jid::CanonicalJid::parse_bare(target_jid) else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let Some(target_localpart) = target.localpart() else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let target_bare = target.to_string();
            if affiliation == "outcast" && same_bare_jid(&requester.full_jid, &target_bare) {
                return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
            }
            let target_affiliation = if target.domainpart() == state.local_domain() {
                let target_user = state
                    .muc_service()
                    .enabled_local_account(target_localpart)
                    .await?;
                match target_user {
                    Some(target_user) => {
                        state
                            .muc_service()
                            .local_affiliation(room.id, target_user.id)
                            .await?
                    }
                    None => {
                        return Ok(federated_error(
                            stanza,
                            &stanza.from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                }
            } else {
                state
                    .muc_service()
                    .federated_affiliation(room.id, &target_bare)
                    .await?
            };
            if requester.affiliation == "admin"
                && matches!(target_affiliation.as_deref(), Some("owner" | "admin"))
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            let present: Vec<_> = state
                .muc_occupants_for(&requester.room_jid)
                .into_iter()
                .filter(|(_, occupant)| same_bare_jid(&occupant.full_jid, &target_bare))
                .collect();
            let local_identities = present
                .iter()
                .map(|(_, occupant)| (occupant.cluster_epoch, occupant.connection_id))
                .collect::<std::collections::HashSet<_>>();
            let remote_present = global_occupants
                .values()
                .filter(|occupant| {
                    same_bare_jid(&occupant.full_jid, &target_bare)
                        && !local_identities
                            .contains(&(occupant.cluster_epoch, occupant.connection_id))
                })
                .cloned()
                .collect::<Vec<_>>();
            let target_is_occupant = !present.is_empty() || !remote_present.is_empty();
            let previous_affiliation = previous_affiliations
                .get(&target_bare)
                .map(String::as_str)
                .unwrap_or("none");
            if super::super::muc::should_broadcast_offline_affiliation_change(
                room.non_anonymous,
                target_is_occupant,
                previous_affiliation,
                affiliation,
            ) {
                super::super::muc::deliver_muc_offline_affiliation_change_notice(
                    state,
                    &requester.room_jid,
                    &target_bare,
                    affiliation,
                    item.nick.as_deref(),
                    item.reason.as_deref(),
                )
                .await;
            }
            for (_, occupant) in present {
                publish_occupant_change(
                    state,
                    room,
                    requester,
                    occupant,
                    OccupantChange {
                        affiliation: Some(affiliation),
                        role: None,
                        reason: item.reason.as_deref(),
                    },
                )
                .await?;
            }
            for remote in remote_present {
                let remove_from_room =
                    affiliation == "outcast" || (affiliation == "none" && room.members_only);
                if remove_from_room {
                    let mut updated = remote;
                    updated.affiliation = affiliation.to_owned();
                    updated.role = "none".to_owned();
                    let status = if affiliation == "outcast" { 301 } else { 321 };
                    if state
                        .federated_muc_evict_occupant(
                            &updated,
                            status,
                            Some(&requester.nick),
                            item.reason.as_deref(),
                        )
                        .await?
                    {
                        state
                            .federated_muc_publish_removal_presence(
                                &requester.room_jid,
                                &updated,
                                Some(status),
                                Some(&requester.nick),
                                item.reason.as_deref(),
                            )
                            .await?;
                        for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                            let presence = muc_presence_stanza_with_status(
                                &updated,
                                &recipient.full_jid,
                                true,
                                false,
                                false,
                                None,
                                updated.room_non_anonymous || recipient.role == "moderator",
                                Some(status),
                                Some(&requester.nick),
                                item.reason.as_deref(),
                            );
                            let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
                        }
                    }
                } else {
                    let role = if matches!(affiliation, "owner" | "admin") {
                        "moderator"
                    } else if room.moderated && affiliation == "none" {
                        "visitor"
                    } else {
                        "participant"
                    };
                    let updated = match state
                        .federated_muc_change_occupant_affiliation(
                            &requester.room_jid,
                            &remote,
                            affiliation,
                            role,
                        )
                        .await?
                    {
                        crate::cluster::MucRoleChange::Changed(updated) => *updated,
                        crate::cluster::MucRoleChange::Stale => continue,
                    };
                    state
                        .federated_muc_publish_presence(
                            &requester.room_jid,
                            &updated,
                            false,
                            false,
                            None,
                        )
                        .await?;
                    for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                        let presence = muc_presence_stanza(
                            &updated,
                            &recipient.full_jid,
                            false,
                            false,
                            false,
                            None,
                            updated.room_non_anonymous || recipient.role == "moderator",
                        );
                        let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
                    }
                }
            }
        } else if let (Some(target_nick), Some(role)) = (item.nick.as_deref(), item.role.as_deref())
        {
            if !matches!(role, "moderator" | "participant" | "visitor" | "none") {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "bad-request",
                ));
            }
            let Ok(target_nick) = prepare_muc_nick(target_nick) else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let local_target = state.local_muc_occupant_by_nick(&requester.room_jid, &target_nick);
            if local_target.is_none() {
                let Some(mut target) = global_occupants.get(&target_nick).cloned() else {
                    return Ok(federated_error(
                        stanza,
                        &stanza.from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                if requester.affiliation == "admin"
                    && matches!(target.affiliation.as_str(), "owner" | "admin")
                {
                    return Ok(federated_error(
                        stanza,
                        &stanza.from,
                        "cancel",
                        "not-allowed",
                    ));
                }
                if role == "none" {
                    target.role = "none".to_owned();
                    if !state
                        .federated_muc_evict_occupant(
                            &target,
                            307,
                            Some(&requester.nick),
                            item.reason.as_deref(),
                        )
                        .await?
                    {
                        return Ok(federated_error(
                            stanza,
                            &stanza.from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                    state
                        .federated_muc_publish_removal_presence(
                            &requester.room_jid,
                            &target,
                            Some(307),
                            Some(&requester.nick),
                            item.reason.as_deref(),
                        )
                        .await?;
                    for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                        let presence = muc_presence_stanza_with_status(
                            &target,
                            &recipient.full_jid,
                            true,
                            false,
                            false,
                            None,
                            target.room_non_anonymous || recipient.role == "moderator",
                            Some(307),
                            Some(&requester.nick),
                            item.reason.as_deref(),
                        );
                        let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
                    }
                } else {
                    let updated = match state
                        .federated_muc_change_occupant_role(&requester.room_jid, &target, role)
                        .await?
                    {
                        crate::cluster::MucRoleChange::Changed(updated) => *updated,
                        crate::cluster::MucRoleChange::Stale => {
                            return Ok(federated_error(
                                stanza,
                                &stanza.from,
                                "cancel",
                                "item-not-found",
                            ));
                        }
                    };
                    state
                        .federated_muc_publish_presence(
                            &requester.room_jid,
                            &updated,
                            false,
                            false,
                            None,
                        )
                        .await?;
                    for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                        let presence = muc_presence_stanza(
                            &updated,
                            &recipient.full_jid,
                            false,
                            false,
                            false,
                            None,
                            updated.room_non_anonymous || recipient.role == "moderator",
                        );
                        let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
                    }
                }
                continue;
            }
            let target = local_target.expect("remote cluster target handled above");
            if requester.affiliation == "admin"
                && matches!(target.affiliation.as_str(), "owner" | "admin")
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            publish_occupant_change(
                state,
                room,
                requester,
                target,
                OccupantChange {
                    affiliation: None,
                    role: Some(role),
                    reason: item.reason.as_deref(),
                },
            )
            .await?;
        } else {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "modify",
                "bad-request",
            ));
        }
    }
    Ok(Some(federated_iq_result(
        stanza,
        &requester.room_jid,
        &requester.full_jid,
        "",
    )))
}
