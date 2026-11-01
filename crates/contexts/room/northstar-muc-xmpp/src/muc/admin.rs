//! XEP-0045 admin IQ handlers.

use super::*;

pub async fn muc_admin_get(
    session: &impl MucSession,
    id: &str,
    iq: Node<'_, '_>,
    query: Node<'_, '_>,
) -> Result<MucAction> {
    let Some(user) = session.user() else {
        return Ok(MucAction::Send(iq_error(id, "not-authorized")));
    };
    let Some(full_jid) = session.full_jid() else {
        return Ok(MucAction::Send(iq_error(id, "not-authorized")));
    };
    let Some((room_jid_owned, room_localpart)) = iq
        .attribute("to")
        .and_then(|value| canonical_local_muc_room(value, &muc_domain(session)))
    else {
        return Ok(MucAction::Send(iq_error(id, "jid-malformed")));
    };
    let room_jid = room_jid_owned.as_str();
    let Some(initial_room) = session
        .host()
        .muc_service()
        .local_room_snapshot(&room_localpart)
        .await?
    else {
        return Ok(MucAction::Send(iq_error_from(
            id,
            room_jid,
            "item-not-found",
        )));
    };
    let _local_authority_guard = if session.host().muc_pg_authority_enabled() {
        None
    } else {
        Some(
            session
                .host()
                .muc_service()
                .lock_local_room_mutation(initial_room.id)
                .await,
        )
    };
    let Some(room) = session
        .host()
        .muc_service()
        .local_room_snapshot(&room_localpart)
        .await?
    else {
        return Ok(MucAction::Send(iq_error_from(
            id,
            room_jid,
            "item-not-found",
        )));
    };
    if room.id != initial_room.id || room.room_epoch != initial_room.room_epoch {
        return Ok(MucAction::Send(iq_error_from(
            id,
            room_jid,
            "item-not-found",
        )));
    }
    let Some(item) = query
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "item")
    else {
        return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
    };

    let requested_affiliation = item.attribute("affiliation");
    let requested_role = item.attribute("role");
    if requested_affiliation.is_some() == requested_role.is_some() {
        return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
    }
    if let Some(requested_role) = requested_role {
        if !matches!(requested_role, "moderator" | "participant" | "visitor") {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
        }
        let actor = validated_muc_occupant(session, room_jid);
        let asserted_local_role = actor
            .as_ref()
            .map(|occupant| occupant.role.as_str())
            .unwrap_or("none");
        let actor_target = if session.host().muc_pg_authority_enabled() {
            if let Some(actor) = actor.as_ref() {
                session
                    .host()
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        actor.cluster_epoch,
                        actor.connection_id,
                    )
                    .await?
                    .filter(|target| {
                        target.room_epoch == room.room_epoch
                            && target.full_jid == actor.full_jid
                            && target.nick == actor.nick
                            && target.connection_uuid == actor.connection_id
                    })
            } else {
                None
            }
        } else {
            None
        };
        let actor_scope = canonical_bare_key(full_jid)?;
        let role_list = match session
            .host()
            .muc_service()
            .authorized_admin_role_list(
                room.id,
                room.room_epoch,
                user.id,
                &actor_scope,
                asserted_local_role,
                actor_target.as_ref(),
                session.host().muc_pg_authority_enabled(),
                requested_role,
            )
            .await?
        {
            MucAdminSnapshot::Authorized(list) => list,
            MucAdminSnapshot::Unauthorized => {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
            }
            MucAdminSnapshot::Stale => {
                return Ok(MucAction::Send(iq_error_from(
                    id,
                    room_jid,
                    "item-not-found",
                )));
            }
        };
        let reveal_real_jids = role_list.non_anonymous || role_list.requester_role == "moderator";
        let mut occupants = if session.host().muc_pg_authority_enabled() {
            role_list
                .entries
                .into_iter()
                .map(|entry| (entry.nick, entry.bare_jid))
                .collect::<Vec<_>>()
        } else {
            session
                .host()
                .muc_occupants_for(room_jid)
                .into_iter()
                .filter(|(_, occupant)| occupant.role == requested_role)
                .filter_map(|(_, occupant)| {
                    canonical_bare_key(&occupant.full_jid)
                        .ok()
                        .map(|bare| (occupant.nick, bare))
                })
                .collect::<Vec<_>>()
        };
        occupants.sort_by(|left, right| left.0.cmp(&right.0));
        let mut result = XmlElement::namespaced("query", "http://jabber.org/protocol/muc#admin");
        for (nick, bare) in occupants {
            result.push_child(
                XmlElement::new("item")
                    .attr("nick", &nick)
                    .attr("role", requested_role)
                    .optional_attr("jid", reveal_real_jids.then_some(bare.as_str())),
            );
        }
        return Ok(MucAction::Send(iq_result_from(
            id,
            room_jid,
            &result.finish(),
        )));
    }
    let requested_affiliation = requested_affiliation.expect("exclusive role/affiliation check");
    if !matches!(
        requested_affiliation,
        "owner" | "admin" | "member" | "outcast"
    ) {
        return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
    }

    let actor_scope = canonical_bare_key(full_jid)?;
    let entries = match session
        .host()
        .muc_service()
        .authorized_admin_affiliation_list(
            room.id,
            room.room_epoch,
            user.id,
            &actor_scope,
            requested_affiliation,
        )
        .await?
    {
        MucAdminSnapshot::Authorized(entries) => entries,
        MucAdminSnapshot::Unauthorized => {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        MucAdminSnapshot::Stale => {
            return Ok(MucAction::Send(iq_error_from(
                id,
                room_jid,
                "item-not-found",
            )));
        }
    };
    let mut result = XmlElement::namespaced("query", "http://jabber.org/protocol/muc#admin");
    for entry in entries {
        result.push_child(
            XmlElement::new("item")
                .attr("affiliation", &entry.affiliation)
                .attr("jid", &entry.bare_jid),
        );
    }
    Ok(MucAction::Send(iq_result_from(
        id,
        room_jid,
        &result.finish(),
    )))
}

pub async fn muc_admin_set(
    session: &impl MucSession,
    id: &str,
    iq: Node<'_, '_>,
    query: Node<'_, '_>,
) -> Result<MucAction> {
    let Some(user) = session.user() else {
        return Ok(MucAction::Send(iq_error(id, "not-authorized")));
    };
    let Some(full_jid) = session.full_jid() else {
        return Ok(MucAction::Send(iq_error(id, "not-authorized")));
    };
    let Some((room_jid_owned, room_localpart)) = iq
        .attribute("to")
        .and_then(|value| canonical_local_muc_room(value, &muc_domain(session)))
    else {
        return Ok(MucAction::Send(iq_error(id, "jid-malformed")));
    };
    let room_jid = room_jid_owned.as_str();
    let Some(room) = session
        .host()
        .muc_service()
        .local_room_snapshot(&room_localpart)
        .await?
    else {
        return Ok(MucAction::Send(iq_error_from(
            id,
            room_jid,
            "item-not-found",
        )));
    };
    let gated_room_id = room.id;
    let gated_room_epoch = room.room_epoch;
    let _local_room_guard = if session.host().muc_pg_authority_enabled() {
        None
    } else {
        Some(
            session
                .host()
                .muc_service()
                .lock_local_room_mutation(room.id)
                .await,
        )
    };
    let Some(room) = session
        .host()
        .muc_service()
        .local_room_snapshot(&room_localpart)
        .await?
    else {
        return Ok(MucAction::Send(iq_error_from(
            id,
            room_jid,
            "item-not-found",
        )));
    };
    if room.id != gated_room_id || room.room_epoch != gated_room_epoch {
        return Ok(MucAction::Send(iq_error_from(
            id,
            room_jid,
            "item-not-found",
        )));
    }
    let my_affiliation = session
        .host()
        .muc_service()
        .local_affiliation(room.id, user.id)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    let actor = authorized_muc_occupant(session, room_jid).await?;
    let actor_nick = actor.as_ref().map(|occupant| occupant.nick.clone());
    let my_role = actor
        .as_ref()
        .map(|occupant| occupant.role.clone())
        .unwrap_or_else(|| "none".to_owned());
    let items = query
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if id.is_empty() || id.len() > 256 {
        return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
    }
    if !session.host().muc_pg_authority_enabled() && classify_muc_admin_items(&items).is_err() {
        return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
    }
    let parsed_batch = match parse_muc_admin_batch(&items) {
        Ok(batch) => batch,
        Err(MucAdminParseError::BadRequest) => {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
        }
        Err(MucAdminParseError::JidMalformed) => {
            return Ok(MucAction::Send(iq_error_from(
                id,
                room_jid,
                "jid-malformed",
            )));
        }
        Err(MucAdminParseError::NotAcceptable) => {
            return Ok(MucAction::Send(iq_error_from(
                id,
                room_jid,
                "not-acceptable",
            )));
        }
    };
    if session.host().muc_pg_authority_enabled() {
        session.host().admit_muc_pg_mutation()?;
        let actor_target = if let Some(actor) = actor.as_ref() {
            session
                .host()
                .muc_service()
                .local_cluster_occupancy_target(room.id, actor.cluster_epoch, actor.connection_id)
                .await?
        } else {
            None
        };
        let changes = match parsed_batch.service_changes(session.host().local_domain()) {
            Ok(changes) => changes,
            Err(MucAdminParseError::BadRequest) => {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
            }
            Err(MucAdminParseError::JidMalformed) => {
                return Ok(MucAction::Send(iq_error_from(
                    id,
                    room_jid,
                    "jid-malformed",
                )));
            }
            Err(MucAdminParseError::NotAcceptable) => {
                return Ok(MucAction::Send(iq_error_from(
                    id,
                    room_jid,
                    "not-acceptable",
                )));
            }
        };
        let result = session
            .host()
            .muc_service()
            .apply_local_cluster_admin_batch(
                session.connection_id(),
                id,
                room_jid,
                room.id,
                room.room_epoch,
                room.config_version,
                actor_target.as_ref(),
                &ClusterMucPrincipal::Local {
                    user_id: user.id,
                    bare_jid: bare_jid(full_jid).to_owned(),
                },
                full_jid,
                &changes,
            )
            .await?;
        if let Some(condition) = muc_admin_batch_error(result.outcome) {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, condition)));
        }
        if result.outcome == MucAdminBatchOutcome::Applied {
            if let Err(error) = session
                .host()
                .wake_committed_muc_operation(result.operation_id)
                .await
            {
                tracing::warn!(?error, operation_id=%result.operation_id, room=%room_jid,
                        "MUC admin batch committed; event wake will be recovered by polling");
            }
        }
        return Ok(MucAction::Send(iq_result_from(id, room_jid, "")));
    }
    if !matches!(my_affiliation.as_str(), "owner" | "admin") && my_role != "moderator" {
        return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
    }
    let Ok(mutation_kind) = classify_muc_admin_items(&items) else {
        return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
    };

    // Validate the entire IQ before committing any durable affiliation
    // changes.  XEP-0045 allows multiple items in one request; returning
    // an error after committing a valid prefix would violate the IQ's
    // request/response semantics and can strand a room without its owner.
    let mut durable_changes = Vec::new();
    let mut previous_affiliations = std::collections::HashMap::new();
    let global_occupants = if session.host().muc_pg_authority_enabled() {
        std::collections::HashMap::new()
    } else {
        session
            .host()
            .cached_muc_cluster_occupants(room_jid)
            .await?
            .into_values()
            .filter_map(|json| {
                serde_json::from_str::<
                    northstar_room_application::muc_service::SerializableMucOccupant,
                >(&json)
                .ok()
            })
            .map(|occupant| (occupant.nick.clone(), occupant))
            .collect::<std::collections::HashMap<_, _>>()
    };
    for item in &parsed_batch.items {
        if let MucAdminChange::Affiliation {
            target_bare_jid: target_bare,
            affiliation: new_affil,
        } = &item.change
        {
            if !matches!(my_affiliation.as_str(), "owner" | "admin") {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
            }
            if (new_affil == "owner" && my_affiliation != "owner")
                || (my_affiliation == "admin" && matches!(new_affil.as_str(), "owner" | "admin"))
            {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
            }
            let Some((target_localpart, target_domain)) = target_bare.split_once('@') else {
                return Ok(MucAction::Send(iq_error_from(
                    id,
                    room_jid,
                    "jid-malformed",
                )));
            };
            if new_affil == "outcast"
                && session
                    .full_jid()
                    .and_then(|jid| canonical_bare_key(jid).ok())
                    .as_deref()
                    == Some(target_bare.as_str())
            {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "conflict")));
            }
            let (target, current) = if target_domain == session.host().local_domain() {
                let Some(target_user) = session
                    .host()
                    .muc_service()
                    .enabled_local_account(target_localpart)
                    .await?
                else {
                    return Ok(MucAction::Send(iq_error_from(
                        id,
                        room_jid,
                        "item-not-found",
                    )));
                };
                (
                    MucAffiliationTarget::LocalUsername(target_localpart.to_owned()),
                    session
                        .host()
                        .muc_service()
                        .local_affiliation(room.id, target_user.id)
                        .await?,
                )
            } else {
                (
                    MucAffiliationTarget::FederatedBareJid(target_bare.clone()),
                    session
                        .host()
                        .muc_service()
                        .federated_affiliation(room.id, target_bare)
                        .await?,
                )
            };
            if my_affiliation == "admin" && matches!(current.as_deref(), Some("owner" | "admin")) {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
            }
            previous_affiliations.insert(
                target_bare.clone(),
                current.unwrap_or_else(|| "none".to_owned()),
            );
            durable_changes.push(MucAffiliationChange {
                target,
                affiliation: new_affil.clone(),
            });
        } else if let MucAdminChange::Role {
            target_nick,
            role: new_role,
        } = &item.change
        {
            if my_role != "moderator" {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
            }
            let target = if session.host().muc_pg_authority_enabled() {
                let authoritative = session
                    .host()
                    .muc_service()
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, target_nick)
                    .await?;
                if let Some(authoritative) = authoritative {
                    session
                        .host()
                        .muc_service()
                        .exact_local_cluster_occupancy_snapshot(&authoritative)
                        .await?
                        .map(|occupancy| {
                            northstar_room_application::muc_service::SerializableMucOccupant {
                                full_jid: occupancy.full_jid,
                                room_jid: room_jid.to_owned(),
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
                            }
                        })
                } else {
                    None
                }
            } else {
                session
                    .host()
                    .local_muc_occupant_by_nick(room_jid, target_nick)
                    .as_ref()
                    .map(northstar_room_application::muc_service::SerializableMucOccupant::from)
                    .or_else(|| global_occupants.get(target_nick).cloned())
            };
            let Some(target) = target else {
                return Ok(MucAction::Send(iq_error_from(
                    id,
                    room_jid,
                    "item-not-found",
                )));
            };
            if (my_affiliation == "admin"
                && matches!(target.affiliation.as_str(), "owner" | "admin"))
                || ((new_role == "moderator" || target.role == "moderator")
                    && !matches!(my_affiliation.as_str(), "owner" | "admin"))
                || (matches!(target.affiliation.as_str(), "owner" | "admin")
                    && !matches!(my_affiliation.as_str(), "owner" | "admin"))
            {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
            }
        }
    }
    // `mutation_kind` is derived from the fully validated shape above.
    // Reuse it rather than independently re-inferring the request kind
    // from attributes, so the durable affiliation path cannot drift from
    // the role-only path.
    let all_affiliation_changes = mutation_kind.requires_affiliation_batch();
    let mut cluster_affiliation_operation = None;
    let affiliation_outcome = if !mutation_kind.requires_affiliation_batch() {
        // A standard XEP-0045 role IQ (including a kick with role='none')
        // owns no affiliation write. Never convert it into an invalid
        // empty affiliation command; continue below into the role path.
        MucAffiliationBatchOutcome::Applied
    } else if session.host().muc_pg_authority_enabled() {
        session.host().admit_muc_pg_mutation()?;
        let Some(actor) = authorized_muc_occupant(session, room_jid).await? else {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
        };
        let Some(actor_target) = session
            .host()
            .muc_service()
            .local_cluster_occupancy_target(room.id, actor.cluster_epoch, actor.connection_id)
            .await?
        else {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
        };
        let operation_id =
            northstar_room_application::muc_service::operation_id(&serde_json::json!({
                "kind":"admin_affiliation_batch","stream":session.connection_id(),"iq_id":id,
                "room":room_jid,"actor":full_jid,"changes":durable_changes,
            }))?;
        let outcome = session
            .host()
            .muc_service()
            .apply_local_cluster_affiliations_batch(
                operation_id,
                room.id,
                room.room_epoch,
                room.config_version,
                &actor_target,
                &ClusterMucPrincipal::Local {
                    user_id: user.id,
                    bare_jid: bare_jid(full_jid).to_owned(),
                },
                full_jid,
                &durable_changes,
            )
            .await?;
        cluster_affiliation_operation = Some(operation_id);
        outcome
    } else {
        session
            .host()
            .muc_service()
            .execute_muc_affiliation_batch(MucAffiliationBatchCommand::from(
                MucAffiliationBatchWrite {
                    room_id: room.id,
                    changes: &durable_changes,
                },
            ))
            .await?
            .outcome
    };
    match affiliation_outcome {
        MucAffiliationBatchOutcome::Applied => {}
        MucAffiliationBatchOutcome::DuplicateTarget => {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
        }
        MucAffiliationBatchOutcome::LastOwner => {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "conflict")));
        }
        MucAffiliationBatchOutcome::MissingTarget => {
            return Ok(MucAction::Send(iq_error_from(
                id,
                room_jid,
                "item-not-found",
            )));
        }
        MucAffiliationBatchOutcome::Unauthorized => {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        MucAffiliationBatchOutcome::Stale | MucAffiliationBatchOutcome::Destroyed => {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "conflict")));
        }
    }

    if let Some(operation_id) = cluster_affiliation_operation {
        if let Err(error) = session
            .host()
            .wake_committed_muc_operation(operation_id)
            .await
        {
            tracing::warn!(?error, %operation_id, room=%room_jid,
                    "durable MUC affiliation batch committed; signed wake will be recovered by polling");
        }
        if all_affiliation_changes {
            // The PostgreSQL audience worker renders every live role
            // change/removal. Do not execute the legacy Redis mutation
            // loop below in clustered mode.
            return Ok(MucAction::Send(iq_result_from(id, room_jid, "")));
        }
    }

    if session.host().muc_pg_authority_enabled() {
        let role_items = parsed_batch
            .items
            .iter()
            .filter(|item| matches!(item.change, MucAdminChange::Role { .. }))
            .collect::<Vec<_>>();
        if !role_items.is_empty() {
            let Some(actor_occupant) = actor.as_ref() else {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
            };
            let Some(actor_target) = session
                .host()
                .muc_service()
                .local_cluster_occupancy_target(
                    room.id,
                    actor_occupant.cluster_epoch,
                    actor_occupant.connection_id,
                )
                .await?
            else {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
            };
            for item in role_items {
                let MucAdminChange::Role { target_nick, role } = &item.change else {
                    unreachable!("role items were selected above");
                };
                let Some(target) = session
                    .host()
                    .muc_service()
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, target_nick)
                    .await?
                else {
                    return Ok(MucAction::Send(iq_error_from(
                        id,
                        room_jid,
                        "item-not-found",
                    )));
                };
                let new_role = role.as_str();
                let reason = item.reason.as_deref();
                let operation_id =
                    northstar_room_application::muc_service::operation_id(&serde_json::json!({
                        "kind":"admin_role","stream":session.connection_id(),"iq_id":id,
                        "room":room_jid,"actor":actor_target,"target":target,
                        "role":new_role,"reason":reason,
                    }))?;
                let outcome = if new_role == "none" {
                    session
                        .host()
                        .muc_service()
                        .kick_local_cluster_occupancy(operation_id, &actor_target, &target, reason)
                        .await?
                } else {
                    session
                        .host()
                        .muc_service()
                        .change_local_cluster_role(
                            operation_id,
                            &actor_target,
                            &target,
                            new_role,
                            reason,
                        )
                        .await?
                };
                match outcome {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
                    }
                    ClusterMucTransitionOutcome::Stale | ClusterMucTransitionOutcome::Destroyed => {
                        return Ok(MucAction::Send(iq_error_from(
                            id,
                            room_jid,
                            "item-not-found",
                        )));
                    }
                    ClusterMucTransitionOutcome::Conflict => {
                        return Ok(MucAction::Send(iq_error_from(id, room_jid, "conflict")));
                    }
                }
                if let Err(error) = session
                    .host()
                    .wake_committed_muc_operation(operation_id)
                    .await
                {
                    tracing::warn!(?error, %operation_id, room=%room_jid,
                            "durable MUC role operation committed; signed wake will be recovered by polling");
                }
            }
        }
        // All clustered control changes above are now durable and their
        // exact audience deliveries are owned by the PG outbox.
        return Ok(MucAction::Send(iq_result_from(id, room_jid, "")));
    }

    for item in items {
        if let (Some(target_raw), Some(new_affil)) =
            (item.attribute("jid"), item.attribute("affiliation"))
        {
            if !matches!(my_affiliation.as_str(), "owner" | "admin") {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
            }
            if !matches!(new_affil, "owner" | "admin" | "member" | "outcast" | "none") {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
            }
            if new_affil == "owner" && my_affiliation != "owner" {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
            }
            if my_affiliation == "admin" && matches!(new_affil, "owner" | "admin") {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
            }
            let Ok(target) = CanonicalJid::parse(target_raw) else {
                return Ok(MucAction::Send(iq_error_from(
                    id,
                    room_jid,
                    "jid-malformed",
                )));
            };
            let Some(target_localpart) = target.localpart() else {
                return Ok(MucAction::Send(iq_error_from(
                    id,
                    room_jid,
                    "jid-malformed",
                )));
            };
            let target_bare = target.bare();
            if new_affil == "outcast"
                && session
                    .full_jid()
                    .and_then(|jid| canonical_bare_key(jid).ok())
                    .as_deref()
                    == Some(target_bare.as_str())
            {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "conflict")));
            }
            let target_is_local = target.domainpart() == session.host().local_domain();
            if target_is_local
                && session
                    .host()
                    .muc_service()
                    .enabled_local_account(target_localpart)
                    .await?
                    .is_none()
            {
                return Ok(MucAction::Send(iq_error_from(
                    id,
                    room_jid,
                    "item-not-found",
                )));
            }
            let target_affiliation = if target_is_local {
                let target_user = session
                    .host()
                    .muc_service()
                    .enabled_local_account(target_localpart)
                    .await?
                    .expect("local target existence checked above");
                session
                    .host()
                    .muc_service()
                    .local_affiliation(room.id, target_user.id)
                    .await?
            } else {
                session
                    .host()
                    .muc_service()
                    .federated_affiliation(room.id, &target_bare)
                    .await?
            };
            if my_affiliation == "admin"
                && matches!(target_affiliation.as_deref(), Some("owner" | "admin"))
            {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
            }
            let reason = child_text(item, "reason").map(str::to_owned);

            tracing::info!(room = %room_jid, target = %target_bare, affiliation = %new_affil, "MUC admin_set: publishing atomically committed affiliation");

            // Broadcast presence if they are in the room
            let occupants: Vec<_> = session
                .host()
                .muc_occupants_for(room_jid)
                .into_iter()
                .filter(|(_, occ)| {
                    canonical_bare_key(&occ.full_jid).ok() == Some(target_bare.clone())
                })
                .collect();
            let local_identities = occupants
                .iter()
                .map(|(_, occupant)| (occupant.cluster_epoch, occupant.connection_id))
                .collect::<std::collections::HashSet<_>>();
            let remote_occupants = session
                .host()
                .cached_muc_cluster_occupants(room_jid)
                .await?
                .into_values()
                .filter_map(|json| {
                    serde_json::from_str::<
                        northstar_room_application::muc_service::SerializableMucOccupant,
                    >(&json)
                    .ok()
                })
                .filter(|occupant| {
                    canonical_bare_key(&occupant.full_jid).ok() == Some(target_bare.clone())
                        && !local_identities
                            .contains(&(occupant.cluster_epoch, occupant.connection_id))
                })
                .collect::<Vec<_>>();

            let target_is_occupant = !occupants.is_empty() || !remote_occupants.is_empty();
            let previous_affiliation = previous_affiliations
                .get(&target_bare)
                .map(String::as_str)
                .unwrap_or("none");
            if should_broadcast_offline_affiliation_change(
                room.non_anonymous,
                target_is_occupant,
                previous_affiliation,
                new_affil,
            ) {
                deliver_muc_offline_affiliation_change_notice(
                    session.host(),
                    room_jid,
                    &target_bare,
                    new_affil,
                    item.attribute("nick"),
                    reason.as_deref(),
                )
                .await;
            }

            for (_, occupant) in occupants {
                let remove_from_room =
                    new_affil == "outcast" || (new_affil == "none" && room.members_only);
                if remove_from_room {
                    let Some(mut occupant) = session.host().remove_local_muc_occupant_exact(
                        northstar_room_application::muc_service::LocalMucOccupantIdentity::from(
                            &occupant,
                        ),
                    ) else {
                        continue;
                    };
                    occupant.affiliation = new_affil.to_owned();
                    occupant.role = "none".to_owned();
                    let serializable =
                        northstar_room_application::muc_service::SerializableMucOccupant::from(
                            &occupant,
                        );
                    session.host().remove_live_muc_membership(&serializable);
                    let is_empty = session.host().muc_occupants_for(room_jid).is_empty();
                    let removal_status = if new_affil == "outcast" { 301 } else { 321 };
                    run_muc_cluster_eviction(
                        session.host(),
                        room_jid,
                        serializable,
                        removal_status,
                        actor_nick.as_deref(),
                        reason.as_deref(),
                        is_empty,
                    )
                    .await;
                    for (_, other) in session.host().muc_occupants_for(room_jid) {
                        let presence = muc_presence_stanza_with_status(
                            &northstar_room_application::muc_service::SerializableMucOccupant::from(
                                &occupant,
                            ),
                            &other.full_jid,
                            true,
                            false,
                            false,
                            None,
                            occupant.room_non_anonymous || other.role == "moderator",
                            Some(if new_affil == "outcast" { 301 } else { 321 }),
                            actor_nick.as_deref(),
                            reason.as_deref(),
                        );
                        let _ = session
                            .host()
                            .deliver_to_muc_occupant(&other, presence)
                            .await;
                    }
                    let self_presence = muc_presence_stanza_with_status(
                        &northstar_room_application::muc_service::SerializableMucOccupant::from(
                            &occupant,
                        ),
                        &occupant.full_jid,
                        true,
                        true,
                        false,
                        None,
                        true,
                        Some(if new_affil == "outcast" { 301 } else { 321 }),
                        actor_nick.as_deref(),
                        reason.as_deref(),
                    );
                    let _ = session
                        .host()
                        .deliver_to_muc_occupant(&occupant, self_presence)
                        .await;
                } else {
                    let Some(occupant) = session.host().set_local_muc_affiliation_exact(
                        northstar_room_application::muc_service::LocalMucOccupantIdentity::from(
                            &occupant,
                        ),
                        new_affil,
                        room.moderated,
                        false,
                        Some(&occupant.affiliation),
                    ) else {
                        continue;
                    };

                    let serializable =
                        northstar_room_application::muc_service::SerializableMucOccupant::from(
                            &occupant,
                        );
                    if let Ok(json) = serde_json::to_string(&serializable) {
                        run_muc_cluster_occupant_refresh(
                            session.host(),
                            room_jid,
                            &occupant.nick,
                            json,
                            serializable,
                        )
                        .await;
                    }

                    for (_, other) in session.host().muc_occupants_for(room_jid) {
                        let self_presence = other.full_jid == occupant.full_jid;
                        let presence = muc_presence_stanza(
                            &northstar_room_application::muc_service::SerializableMucOccupant::from(
                                &occupant,
                            ),
                            &other.full_jid,
                            false,
                            self_presence,
                            false,
                            None,
                            occupant.room_non_anonymous
                                || self_presence
                                || other.role == "moderator",
                        );
                        let _ = session
                            .host()
                            .deliver_to_muc_occupant(&other, presence)
                            .await;
                    }
                }
            }
            for remote in remote_occupants {
                let remove_from_room =
                    new_affil == "outcast" || (new_affil == "none" && room.members_only);
                if remove_from_room {
                    let mut updated = remote;
                    updated.affiliation = new_affil.to_owned();
                    updated.role = "none".to_owned();
                    let removal_status = if new_affil == "outcast" { 301 } else { 321 };
                    if session
                        .host()
                        .revoke_cluster_muc_occupant_exact(
                            &updated,
                            removal_status,
                            actor_nick.as_deref(),
                            reason.as_deref(),
                        )
                        .await?
                    {
                        session
                            .host()
                            .publish_muc_cluster_presence(MucPresencePublication {
                                room: room_jid,
                                occupant: &updated,
                                unavailable: true,
                                created: false,
                                removal_status: Some(removal_status),
                                actor_nick: actor_nick.as_deref(),
                                reason: reason.as_deref(),
                            })
                            .await?;
                        for (_, other) in session.host().muc_occupants_for(room_jid) {
                            let presence = muc_presence_stanza_with_status(
                                &updated,
                                &other.full_jid,
                                true,
                                false,
                                false,
                                None,
                                updated.room_non_anonymous || other.role == "moderator",
                                Some(removal_status),
                                actor_nick.as_deref(),
                                reason.as_deref(),
                            );
                            let _ = session
                                .host()
                                .deliver_to_muc_occupant(&other, presence)
                                .await;
                        }
                    }
                } else {
                    let role = if matches!(new_affil, "owner" | "admin") {
                        "moderator"
                    } else if room.moderated && new_affil == "none" {
                        "visitor"
                    } else {
                        "participant"
                    };
                    let updated = match session
                        .host()
                        .change_cluster_muc_affiliation_exact(room_jid, &remote, new_affil, role)
                        .await?
                    {
                        northstar_room_core::occupancy::MucRoleChange::Changed(updated) => *updated,
                        northstar_room_core::occupancy::MucRoleChange::Stale => continue,
                    };
                    for (_, other) in session.host().muc_occupants_for(room_jid) {
                        let presence = muc_presence_stanza(
                            &updated,
                            &other.full_jid,
                            false,
                            false,
                            false,
                            None,
                            updated.room_non_anonymous || other.role == "moderator",
                        );
                        let _ = session
                            .host()
                            .deliver_to_muc_occupant(&other, presence)
                            .await;
                    }
                }
            }
        } else if let (Some(target_nick), Some(new_role)) =
            (item.attribute("nick"), item.attribute("role"))
        {
            if my_role != "moderator" {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "forbidden")));
            }
            if !matches!(new_role, "moderator" | "participant" | "visitor" | "none") {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
            }
            let Ok(target_nick) = prepare_muc_nick(target_nick) else {
                return Ok(MucAction::Send(iq_error_from(
                    id,
                    room_jid,
                    "jid-malformed",
                )));
            };
            let local_target = session
                .host()
                .local_muc_occupant_by_nick(room_jid, &target_nick);
            if local_target.is_none() {
                let remote = session
                    .host()
                    .cached_muc_cluster_occupants(room_jid)
                    .await?
                    .get(&target_nick)
                    .and_then(|json| {
                        serde_json::from_str::<
                            northstar_room_application::muc_service::SerializableMucOccupant,
                        >(json)
                        .ok()
                    });
                let Some(mut remote) = remote else {
                    return Ok(MucAction::Send(iq_error_from(
                        id,
                        room_jid,
                        "item-not-found",
                    )));
                };
                if my_affiliation == "admin"
                    && matches!(remote.affiliation.as_str(), "owner" | "admin")
                {
                    return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                if (new_role == "moderator" || remote.role == "moderator")
                    && !matches!(my_affiliation.as_str(), "owner" | "admin")
                {
                    return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                if matches!(remote.affiliation.as_str(), "owner" | "admin")
                    && !matches!(my_affiliation.as_str(), "owner" | "admin")
                {
                    return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                let reason = child_text(item, "reason").map(str::to_owned);
                if new_role == "none" {
                    remote.role = "none".to_owned();
                    if !session
                        .host()
                        .revoke_cluster_muc_occupant_exact(
                            &remote,
                            307,
                            actor_nick.as_deref(),
                            reason.as_deref(),
                        )
                        .await?
                    {
                        return Ok(MucAction::Send(iq_error_from(
                            id,
                            room_jid,
                            "item-not-found",
                        )));
                    }
                    session
                        .host()
                        .publish_muc_cluster_presence(MucPresencePublication {
                            room: room_jid,
                            occupant: &remote,
                            unavailable: true,
                            created: false,
                            removal_status: Some(307),
                            actor_nick: actor_nick.as_deref(),
                            reason: reason.as_deref(),
                        })
                        .await?;
                    for (_, other) in session.host().muc_occupants_for(room_jid) {
                        let presence = muc_presence_stanza_with_status(
                            &remote,
                            &other.full_jid,
                            true,
                            false,
                            false,
                            None,
                            remote.room_non_anonymous || other.role == "moderator",
                            Some(307),
                            actor_nick.as_deref(),
                            reason.as_deref(),
                        );
                        let _ = session
                            .host()
                            .deliver_to_muc_occupant(&other, presence)
                            .await;
                    }
                } else {
                    let updated = match session
                        .host()
                        .change_cluster_muc_role_exact(room_jid, &remote, new_role)
                        .await?
                    {
                        northstar_room_core::occupancy::MucRoleChange::Changed(updated) => *updated,
                        northstar_room_core::occupancy::MucRoleChange::Stale => {
                            return Ok(MucAction::Send(iq_error_from(
                                id,
                                room_jid,
                                "item-not-found",
                            )));
                        }
                    };
                    for (_, other) in session.host().muc_occupants_for(room_jid) {
                        let presence = muc_presence_stanza(
                            &updated,
                            &other.full_jid,
                            false,
                            false,
                            false,
                            None,
                            updated.room_non_anonymous || other.role == "moderator",
                        );
                        let _ = session
                            .host()
                            .deliver_to_muc_occupant(&other, presence)
                            .await;
                    }
                }
                continue;
            }
            let occupant = local_target.expect("checked above");
            if my_affiliation == "admin"
                && matches!(occupant.affiliation.as_str(), "owner" | "admin")
            {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
            }
            if (new_role == "moderator" || occupant.role == "moderator")
                && !matches!(my_affiliation.as_str(), "owner" | "admin")
            {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
            }
            if matches!(occupant.affiliation.as_str(), "owner" | "admin")
                && !matches!(my_affiliation.as_str(), "owner" | "admin")
            {
                return Ok(MucAction::Send(iq_error_from(id, room_jid, "not-allowed")));
            }
            if new_role == "none" {
                let Some(mut occupant) = session
                    .host()
                    .remove_local_muc_occupant_exact((&occupant).into())
                else {
                    return Ok(MucAction::Send(iq_error_from(
                        id,
                        room_jid,
                        "item-not-found",
                    )));
                };
                occupant.role = "none".to_owned();
                let reason = child_text(item, "reason").map(str::to_owned);
                let serializable =
                    northstar_room_application::muc_service::SerializableMucOccupant::from(
                        &occupant,
                    );
                for (_, other) in session.host().muc_occupants_for(room_jid) {
                    // The target receives exactly one self-presence below.
                    // Do not also deliver it through the room audience: a
                    // second unavailable 110/307 can remain queued ahead
                    // of a later rejoin response and violates ordered MUC
                    // status delivery.  Match the complete occupancy
                    // identity so a replacement connection is never
                    // suppressed as if it were the removed actor.
                    if is_exact_muc_removal_target(&other, &occupant) {
                        continue;
                    }
                    let presence = muc_presence_stanza_with_status(
                        &northstar_room_application::muc_service::SerializableMucOccupant::from(
                            &occupant,
                        ),
                        &other.full_jid,
                        true,
                        false,
                        false,
                        None,
                        occupant.room_non_anonymous || other.role == "moderator",
                        Some(307),
                        actor_nick.as_deref(),
                        reason.as_deref(),
                    );
                    let _ = session
                        .host()
                        .deliver_to_muc_occupant(&other, presence)
                        .await;
                }
                let presence = muc_presence_stanza_with_status(
                    &northstar_room_application::muc_service::SerializableMucOccupant::from(
                        &occupant,
                    ),
                    &occupant.full_jid,
                    true,
                    true,
                    false,
                    None,
                    true,
                    Some(307),
                    actor_nick.as_deref(),
                    reason.as_deref(),
                );
                let _ = session
                    .host()
                    .deliver_to_muc_occupant(&occupant, presence)
                    .await;
                session.host().remove_live_muc_membership(&serializable);
                let is_empty = session.host().muc_occupants_for(room_jid).is_empty();
                run_muc_cluster_eviction(
                    session.host(),
                    room_jid,
                    serializable,
                    307,
                    actor_nick.as_deref(),
                    reason.as_deref(),
                    is_empty,
                )
                .await;
            } else {
                let Some(occupant) = session.host().set_local_muc_role_exact(
                    (&occupant).into(),
                    &occupant.role,
                    new_role,
                    None,
                ) else {
                    return Ok(MucAction::Send(iq_error_from(
                        id,
                        room_jid,
                        "item-not-found",
                    )));
                };
                for (_, other) in session.host().muc_occupants_for(room_jid) {
                    let self_presence = other.full_jid == occupant.full_jid;
                    let presence = muc_presence_stanza(
                        &northstar_room_application::muc_service::SerializableMucOccupant::from(
                            &occupant,
                        ),
                        &other.full_jid,
                        false,
                        self_presence,
                        false,
                        None,
                        occupant.room_non_anonymous || self_presence || other.role == "moderator",
                    );
                    let _ = session
                        .host()
                        .deliver_to_muc_occupant(&other, presence)
                        .await;
                }
            }
        } else {
            return Ok(MucAction::Send(iq_error_from(id, room_jid, "bad-request")));
        }
    }

    Ok(MucAction::Send(iq_result_from(id, room_jid, "")))
}
