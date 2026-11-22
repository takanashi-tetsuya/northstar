//! Authorize, prepare, admit and fan out federated groupchat messages.

use super::archive_eligibility::{
    archive_payload, cluster_subject_archive, federated_archive_eligible,
};
use super::*;
use northstar_room_core::{stanza::apply_muc_discussion_reflection, ClusterMucOccupancyTarget};
use tokio::sync::OwnedMutexGuard;

pub(super) struct GroupchatAuthority<S: MucHost> {
    pub(super) local_authority_guard: Option<OwnedMutexGuard<()>>,
    pub(super) occupancy: GroupchatOccupancy<S>,
    pub(super) cluster_target: Option<ClusterMucOccupancyTarget>,
}

pub(super) struct GroupchatOccupancy<S: MucHost> {
    room: MucRoom,
    own: Occupant<S>,
    current_affiliation: String,
}

pub(super) struct GroupchatReflection {
    reflected: String,
    actor_scope: String,
}

pub(super) struct GroupchatAdmission<'a> {
    subject_command: Option<&'a str>,
    origin_id: Option<&'a str>,
    author_retraction: Option<uuid::Uuid>,
    stable_id: uuid::Uuid,
    eligible: bool,
    archive: String,
    actor_authority: MucActorAuthority,
}

pub(super) async fn recheck_groupchat_authority<S: MucHost>(
    state: &S,
    authenticated_domain: &str,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
    occupancy: &RoomOccupancy<S>,
) -> Result<MessageStep<GroupchatAuthority<S>>> {
    let &MessageAddress {
        from,
        ref actor_bare_jid,
        ref room_jid,
        ..
    } = address;
    let RoomOccupancy { own, room } = occupancy;
    // In single-node mode the room map is the occupancy authority. Serialize
    // the final remote endpoint/incarnation check, durable admission and live
    // fan-out with the same room gate used by kick/ban/leave. Cluster mode
    // instead presents the exact PostgreSQL occupancy tuple below.
    let local_authority_guard = if state.federated_muc_pg_authority_enabled() {
        None
    } else {
        Some(state.muc_service().lock_local_room_mutation(room.id).await)
    };
    let Some(refreshed_room) = state
        .muc_service()
        .federated_room_snapshot(localpart(room_jid))
        .await?
    else {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        )));
    };
    if refreshed_room.id != room.id || refreshed_room.room_epoch != room.room_epoch {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        )));
    }
    let Some((_, refreshed_own)) =
        state
            .muc_occupants_for(room_jid)
            .into_iter()
            .find(|(_, occupant)| {
                occupant.full_jid == own.full_jid
                    && occupant.connection_id == own.connection_id
                    && occupant.cluster_epoch == own.cluster_epoch
                    && occupant.nick == own.nick
            })
    else {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "auth",
            "forbidden",
        )));
    };
    if !federated_endpoint_matches(&refreshed_own, authenticated_domain) {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        )));
    }
    let room = refreshed_room;
    let own = refreshed_own;
    let current_affiliation = state
        .muc_service()
        .federated_affiliation(room.id, actor_bare_jid)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if current_affiliation != own.affiliation
        || current_affiliation == "outcast"
        || (room.members_only && current_affiliation == "none")
    {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "auth",
            "forbidden",
        )));
    }
    let cluster_target = if state.federated_muc_pg_authority_enabled() {
        let Some(target) = state
            .muc_service()
            .local_cluster_occupancy_target(room.id, own.cluster_epoch, own.connection_id)
            .await?
            .filter(|target| {
                target.room_epoch == room.room_epoch
                    && target.full_jid == own.full_jid
                    && target.nick == own.nick
                    && target.connection_uuid == own.connection_id
            })
        else {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "auth",
                "forbidden",
            )));
        };
        Some(target)
    } else {
        None
    };
    if own.role == "visitor" {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "auth",
            "forbidden",
        )));
    }
    Ok(MessageStep::Next(GroupchatAuthority {
        local_authority_guard,
        occupancy: GroupchatOccupancy {
            room,
            own,
            current_affiliation,
        },
        cluster_target,
    }))
}

pub(super) fn prepare_groupchat<'a, S: MucHost>(
    state: &S,
    authenticated_domain: &str,
    request: &'a FederatedMessageRequest,
    address: &MessageAddress<'_>,
    occupancy: &GroupchatOccupancy<S>,
    cluster_target: Option<ClusterMucOccupancyTarget>,
) -> Result<MessageStep<(GroupchatReflection, GroupchatAdmission<'a>)>> {
    let &MessageAddress {
        from,
        ref actor_full_jid,
        ref actor_bare_jid,
        ref to_jid,
        ref room_jid,
        ..
    } = address;
    let GroupchatOccupancy {
        room,
        own,
        current_affiliation,
    } = occupancy;
    let subject_command = match &request.subject {
        Ok(subject) => subject.as_deref(),
        Err(MalformedMucStanza) => {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    let origin_id = match &request.origin_id {
        Ok(origin_id) => origin_id.as_deref(),
        Err(MalformedMucStanza) => {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    let author_retraction = match request.author_retraction {
        Ok(retraction) => retraction,
        Err(MalformedMucStanza) => {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    if subject_command.is_some() && author_retraction.is_some() {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "modify",
            "bad-request",
        )));
    }
    if subject_command.is_some()
        && own.role != "moderator"
        && !(room.allow_subject_change && own.role == "participant")
    {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "auth",
            "forbidden",
        )));
    }
    let stable_id = uuid::Uuid::new_v4();
    let reflected = set_muc_occupant_id(
        &add_stanza_id(
            &set_to(
                &set_from(&request.stanza.raw, &format!("{room_jid}/{}", own.nick)),
                room_jid,
            ),
            room_jid,
            stable_id,
        ),
        &own.occupant_id,
    );
    let eligible = federated_archive_eligible(request, to_jid, state.archive_requires_encryption());
    let archive = archive_payload(&reflected, eligible, request.encrypted);
    let actor_scope = northstar_xmpp_types::jid::canonical_bare_key(actor_full_jid)?;
    let actor_authority = MucActorAuthority {
        clustered: state.federated_muc_pg_authority_enabled(),
        expected_room_epoch: room.room_epoch,
        principal: MucActorPrincipal::Federated {
            bare_jid: actor_bare_jid.clone(),
            authenticated_domain: authenticated_domain.to_owned(),
        },
        actor_scope: actor_scope.clone(),
        full_jid: actor_full_jid.clone(),
        nick: own.nick.clone(),
        occupant_incarnation: own.cluster_epoch,
        connection_uuid: own.connection_id,
        expected_role: own.role.clone(),
        expected_affiliation: current_affiliation.clone(),
        cluster_target,
    };
    Ok(MessageStep::Next((
        GroupchatReflection {
            reflected,
            actor_scope,
        },
        GroupchatAdmission {
            subject_command,
            origin_id,
            author_retraction,
            stable_id,
            eligible,
            archive,
            actor_authority,
        },
    )))
}

pub(super) async fn admit_groupchat<S: MucHost>(
    state: &S,
    connection_id: &uuid::Uuid,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
    occupancy: &GroupchatOccupancy<S>,
    reflection: &mut GroupchatReflection,
    admission: GroupchatAdmission<'_>,
) -> Result<MessageStep<()>> {
    let &MessageAddress {
        from,
        ref actor_full_jid,
        ref room_jid,
        ..
    } = address;
    let GroupchatOccupancy { room, own, .. } = occupancy;
    let &mut GroupchatReflection {
        ref mut reflected,
        ref actor_scope,
    } = reflection;
    let GroupchatAdmission {
        subject_command,
        origin_id,
        author_retraction,
        stable_id,
        eligible,
        archive,
        actor_authority,
    } = admission;
    if let Some(target_id) = author_retraction {
        let Some(original) = state
            .muc_service()
            .federated_message_by_id(room.id, target_id)
            .await?
        else {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        if northstar_xmpp_types::jid::canonical_bare_key(&original.sender_jid)
            .ok()
            .as_deref()
            != Some(actor_scope.as_str())
        {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "auth",
                "forbidden",
            )));
        }
        let Ok(original_document) = roxmltree::Document::parse(&original.stanza) else {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "wait",
                "internal-server-error",
            )));
        };
        let original_root = original_document.root_element();
        if original_root.tag_name().name() != "message"
            || original_root.attribute("type") != Some("groupchat")
        {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "not-acceptable",
            )));
        }
        let stamp = northstar_time::Utc::now();
        let tombstone = XmlElement::namespaced("message", "jabber:client")
            .attr("from", original_root.attribute("from").unwrap_or(room_jid))
            .attr("to", room_jid)
            .attr("type", "groupchat")
            .attr("id", original_root.attribute("id").unwrap_or_default())
            .child(
                XmlElement::namespaced("stanza-id", "urn:xmpp:sid:0")
                    .attr("id", target_id)
                    .attr("by", room_jid),
            )
            .child(
                XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0").attr(
                    "id",
                    muc_occupant_id(&room.occupant_id_secret, &original.sender_jid),
                ),
            )
            .child(
                XmlElement::namespaced("retracted", "urn:xmpp:message-retract:1")
                    .attr("stamp", stamp.format("%Y-%m-%dT%H:%M:%SZ")),
            )
            .finish();
        match state
            .muc_service()
            .retract_local_message_and_archive_action(MucRetractionMutation {
                action_id: stable_id,
                room_id: room.id,
                target_id,
                expected_stanza: &original.stanza,
                actor_scope,
                sender_jid: actor_full_jid,
                nick: &own.nick,
                tombstone: &tombstone,
                action_stanza: reflected,
                reason: None,
                kind: MucRetractionKind::Author,
                authority: actor_authority,
            })
            .await?
        {
            MucRetractionOutcome::Applied => {}
            MucRetractionOutcome::Unauthorized => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "conflict",
                )));
            }
        }
    } else if let Some(subject) = subject_command {
        let service = state.muc_service();
        if state.federated_muc_pg_authority_enabled() {
            let Some(actor_target) = service
                .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                .await?
            else {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "forbidden",
                )));
            };
            if actor_target.full_jid != own.full_jid
                || actor_target.connection_uuid != own.connection_id
            {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            let (subject_stanza, subject_archive) =
                cluster_subject_archive(reflected, &archive, eligible, room.logging_enabled);
            let operation_id = northstar_room_application::muc_service::operation_id(
                &serde_json::json!({
                    "kind":"subject","stream":*connection_id,"stanza_id":request.stanza.id,
                    "room":room_jid,"actor":actor_target,"subject":subject,"archive":subject_archive.digest_archive
                }),
            )?;
            match service
                .set_local_cluster_subject(
                    operation_id,
                    room.room_epoch,
                    room.config_version,
                    &actor_target,
                    MucSubjectMutation {
                        stanza_id: stable_id,
                        room_id: room.id,
                        actor_scope,
                        sender_jid: actor_full_jid,
                        nick: &own.nick,
                        subject,
                        stanza: subject_stanza,
                        encrypted: request.encrypted,
                    },
                    subject_archive,
                )
                .await?
            {
                ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                ClusterMucTransitionOutcome::Unauthorized => {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                _ => {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "conflict",
                    )))
                }
            }
            if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                tracing::warn!(?error, %operation_id, "committed federated MUC subject wake failed; PostgreSQL outbox will catch up");
            }
            return Ok(MessageStep::Done(None));
        }
        match service
            .set_local_subject(
                MucSubjectMutation {
                    stanza_id: stable_id,
                    room_id: room.id,
                    actor_scope,
                    sender_jid: actor_full_jid,
                    nick: &own.nick,
                    subject,
                    stanza: reflected,
                    encrypted: request.encrypted,
                },
                eligible.then_some(archive.as_str()),
                actor_authority,
            )
            .await?
        {
            MucSubjectOutcome::Applied => {}
            MucSubjectOutcome::Unauthorized => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            MucSubjectOutcome::Stale => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "conflict",
                )));
            }
        }
    } else {
        let admission = state
            .muc_service()
            .admit_local_discussion(MucDiscussion {
                id: stable_id,
                room_id: room.id,
                actor_scope: actor_scope.clone(),
                origin_id: origin_id.map(str::to_owned),
                sender_jid: actor_full_jid.clone(),
                nick: own.nick.clone(),
                stanza: archive,
                encrypted: request.encrypted,
                archive_eligible: eligible,
                unarchived_stanza_bytes: (eligible && request.encrypted).then_some(reflected.len()),
                retention_days: state.muc_mam_retention_days(),
                authority: actor_authority,
            })
            .await?;
        match admission {
            MucDiscussionAdmission::Stored { .. } => apply_muc_discussion_reflection(
                reflected,
                room_jid,
                admission,
                eligible && room.logging_enabled,
            ),
            MucDiscussionAdmission::Replay(_) => return Ok(MessageStep::Done(None)),
            MucDiscussionAdmission::Unauthorized => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            MucDiscussionAdmission::Stale => {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "conflict",
                )));
            }
        }
    }
    Ok(MessageStep::Next(()))
}

pub(super) async fn fan_out_groupchat<S: MucHost>(
    state: &S,
    address: &MessageAddress<'_>,
    occupancy: &GroupchatOccupancy<S>,
    reflection: &GroupchatReflection,
    local_authority_guard: Option<OwnedMutexGuard<()>>,
) -> Result<Option<String>> {
    let MessageAddress {
        actor_full_jid,
        room_jid,
        ..
    } = address;
    let GroupchatOccupancy { own, .. } = occupancy;
    let GroupchatReflection { reflected, .. } = reflection;
    if state
        .federated_muc_publish_room_message(room_jid, reflected, Some(actor_full_jid))
        .await
        .is_err()
    {
        record_federated_muc_post_commit_failure(state, room_jid, "*", "cluster groupchat fan-out");
    }
    let occupants = state
        .muc_occupants_for(room_jid)
        .into_iter()
        .map(|(_, occupant)| occupant)
        .collect::<Vec<_>>();
    let blocked = state
        .blocked_muc_recipient_accounts(
            &occupants,
            &[format!("{room_jid}/{}", own.nick), actor_full_jid.clone()],
        )
        .await;
    for occupant in occupants {
        if northstar_xmpp_types::jid::canonical_bare_key(&occupant.full_jid)
            .is_ok_and(|owner| blocked.contains(&owner))
        {
            continue;
        }
        let delivery = set_to(reflected, &occupant.full_jid);
        if !state
            .deliver_to_muc_occupant_unchecked(&occupant, delivery)
            .await
        {
            record_federated_muc_post_commit_failure(
                state,
                room_jid,
                &occupant.full_jid,
                "occupant groupchat queue",
            );
        }
    }
    drop(local_authority_guard);
    state.federated_muc_telemetry().message_routed();
    Ok(None)
}
