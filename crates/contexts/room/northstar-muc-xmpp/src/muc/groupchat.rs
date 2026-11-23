//! Room message entry point: groupchat, subject, retraction and discussion admission.

use super::*;
use crate::federated_muc::message::archive_eligibility::{
    archive_eligible, archive_payload, cluster_subject_archive,
};
use northstar_room_core::stanza::apply_muc_discussion_reflection;

pub async fn muc_message(
    session: &impl MucSession,
    root: Node<'_, '_>,
    raw: &str,
) -> Result<MucAction> {
    let facts = session.host().muc_time_sources().prepare_request();
    session.enter_frame_stage(MucFrameStage::Policy);
    let Some(from) = session.full_jid() else {
        return Ok(MucAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        )));
    };
    if !session
        .host()
        .xmpp_extension_enabled(northstar_xep_0045::XEP_ID)
    {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "cancel",
            "service-unavailable",
        )));
    }
    let Some(to) = root.attribute("to") else {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "modify",
            "jid-malformed",
        )));
    };
    let Ok(to_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "modify",
            "jid-malformed",
        )));
    };
    if to_jid.domainpart() != muc_domain(session) || to_jid.localpart().is_none() {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "modify",
            "jid-malformed",
        )));
    }
    let decline = match parse_muc_invitation_decline(root) {
        Ok(decline) => decline,
        Err(MalformedMucStanza) => {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    if let Some(decline) = decline {
        return handle_muc_invitation_decline(session, root, raw, from, &to_jid, decline, facts)
            .await;
    }
    let room_jid = to_jid.bare();
    let voice_form = parse_muc_voice_form(root);
    match &voice_form {
        Ok(Some(MucVoiceForm::Request)) => {
            return super::message::handle_local_voice_request(
                session, root, from, &to_jid, &room_jid,
            )
            .await;
        }
        Ok(None) if to.contains('/') => {
            return handle_muc_private_message(
                session, root, raw, from, room_jid, &to_jid, facts.id,
            )
            .await;
        }
        _ => {}
    }
    let Some(own) = authorized_muc_occupant(session, &room_jid).await? else {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "auth",
            "not-acceptable",
        )));
    };
    let Some(user) = session.user() else {
        return Ok(MucAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        )));
    };
    let Some(current_room) = session
        .host()
        .muc_service()
        .local_room_snapshot(localpart(&room_jid))
        .await?
    else {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "cancel",
            "item-not-found",
        )));
    };
    let current_affiliation = session
        .host()
        .muc_service()
        .local_affiliation(current_room.id, user.id)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if current_affiliation == "outcast"
        || (current_room.members_only && current_affiliation == "none")
    {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "auth",
            "forbidden",
        )));
    }
    let voice_form = match voice_form {
        Ok(form) => form,
        Err(MalformedMucStanza) => {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    if let Some(voice_form) = voice_form {
        return handle_muc_voice_form(session, root, from, &to_jid, room_jid, &own, voice_form)
            .await;
    }

    if root.attribute("type") != Some("groupchat") {
        return handle_muc_invitation(session, root, raw, from, room_jid, &own, facts).await;
    }
    let Some(initial_room) = session
        .host()
        .muc_service()
        .local_room_snapshot(localpart(&room_jid))
        .await?
    else {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "cancel",
            "item-not-found",
        )));
    };
    // Single-node occupancy is intentionally process-local. Hold the one
    // room mutation gate from the final incarnation/affiliation check
    // through database admission and live fan-out. Clustered rooms use
    // the exact PostgreSQL occupancy tuple in the admission transaction.
    let local_authority_guard = if session.host().muc_pg_authority_enabled() {
        None
    } else {
        session.enter_frame_stage(MucFrameStage::GateWait);
        Some(
            session
                .host()
                .muc_service()
                .lock_local_room_mutation(initial_room.id)
                .await,
        )
    };
    session.enter_frame_stage(MucFrameStage::Authority);
    let Some(room) = session
        .host()
        .muc_service()
        .local_room_snapshot(localpart(&room_jid))
        .await?
    else {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "cancel",
            "item-not-found",
        )));
    };
    if room.id != initial_room.id || room.room_epoch != initial_room.room_epoch {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "cancel",
            "item-not-found",
        )));
    }
    let Some(own) = validated_muc_occupant(session, &room_jid) else {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "auth",
            "forbidden",
        )));
    };
    let current_affiliation = session
        .host()
        .muc_service()
        .local_affiliation(room.id, user.id)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if current_affiliation != own.affiliation
        || current_affiliation == "outcast"
        || (room.members_only && current_affiliation == "none")
    {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "auth",
            "forbidden",
        )));
    }
    let cluster_target = if session.host().muc_pg_authority_enabled() {
        let target = session
            .host()
            .muc_service()
            .local_cluster_occupancy_target(room.id, own.cluster_epoch, own.connection_id)
            .await?;
        let Some(target) = target.filter(|target| {
            target.room_epoch == room.room_epoch
                && target.full_jid == own.full_jid
                && target.nick == own.nick
                && target.connection_uuid == own.connection_id
        }) else {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
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
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "auth",
            "forbidden",
        )));
    }
    let subject_command = match parse_muc_subject_command(root) {
        Ok(subject) => subject,
        Err(MalformedMucStanza) => {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    let origin_id = match parse_muc_origin_id(root) {
        Ok(origin_id) => origin_id,
        Err(MalformedMucStanza) => {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    let author_retraction = match parse_muc_author_retraction(root) {
        Ok(retraction) => retraction,
        Err(MalformedMucStanza) => {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    if subject_command.is_some() && author_retraction.is_some() {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "modify",
            "bad-request",
        )));
    }
    if subject_command.is_some() && own.role != "moderator" && !room.allow_subject_change {
        return Ok(MucAction::Send(muc_stanza_error(
            root,
            from,
            "auth",
            "forbidden",
        )));
    }
    let room_from = format!("{room_jid}/{}", own.nick);
    let stable_id = facts.id;
    let mut rewritten = set_muc_occupant_id(
        &add_stanza_id(
            &set_to(&set_from(raw, &room_from), &room_jid),
            &room_jid,
            stable_id,
        ),
        &own.occupant_id,
    );
    let encrypted = is_encrypted(root);
    let eligible = archive_eligible(
        &to_jid,
        !has_no_store_hint(root),
        encrypted,
        session.host().archive_requires_encryption(),
    );
    let archive = archive_payload(&rewritten, eligible, encrypted);
    let actor_scope = canonical_bare_key(from)?;
    let actor_authority = MucActorAuthority {
        clustered: session.host().muc_pg_authority_enabled(),
        expected_room_epoch: room.room_epoch,
        principal: MucActorPrincipal::Local {
            user_id: user.id,
            local_domain: session.host().local_domain().to_owned(),
        },
        actor_scope: actor_scope.clone(),
        full_jid: from.to_owned(),
        nick: own.nick.clone(),
        occupant_incarnation: own.cluster_epoch,
        connection_uuid: own.connection_id,
        expected_role: own.role.clone(),
        expected_affiliation: current_affiliation.clone(),
        cluster_target,
    };
    let mut fanout_disposition = MucFanoutDisposition::Accepted;
    let mut discussion_fanout = None;
    let mut live_audience = None;
    if let Some(target_id) = author_retraction {
        let Some(original) = session
            .host()
            .muc_service()
            .local_message_by_id(room.id, target_id)
            .await?
        else {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        if canonical_bare_key(&original.sender_jid).ok().as_deref() != Some(actor_scope.as_str()) {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        let Ok(original_document) = roxmltree::Document::parse(&original.stanza) else {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
                from,
                "wait",
                "internal-server-error",
            )));
        };
        let original_root = original_document.root_element();
        if original_root.tag_name().name() != "message"
            || original_root.attribute("type") != Some("groupchat")
        {
            return Ok(MucAction::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "not-acceptable",
            )));
        }
        let stamp = facts.at;
        let retraction_message_id = root
            .attribute("id")
            .map(str::to_owned)
            .unwrap_or_else(|| stable_id.to_string());
        let tombstone = XmlElement::namespaced("message", "jabber:client")
            .attr("from", original_root.attribute("from").unwrap_or(&room_jid))
            .attr("to", &room_jid)
            .attr("type", "groupchat")
            .attr("id", original_root.attribute("id").unwrap_or_default())
            .child(
                XmlElement::namespaced("stanza-id", "urn:xmpp:sid:0")
                    .attr("id", target_id)
                    .attr("by", &room_jid),
            )
            .child(
                XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0").attr(
                    "id",
                    muc_occupant_id(&room.occupant_id_secret, &original.sender_jid),
                ),
            )
            .child(
                XmlElement::namespaced("retracted", "urn:xmpp:message-retract:1")
                    .attr("id", &retraction_message_id)
                    .attr("stamp", stamp.format("%Y-%m-%dT%H:%M:%SZ")),
            )
            .finish();
        session.enter_frame_stage(MucFrameStage::Admission);
        let commit = session
            .host()
            .muc_service()
            .execute_muc_live_retraction(MucRetractionCommand {
                mutation: MucRetractionMutation {
                    action_id: stable_id,
                    room_id: room.id,
                    target_id,
                    expected_stanza: &original.stanza,
                    actor_scope: &actor_scope,
                    sender_jid: from,
                    nick: &own.nick,
                    tombstone: &tombstone,
                    action_stanza: &rewritten,
                    reason: None,
                    kind: MucRetractionKind::Author,
                    authority: actor_authority,
                },
            })
            .await?;
        match commit.outcome {
            MucRetractionOutcome::Applied => live_audience = commit.audience,
            MucRetractionOutcome::Unauthorized => {
                return Ok(MucAction::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
                return Ok(MucAction::Send(muc_stanza_error(
                    root, from, "cancel", "conflict",
                )));
            }
        }
    } else if let Some(subject) = subject_command.as_deref() {
        let service = session.host().muc_service();
        if session.host().muc_pg_authority_enabled() {
            let Some(actor_target) = service
                .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                .await?
            else {
                return Ok(MucAction::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            };
            if actor_target.full_jid != own.full_jid
                || actor_target.connection_uuid != own.connection_id
            {
                return Ok(MucAction::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            let (subject_stanza, subject_archive) =
                cluster_subject_archive(&rewritten, &archive, eligible, room.logging_enabled);
            let operation_id = northstar_room_application::muc_service::operation_id(
                &serde_json::json!({
                    "kind":"subject","stream":session.connection_id(),"stanza_id":root.attribute("id"),
                    "room":room_jid,"actor":actor_target,"subject":subject,"archive":subject_archive.digest_archive
                }),
            )?;
            session.enter_frame_stage(MucFrameStage::Admission);
            match service
                .set_local_cluster_subject(
                    operation_id,
                    room.room_epoch,
                    room.config_version,
                    &actor_target,
                    MucSubjectMutation {
                        stanza_id: stable_id,
                        room_id: room.id,
                        actor_scope: &actor_scope,
                        sender_jid: from,
                        nick: &own.nick,
                        subject,
                        stanza: subject_stanza,
                        encrypted,
                    },
                    subject_archive,
                )
                .await?
            {
                ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                ClusterMucTransitionOutcome::Unauthorized => {
                    return Ok(MucAction::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                _ => {
                    return Ok(MucAction::Send(muc_stanza_error(
                        root, from, "cancel", "conflict",
                    )));
                }
            }
            if let Err(error) = session
                .host()
                .wake_committed_muc_operation(operation_id)
                .await
            {
                tracing::warn!(?error, %operation_id, "committed MUC subject wake failed; PostgreSQL outbox will catch up");
            }
            return Ok(MucAction::None);
        }
        session.enter_frame_stage(MucFrameStage::Admission);
        match service
            .execute_muc_subject(MucSubjectCommand {
                mutation: MucSubjectMutation {
                    stanza_id: stable_id,
                    room_id: room.id,
                    actor_scope: &actor_scope,
                    sender_jid: from,
                    nick: &own.nick,
                    subject,
                    stanza: &rewritten,
                    encrypted,
                },
                archive_stanza: eligible.then_some(archive.as_str()),
                authority: actor_authority,
            })
            .await?
            .outcome
        {
            MucSubjectOutcome::Applied => {}
            MucSubjectOutcome::Unauthorized => {
                return Ok(MucAction::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            MucSubjectOutcome::Stale => {
                return Ok(MucAction::Send(muc_stanza_error(
                    root, from, "cancel", "conflict",
                )));
            }
        }
    } else {
        let discussion = MucDiscussion {
            id: stable_id,
            room_id: room.id,
            actor_scope: actor_scope.clone(),
            origin_id,
            sender_jid: from.to_owned(),
            nick: own.nick.clone(),
            stanza: archive,
            encrypted,
            archive_eligible: eligible,
            unarchived_stanza_bytes: (eligible && encrypted).then_some(rewritten.len()),
            retention_days: session.host().muc_mam_retention_days(),
            authority: actor_authority,
        };
        let prepared = PreparedMucDiscussion::new(
            session
                .host()
                .muc_service()
                .prepare_muc_discussion(discussion),
            &room,
            room_jid.clone(),
            rewritten.clone(),
        )?;
        // Only genuine absence of a frame uses the compatibility entry.
        // Retired/conflicting registration propagates before any SQL.
        let operation = session.muc_discussion_operation(&prepared.prepared)?;
        let admission = if let Some(operation) = operation {
            let bound = prepared.bind(operation)?;
            session.enter_frame_stage(MucFrameStage::Admission);
            let completion = session
                .host()
                .muc_service()
                .execute_muc_discussion_observed(&bound.request)
                .await?;
            let admission = completion.outcome();
            discussion_fanout = bound.finish(completion)?;
            admission
        } else {
            session.enter_frame_stage(MucFrameStage::Admission);
            let commit = session
                .host()
                .muc_service()
                .execute_muc_live_discussion(prepared.prepared.command())
                .await?;
            live_audience = commit.audience;
            commit.outcome
        };
        match admission {
            MucDiscussionAdmission::Stored { .. } if discussion_fanout.is_none() => {
                apply_muc_discussion_reflection(
                    &mut rewritten,
                    &room_jid,
                    admission,
                    eligible && room.logging_enabled,
                );
            }
            MucDiscussionAdmission::Stored { .. } => {}
            MucDiscussionAdmission::Replay(_) => {
                fanout_disposition = MucFanoutDisposition::Replay;
            }
            MucDiscussionAdmission::Unauthorized => {
                return Ok(MucAction::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            MucDiscussionAdmission::Stale => {
                return Ok(MucAction::Send(muc_stanza_error(
                    root, from, "cancel", "conflict",
                )));
            }
        }
    }
    let attempted = if let Some(accepted) = discussion_fanout {
        accepted.fanout(session).await?
    } else {
        run_muc_fanout(
            &MucMessageFanout {
                session,
                room_jid: &room_jid,
                room_from: &room_from,
                sender: from,
                stanza: &rewritten,
                audience: live_audience.as_ref(),
            },
            fanout_disposition,
        )
        .await
    };
    if !attempted {
        return Ok(MucAction::None);
    }
    // The single-node authority gate is intentionally released only after
    // the accepted incarnation's complete live fan-out has been queued.
    drop(local_authority_guard);
    session.host().muc_telemetry().message_routed();
    Ok(MucAction::None)
}
