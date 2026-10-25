//! Room message entry point: groupchat, subject, retraction and discussion admission.

use super::*;

impl ProtocolSession {
    pub(crate) async fn muc_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        self.enter_frame_stage(Stage::MucPolicy);
        let Some(from) = self.full_jid.as_deref() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        if !self
            .state
            .xmpp_extension_enabled(northstar_xep_0045::XEP_ID)
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "service-unavailable",
            )));
        }
        let Some(to) = root.attribute("to") else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "jid-malformed",
            )));
        };
        let Ok(to_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "jid-malformed",
            )));
        };
        if to_jid.domainpart() != self.muc_domain() || to_jid.localpart().is_none() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "jid-malformed",
            )));
        }
        let room_jid = to_jid.bare();
        let decline = match parse_muc_invitation_decline(root) {
            Ok(decline) => decline,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        if let Some(decline) = decline {
            return self
                .handle_muc_invitation_decline(root, raw, from, room_jid, &to_jid, decline)
                .await;
        }
        let Some(own) = self.authorized_muc_occupant(&room_jid).await? else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "not-acceptable",
            )));
        };
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(current_room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        let current_affiliation = self
            .state
            .muc_service()
            .local_affiliation(current_room.id, user.id)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if current_affiliation == "outcast"
            || (current_room.members_only && current_affiliation == "none")
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        let voice_form = match parse_muc_voice_form(root) {
            Ok(form) => form,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        if let Some(voice_form) = voice_form {
            return self
                .handle_muc_voice_form(root, from, &to_jid, room_jid, &own, voice_form)
                .await;
        }

        if to.contains('/') {
            return self
                .handle_muc_private_message(root, raw, from, room_jid, &to_jid, &own)
                .await;
        }

        if root.attribute("type") != Some("groupchat") {
            return self
                .handle_muc_invitation(root, raw, from, room_jid, &own)
                .await;
        }
        let Some(initial_room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
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
        let local_authority_guard = if self.state.muc_pg_authority_enabled() {
            None
        } else {
            self.enter_frame_stage(Stage::MucGateWait);
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(initial_room.id)
                    .await,
            )
        };
        self.enter_frame_stage(Stage::MucAuthority);
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        if room.id != initial_room.id || room.room_epoch != initial_room.room_epoch {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        }
        let Some(own) = self.validated_muc_occupant(&room_jid) else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        };
        let current_affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if current_affiliation != own.affiliation
            || current_affiliation == "outcast"
            || (room.members_only && current_affiliation == "none")
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        let cluster_target = if self.state.muc_pg_authority_enabled() {
            let target = self
                .state
                .muc_service()
                .local_cluster_occupancy_target(room.id, own.cluster_epoch, own.connection_id)
                .await?;
            let Some(target) = target.filter(|target| {
                target.room_epoch == room.room_epoch
                    && target.full_jid == own.full_jid
                    && target.nick == own.nick
                    && target.connection_uuid == own.connection_id
            }) else {
                return Ok(Action::Send(muc_stanza_error(
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
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        let subject_command = match parse_muc_subject_command(root) {
            Ok(subject) => subject,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        let origin_id = match parse_muc_origin_id(root) {
            Ok(origin_id) => origin_id,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        let author_retraction = match parse_muc_author_retraction(root) {
            Ok(retraction) => retraction,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        if subject_command.is_some() && author_retraction.is_some() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
        if subject_command.is_some() && own.role != "moderator" && !room.allow_subject_change {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        let room_from = format!("{room_jid}/{}", own.nick);
        let stable_id = uuid::Uuid::new_v4();
        let rewritten = set_muc_occupant_id(
            &add_stanza_id(
                &set_to(&set_from(raw, &room_from), &room_jid),
                &room_jid,
                stable_id,
            ),
            &own.occupant_id,
        );
        let encrypted = is_encrypted(root);
        let archive_enabled = room.logging_enabled
            && !has_no_store_hint(root)
            && (encrypted || !self.state.archive_requires_encryption());
        let archive = if archive_enabled && encrypted {
            encrypted_archive_stanza(&rewritten)
        } else {
            rewritten.clone()
        };
        let actor_scope = canonical_bare_key(from)?;
        let actor_authority = MucActorAuthority {
            clustered: self.state.muc_pg_authority_enabled(),
            expected_room_epoch: room.room_epoch,
            principal: MucActorPrincipal::Local {
                user_id: user.id,
                local_domain: self.state.local_domain().to_owned(),
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
        if let Some(target_id) = author_retraction {
            let Some(original) = self
                .state
                .muc_service()
                .local_message_by_id(room.id, target_id)
                .await?
            else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            };
            if canonical_bare_key(&original.sender_jid).ok().as_deref()
                != Some(actor_scope.as_str())
            {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            let Ok(original_document) = roxmltree::Document::parse(&original.stanza) else {
                return Ok(Action::Send(muc_stanza_error(
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
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "not-acceptable",
                )));
            }
            let stamp = chrono::Utc::now();
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
            self.enter_frame_stage(Stage::MucAdmission);
            match self
                .state
                .muc_service()
                .execute_muc_retraction(MucRetractionCommand {
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
                .await?
                .outcome
            {
                MucRetractionOutcome::Applied => {}
                MucRetractionOutcome::Unauthorized => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
                    return Ok(Action::Send(muc_stanza_error(
                        root, from, "cancel", "conflict",
                    )));
                }
            }
        } else if let Some(subject) = subject_command.as_deref() {
            let service = self.state.muc_service();
            if self.state.muc_pg_authority_enabled() {
                let Some(actor_target) = service
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                    .await?
                else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                };
                if actor_target.full_jid != own.full_jid
                    || actor_target.connection_uuid != own.connection_id
                {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                let operation_id = crate::services::muc::operation_id(&serde_json::json!({
                    "kind":"subject","stream":self.connection_id,"stanza_id":root.attribute("id"),
                    "room":room_jid,"actor":actor_target,"subject":subject,"archive":archive_enabled
                }))?;
                self.enter_frame_stage(Stage::MucAdmission);
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
                            stanza: &archive,
                            encrypted,
                        },
                        archive_enabled,
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    }
                    _ => {
                        return Ok(Action::Send(muc_stanza_error(
                            root, from, "cancel", "conflict",
                        )));
                    }
                }
                if let Err(error) = self.state.wake_committed_muc_operation(operation_id).await {
                    tracing::warn!(?error, %operation_id, "committed MUC subject wake failed; PostgreSQL outbox will catch up");
                }
                return Ok(Action::None);
            }
            self.enter_frame_stage(Stage::MucAdmission);
            match service
                .execute_muc_subject(MucSubjectCommand {
                    mutation: MucSubjectMutation {
                        stanza_id: stable_id,
                        room_id: room.id,
                        actor_scope: &actor_scope,
                        sender_jid: from,
                        nick: &own.nick,
                        subject,
                        stanza: &archive,
                        encrypted,
                    },
                    archive: archive_enabled,
                    authority: actor_authority,
                })
                .await?
                .outcome
            {
                MucSubjectOutcome::Applied => {}
                MucSubjectOutcome::Unauthorized => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                MucSubjectOutcome::Stale => {
                    return Ok(Action::Send(muc_stanza_error(
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
                stanza: archive.clone(),
                encrypted,
                archive: archive_enabled,
                retention_days: self.state.muc_mam_retention_days(),
                authority: actor_authority,
            };
            let prepared = PreparedMucDiscussion::new(
                self.state.muc_service().prepare_muc_discussion(discussion),
                &room,
                room_jid.clone(),
                rewritten.clone(),
            )?;
            // Only genuine absence of a frame uses the compatibility entry.
            // Retired/conflicting registration propagates before any SQL.
            let operation = self.muc_discussion_operation(&prepared.prepared)?;
            let admission = if let Some(operation) = operation {
                let bound = prepared.bind(operation)?;
                self.enter_frame_stage(Stage::MucAdmission);
                let completion = self
                    .state
                    .muc_service()
                    .execute_muc_discussion_observed(&bound.request)
                    .await?;
                let admission = completion.outcome();
                discussion_fanout = bound.finish(completion)?;
                admission
            } else {
                self.enter_frame_stage(Stage::MucAdmission);
                self.state
                    .muc_service()
                    .execute_muc_discussion(prepared.prepared.command())
                    .await?
            };
            match admission {
                MucDiscussionAdmission::Stored(_) => {}
                MucDiscussionAdmission::Replay(_) => {
                    fanout_disposition = MucFanoutDisposition::Replay;
                }
                MucDiscussionAdmission::Unauthorized => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                MucDiscussionAdmission::Stale => {
                    return Ok(Action::Send(muc_stanza_error(
                        root, from, "cancel", "conflict",
                    )));
                }
            }
        }
        let attempted = if let Some(accepted) = discussion_fanout {
            accepted.fanout(self).await?
        } else {
            run_muc_fanout(
                &MucMessageFanout {
                    session: self,
                    room_jid: &room_jid,
                    room_from: &room_from,
                    sender: from,
                    stanza: &rewritten,
                },
                fanout_disposition,
            )
            .await
        };
        if !attempted {
            return Ok(Action::None);
        }
        // The single-node authority gate is intentionally released only after
        // the accepted incarnation's complete live fan-out has been queued.
        drop(local_authority_guard);
        self.state.muc_telemetry().message_routed();
        Ok(Action::None)
    }
}
