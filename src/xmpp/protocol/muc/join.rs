//! Room presence entry point: joins, nickname and status changes.

use super::*;

// Keep the live-session admission bound equal to the durable XEP-0198
// snapshot bound in the durable SM service. Rejecting the 257th room at join time is safer
// than discovering at disconnect that the session can no longer be resumed.
pub(super) const MAX_JOINED_ROOMS_PER_SESSION: usize = 256;

pub(super) fn muc_sender_is_blocked(
    patterns: &[String],
    owner_bare: &str,
    visible_sender: &str,
    real_sender: Option<&str>,
) -> bool {
    [Some(visible_sender), real_sender]
        .into_iter()
        .flatten()
        .filter(|sender| {
            northstar_xmpp_types::jid::canonical_bare_key(sender)
                .is_ok_and(|sender_bare| sender_bare != owner_bare)
        })
        .any(|sender| {
            patterns
                .iter()
                .any(|pattern| northstar_roster_application::blocking::matches(pattern, sender))
        })
}

pub(super) fn muc_presence_payload(root: Node<'_, '_>, raw: &str) -> String {
    let mut payload = String::new();
    for child in root.children().filter(|node| node.is_element()) {
        let namespace = child.tag_name().namespace().unwrap_or_default();
        if is_allowed_muc_presence_payload_namespace(namespace) {
            let range = child.range();
            payload.push_str(&raw[range.start..range.end]);
        }
    }
    payload
}

pub(super) fn has_muc_join_extension(root: Node<'_, '_>) -> bool {
    root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "x"
            && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc")
    })
}

impl ProtocolSession {
    pub(crate) async fn muc_presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        let Some(user) = self.authenticated.clone() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.clone() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        if !self
            .state
            .xmpp_extension_enabled(northstar_xep_0045::XEP_ID)
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "service-unavailable",
            )));
        }
        let Some(to) = root.attribute("to") else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "jid-malformed",
            )));
        };
        let Ok(to_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "jid-malformed",
            )));
        };
        if to_jid.domainpart() != self.muc_domain() || to_jid.localpart().is_none() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "jid-malformed",
            )));
        }
        let room_jid = to_jid.bare();
        let nick = to_jid.resourcepart().unwrap_or_default();
        if !valid_muc_room(localpart(&room_jid)) || !valid_muc_nick(nick) {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "jid-malformed",
            )));
        }
        if root.attribute("type") == Some("unavailable") {
            return self
                .handle_muc_unavailable_presence(root, full_jid, room_jid)
                .await;
        }
        if root.attribute("type").is_some() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "bad-request",
            )));
        }

        // A moderator can remove an occupant from another protocol session.
        // That operation owns the shared occupant map but cannot mutate the
        // target session's private `joined_rooms` map.  Treat a local join
        // marker without its exact occupant as stale so the next presence is
        // a real rejoin (and re-evaluates outcast/members-only policy) rather
        // than returning a one-shot `not-acceptable` error.
        if let Some(joined) = self
            .joined_rooms
            .get(&room_jid)
            .map(|membership| membership.value().clone())
        {
            let stale = self.authorized_muc_occupant(&room_jid).await?.is_none();
            if stale {
                self.joined_rooms
                    .remove_if(&room_jid, |_, current| current == &joined);
            }
        }

        if let Some(joined) = self
            .joined_rooms
            .get(&room_jid)
            .map(|membership| membership.value().clone())
        {
            let joined_nick = joined.nick;
            let Some(mut occupant) = self.authorized_muc_occupant(&room_jid).await? else {
                self.joined_rooms.remove(&room_jid);
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "cancel",
                    "not-acceptable",
                )));
            };
            occupant.payload = muc_presence_payload(root, raw);
            if joined_nick == nick {
                let local_refresh_guard = if self.state.muc_pg_authority_enabled() {
                    None
                } else {
                    let Some(initial_room) = self
                        .state
                        .muc_service()
                        .local_room_snapshot(localpart(&room_jid))
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let guard = self
                        .state
                        .muc_service()
                        .lock_local_room_mutation(initial_room.id)
                        .await;
                    let Some(refreshed_room) = self
                        .state
                        .muc_service()
                        .local_room_snapshot(localpart(&room_jid))
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    if refreshed_room.room_epoch != initial_room.room_epoch {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    }
                    let Some(current) = self.state.local_muc_occupant_exact(
                        crate::services::muc::LocalMucOccupantIdentity {
                            room_jid: &room_jid,
                            nick: &joined_nick,
                            full_jid: &full_jid,
                            connection_id: self.connection_id,
                            cluster_epoch: joined.cluster_epoch,
                        },
                    ) else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    };
                    let requested_payload = occupant.payload.clone();
                    occupant = current;
                    occupant.payload = requested_payload;
                    let affiliation = self
                        .state
                        .muc_service()
                        .local_affiliation(refreshed_room.id, user.id)
                        .await?;
                    if affiliation.as_deref() == Some("outcast") {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "auth",
                            "forbidden",
                        )));
                    }
                    if refreshed_room.members_only && affiliation.is_none() {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "auth",
                            "registration-required",
                        )));
                    }
                    occupant.affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
                    occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                        "moderator"
                    } else if refreshed_room.moderated && occupant.affiliation == "none" {
                        "visitor"
                    } else {
                        "participant"
                    }
                    .to_owned();
                    occupant.room_non_anonymous = refreshed_room.non_anonymous;
                    Some(guard)
                };
                if self.state.muc_pg_authority_enabled() {
                    let Some(room) = self
                        .state
                        .muc_service()
                        .local_room_snapshot(localpart(&room_jid))
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let Some(target) = self
                        .state
                        .muc_service()
                        .local_cluster_occupancy_target(
                            room.id,
                            occupant.cluster_epoch,
                            occupant.connection_id,
                        )
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    };
                    if !self
                        .state
                        .muc_service()
                        .refresh_local_cluster_presence(
                            &target,
                            self.state.muc_cluster_node_id(),
                            &occupant.payload,
                            std::time::Duration::from_secs(90),
                        )
                        .await?
                    {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    }
                }
                occupant = if let Some(updated) = self
                    .state
                    .refresh_local_muc_presence_exact(&occupant, local_refresh_guard.is_some())
                {
                    updated
                } else if self.state.muc_pg_authority_enabled() {
                    tracing::warn!(room=%room_jid, %nick,
                        "PG-authoritative MUC presence refresh lost its exact local incarnation; reconciliation will repair the cache");
                    return Ok(Action::None);
                } else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "not-acceptable",
                    )));
                };
                drop(local_refresh_guard);
                let serializable = crate::services::muc::SerializableMucOccupant::from(&occupant);
                if self.state.muc_redis_transport_enabled() {
                    if let Ok(json) = serde_json::to_string(&serializable) {
                        let cache_result = self
                            .state
                            .register_cluster_muc_occupant(&room_jid, nick, &json)
                            .await;
                        if self.state.muc_pg_authority_enabled() {
                            if let Err(error) = cache_result {
                                tracing::warn!(?error, room=%room_jid, nick=%nick,
                                "could not refresh Redis MUC presence soft-state");
                            }
                        } else if !cache_result? {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                &full_jid,
                                "cancel",
                                "not-acceptable",
                            )));
                        }
                        self.state
                            .publish_muc_cluster_presence_with_id(
                                &room_jid,
                                &serializable,
                                false,
                                false,
                                root.attribute("id"),
                            )
                            .await?;
                    }
                }
                let resync = has_muc_join_extension(root);
                for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                    let self_presence = recipient.full_jid == full_jid;
                    if resync && self_presence {
                        continue;
                    }
                    let update = muc_presence_stanza(
                        &serializable,
                        &recipient.full_jid,
                        false,
                        self_presence,
                        false,
                        root.attribute("id"),
                        serializable.room_non_anonymous
                            || self_presence
                            || recipient.role == "moderator",
                    );
                    let _ = self.state.deliver_to_muc_occupant(&recipient, update).await;
                }
                if resync {
                    let Some(room) = self
                        .state
                        .muc_service()
                        .local_room_snapshot(localpart(&room_jid))
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let history_request = match parse_muc_history_request(root, chrono::Utc::now())
                    {
                        Ok(request) => request,
                        Err(()) => {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                &full_jid,
                                "modify",
                                "bad-request",
                            )));
                        }
                    };
                    let owner_bare = bare_jid(&full_jid);
                    let blocked_patterns = self.state.muc_service().blocked_jids(user.id).await?;
                    let mut replies = Vec::new();
                    let mut roster_nicks = std::collections::HashSet::new();
                    for (_, present) in self.state.muc_occupants_for(&room_jid) {
                        if present.cluster_epoch == occupant.cluster_epoch {
                            continue;
                        }
                        let visible_sender = format!("{room_jid}/{}", present.nick);
                        let real_sender = room.non_anonymous.then_some(present.full_jid.as_str());
                        if !muc_sender_is_blocked(
                            &blocked_patterns,
                            owner_bare,
                            &visible_sender,
                            real_sender,
                        ) && roster_nicks.insert(present.nick.clone())
                        {
                            replies.push(muc_presence_stanza(
                                &crate::services::muc::SerializableMucOccupant::from(&present),
                                &full_jid,
                                false,
                                false,
                                false,
                                None,
                                room.non_anonymous || occupant.role == "moderator",
                            ));
                        }
                    }
                    for json in self
                        .state
                        .cached_muc_cluster_occupants(&room_jid)
                        .await?
                        .into_values()
                    {
                        let Ok(present) = serde_json::from_str::<
                            crate::services::muc::SerializableMucOccupant,
                        >(&json) else {
                            continue;
                        };
                        if present.cluster_epoch == occupant.cluster_epoch {
                            continue;
                        }
                        let visible_sender = format!("{room_jid}/{}", present.nick);
                        let real_sender = room.non_anonymous.then_some(present.full_jid.as_str());
                        if !muc_sender_is_blocked(
                            &blocked_patterns,
                            owner_bare,
                            &visible_sender,
                            real_sender,
                        ) && roster_nicks.insert(present.nick.clone())
                        {
                            replies.push(muc_presence_stanza(
                                &present,
                                &full_jid,
                                false,
                                false,
                                false,
                                None,
                                room.non_anonymous || occupant.role == "moderator",
                            ));
                        }
                    }
                    replies.push(muc_presence_stanza(
                        &serializable,
                        &full_jid,
                        false,
                        true,
                        false,
                        root.attribute("id"),
                        true,
                    ));
                    let mut history = Vec::new();
                    if history_request.max_stanzas != 0 && room.logging_enabled {
                        for message in self
                            .state
                            .muc_service()
                            .local_history_since(room.id, 100, history_request.since)
                            .await?
                        {
                            let visible_sender = roxmltree::Document::parse(&message.stanza)
                                .ok()
                                .and_then(|document| {
                                    document.root_element().attribute("from").map(str::to_owned)
                                })
                                .unwrap_or_else(|| room_jid.clone());
                            if muc_sender_is_blocked(
                                &blocked_patterns,
                                owner_bare,
                                &visible_sender,
                                room.non_anonymous.then_some(message.sender_jid.as_str()),
                            ) {
                                continue;
                            }
                            let authoritative = set_muc_occupant_id(
                                &message.stanza,
                                &muc_occupant_id(&room.occupant_id_secret, &message.sender_jid),
                            );
                            let authoritative = if room.non_anonymous {
                                add_muc_sender(&authoritative, &message.sender_jid)
                            } else {
                                authoritative
                            };
                            history.push(set_to(
                                &add_delay_from(
                                    &authoritative,
                                    message.created_at,
                                    Some(&room_jid),
                                ),
                                &full_jid,
                            ));
                        }
                    }
                    replies.extend(apply_muc_history_bounds(history, history_request));
                    replies.push(current_muc_subject_stanza(&room, &room_jid, &full_jid));
                    return Ok(Action::SendMany(replies));
                }
                return Ok(Action::None);
            }

            let Some(room) = self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
            else {
                self.joined_rooms.remove(&room_jid);
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "cancel",
                    "item-not-found",
                )));
            };
            if self
                .state
                .muc_service()
                .local_nick_reserved_for_other(room.id, user.id, nick)
                .await?
            {
                return Ok(Action::Send(muc_stanza_error(
                    root, &full_jid, "cancel", "conflict",
                )));
            }

            let local_rename_guard = if self.state.muc_pg_authority_enabled() {
                None
            } else {
                Some(
                    self.state
                        .muc_service()
                        .lock_local_room_mutation(room.id)
                        .await,
                )
            };

            if local_rename_guard.is_some() {
                let requested_payload = occupant.payload.clone();
                let Some(refreshed_room) = self
                    .state
                    .muc_service()
                    .local_room_snapshot(localpart(&room_jid))
                    .await?
                else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "item-not-found",
                    )));
                };
                if refreshed_room.room_epoch != room.room_epoch {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "item-not-found",
                    )));
                }
                let Some(current) = self.validated_muc_occupant(&room_jid) else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "not-acceptable",
                    )));
                };
                occupant = current;
                occupant.payload = requested_payload;
                let affiliation = self
                    .state
                    .muc_service()
                    .local_affiliation(refreshed_room.id, user.id)
                    .await?;
                if affiliation.as_deref() == Some("outcast") {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "auth",
                        "forbidden",
                    )));
                }
                if refreshed_room.members_only && affiliation.is_none() {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "auth",
                        "registration-required",
                    )));
                }
                let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
                if occupant.affiliation != affiliation {
                    occupant.affiliation = affiliation;
                    occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                        "moderator"
                    } else if refreshed_room.moderated {
                        "visitor"
                    } else {
                        "participant"
                    }
                    .to_owned();
                }
                occupant.room_non_anonymous = refreshed_room.non_anonymous;
                if self
                    .state
                    .muc_service()
                    .local_nick_reserved_for_other(refreshed_room.id, user.id, nick)
                    .await?
                {
                    return Ok(Action::Send(muc_stanza_error(
                        root, &full_jid, "cancel", "conflict",
                    )));
                }
            }

            if !self.state.muc_pg_authority_enabled()
                && self
                    .state
                    .local_muc_occupant_by_nick(&room_jid, nick)
                    .is_some()
            {
                return Ok(Action::Send(muc_stanza_error(
                    root, &full_jid, "cancel", "conflict",
                )));
            }
            let old_occupant = occupant.clone();
            let old_serializable =
                crate::services::muc::SerializableMucOccupant::from(&old_occupant);
            occupant.nick = nick.to_owned();
            let new_serializable = crate::services::muc::SerializableMucOccupant::from(&occupant);
            let old_json = serde_json::to_string(&old_serializable)?;
            let new_json = serde_json::to_string(&new_serializable)?;
            let mut cluster_operation = None;
            if self.state.muc_pg_authority_enabled() {
                self.state.admit_muc_pg_mutation()?;
                let Some(target) = self
                    .state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        occupant.cluster_epoch,
                        occupant.connection_id,
                    )
                    .await?
                else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "not-acceptable",
                    )));
                };
                let cluster_operation_id = uuid::Uuid::new_v4();
                match self
                    .state
                    .muc_service()
                    .rename_local_cluster_occupancy(
                        cluster_operation_id,
                        &target,
                        self.state.muc_cluster_node_id(),
                        nick,
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        cluster_operation = Some(cluster_operation_id)
                    }
                    ClusterMucTransitionOutcome::Conflict => {
                        return Ok(Action::Send(muc_stanza_error(
                            root, &full_jid, "cancel", "conflict",
                        )));
                    }
                    ClusterMucTransitionOutcome::Stale
                    | ClusterMucTransitionOutcome::Destroyed
                    | ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    }
                }
                if let Err(error) = self
                    .state
                    .wake_committed_muc_operation(cluster_operation_id)
                    .await
                {
                    tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                        "MUC rename committed; signed wake failed and PostgreSQL polling will catch up");
                }
            }
            let redis_renamed = match self
                .state
                .rename_cluster_muc_occupant_exact(
                    &room_jid,
                    &joined_nick,
                    nick,
                    occupant.cluster_epoch,
                    &old_json,
                    &new_json,
                )
                .await
            {
                Ok(crate::cluster::MucRename::Renamed) => true,
                Ok(crate::cluster::MucRename::Conflict) => {
                    if cluster_operation.is_none() {
                        return Ok(Action::Send(muc_stanza_error(
                            root, &full_jid, "cancel", "conflict",
                        )));
                    }
                    tracing::warn!(%room_jid, old_nick=%joined_nick, new_nick=%nick,
                        "Redis MUC nickname cache conflicted after PostgreSQL committed; reconciliation will replace soft state");
                    false
                }
                Ok(crate::cluster::MucRename::Stale) => {
                    if cluster_operation.is_none() {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    }
                    tracing::warn!(%room_jid, old_nick=%joined_nick, new_nick=%nick,
                        "Redis MUC nickname cache was stale after PostgreSQL committed");
                    false
                }
                Err(error) => {
                    if cluster_operation.is_none() {
                        return Err(error);
                    }
                    self.state.record_muc_cluster_control_plane_failure(&error);
                    tracing::warn!(?error, %room_jid,
                        "PostgreSQL committed MUC rename; Redis wake/cache update will be reconciled");
                    false
                }
            };
            let move_outcome = self.state.move_local_muc_nickname_exact(
                crate::services::muc::LocalMucOccupantIdentity::from(&old_occupant),
                &occupant,
                cluster_operation.is_some(),
            );
            match move_outcome {
                crate::xmpp::local_routes::muc::LocalMucNicknameMove::Published
                | crate::xmpp::local_routes::muc::LocalMucNicknameMove::AlreadyPublished => {}
                crate::xmpp::local_routes::muc::LocalMucNicknameMove::DeferredToReconciliation
                    if cluster_operation.is_some() =>
                {
                    tracing::warn!(room=%room_jid, %nick,
                        "PG-authoritative MUC rename found another local incarnation; reconciliation will repair the cache");
                }
                crate::xmpp::local_routes::muc::LocalMucNicknameMove::CollisionRestored
                | crate::xmpp::local_routes::muc::LocalMucNicknameMove::CollisionRestoreFailed => {
                    if move_outcome == crate::xmpp::local_routes::muc::LocalMucNicknameMove::CollisionRestoreFailed {
                        tracing::error!(room=%room_jid, old_nick=%joined_nick,
                            "could not restore local MUC actor after nickname collision");
                    }
                    if redis_renamed {
                        let _ = self
                            .state
                            .rename_cluster_muc_occupant_exact(
                                &room_jid,
                                nick,
                                &joined_nick,
                                occupant.cluster_epoch,
                                &new_json,
                                &old_json,
                            )
                            .await;
                    }
                    return Ok(Action::Send(muc_stanza_error(
                        root, &full_jid, "cancel", "conflict",
                    )));
                }
                _ => {
                    self.joined_rooms.remove_if(&room_jid, |_, current| {
                        current.cluster_epoch == occupant.cluster_epoch
                    });
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "not-acceptable",
                    )));
                }
            }
            self.joined_rooms.insert(
                room_jid.clone(),
                northstar_session_core::JoinedMucMembership {
                    nick: nick.to_owned(),
                    cluster_epoch: occupant.cluster_epoch,
                },
            );
            drop(local_rename_guard);
            if cluster_operation.is_some() {
                return Ok(Action::None);
            }
            self.state
                .publish_muc_cluster_nickname_change(
                    &room_jid,
                    &old_serializable,
                    &new_serializable,
                    root.attribute("id"),
                )
                .await?;
            for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                let recipient_serializable =
                    crate::services::muc::SerializableMucOccupant::from(&recipient);
                let unavailable = muc_nickname_change_presence(
                    &old_serializable,
                    &recipient_serializable,
                    nick,
                    root.attribute("id"),
                );
                let _ = self
                    .state
                    .deliver_to_muc_occupant(&recipient, unavailable)
                    .await;
                let self_presence = recipient.full_jid == full_jid;
                let available = muc_presence_stanza(
                    &new_serializable,
                    &recipient.full_jid,
                    false,
                    self_presence,
                    false,
                    root.attribute("id"),
                    new_serializable.room_non_anonymous
                        || self_presence
                        || recipient.role == "moderator",
                );
                let _ = self
                    .state
                    .deliver_to_muc_occupant(&recipient, available)
                    .await;
            }
            return Ok(Action::None);
        }

        if self.joined_rooms.len() >= MAX_JOINED_ROOMS_PER_SESSION {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "wait",
                "resource-constraint",
            )));
        }
        let history_request = match parse_muc_history_request(root, chrono::Utc::now()) {
            Ok(request) => request,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "modify",
                    "bad-request",
                )));
            }
        };
        if !self.state.muc_pg_authority_enabled()
            && self
                .state
                .local_muc_occupant_by_nick(&room_jid, nick)
                .is_some()
        {
            return Ok(Action::Send(muc_stanza_error(
                root, &full_jid, "cancel", "conflict",
            )));
        }
        let (room, created) = match self
            .state
            .muc_service()
            .get_or_create_local_room(localpart(&room_jid), user.id, &full_jid)
            .await
        {
            Ok(result) => result,
            Err(error) if crate::services::muc::is_capacity_exhausted(&error) => {
                self.state.muc_telemetry().capacity_rejected();
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "wait",
                    "resource-constraint",
                )));
            }
            Err(error) => return Err(error),
        };
        if !created && room.configuration_is_expired(chrono::Utc::now()) {
            let _ = self
                .state
                .muc_service()
                .delete_expired_locked_room(room.id)
                .await?;
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "item-not-found",
            )));
        }
        if !created
            && room.is_locked()
            && !room.can_configure_locked_room(&full_jid, chrono::Utc::now())
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "item-not-found",
            )));
        }
        if created {
            let actor_bare = format!("{}@{}", user.username, self.state.local_domain());
            let _ = super::super::mix_muc::maybe_link_local_mirror(
                self.state.mix_muc_mirror_enabled(),
                self.state.mix_service(),
                self.state.local_domain(),
                &room.localpart,
                &actor_bare,
            )
            .await?;
        }
        let affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?;
        tracing::info!(
            room = %room_jid, user = %user.username, user_id = %user.id,
            room_id = %room.id, members_only = %room.members_only,
            affiliation = ?affiliation, "MUC join: affiliation check"
        );
        if affiliation.as_deref() == Some("outcast") {
            tracing::warn!(room = %room_jid, user = %user.username, "MUC join denied: user is outcast");
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "auth",
                "forbidden",
            )));
        }
        if let Some(password_hash) = room.password_hash.as_deref() {
            let supplied_password = root
                .children()
                .find(|node| {
                    node.is_element()
                        && node.tag_name().name() == "x"
                        && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc")
                })
                .and_then(|x| child_text(x, "password"))
                .unwrap_or_default();
            let password_hash = zeroize::Zeroizing::new(password_hash.to_owned());
            let supplied_password = zeroize::Zeroizing::new(supplied_password.to_owned());
            let password_valid = match northstar_security::password_work::run(move || {
                Ok(crate::services::muc::verify_room_password(
                    &password_hash,
                    &supplied_password,
                ))
            })
            .await
            {
                Ok(valid) => valid,
                Err(error) if error.is_overloaded() => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "wait",
                        "resource-constraint",
                    )));
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "room password verification task failed: {error}"
                    ));
                }
            };
            if !password_valid {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "auth",
                    "not-authorized",
                )));
            }
        }
        if room.members_only && affiliation.is_none() {
            tracing::warn!(room = %room_jid, user = %user.username, "MUC join denied: members-only and no affiliation");
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "auth",
                "registration-required",
            )));
        }
        if self
            .state
            .muc_service()
            .local_nick_reserved_for_other(room.id, user.id, nick)
            .await?
        {
            return Ok(Action::Send(muc_stanza_error(
                root, &full_jid, "cancel", "conflict",
            )));
        }
        let local_join_guard = if self.state.muc_pg_authority_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(room.id)
                    .await,
            )
        };
        let Some(refreshed_room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "item-not-found",
            )));
        };
        match refreshed_room.join_snapshot_consistency(&room) {
            Ok(()) => {}
            Err(MucJoinSnapshotError::RoomReplaced) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "cancel",
                    "item-not-found",
                )));
            }
            Err(MucJoinSnapshotError::ConfigurationChanged) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "wait",
                    "resource-constraint",
                )));
            }
        }
        let room = refreshed_room;
        if room.configuration_is_expired(chrono::Utc::now())
            || (room.is_locked() && !room.can_configure_locked_room(&full_jid, chrono::Utc::now()))
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "item-not-found",
            )));
        }
        let affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?;
        if affiliation.as_deref() == Some("outcast") {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "auth",
                "forbidden",
            )));
        }
        if room.members_only && affiliation.is_none() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "auth",
                "registration-required",
            )));
        }
        if self
            .state
            .muc_service()
            .local_nick_reserved_for_other(room.id, user.id, nick)
            .await?
        {
            return Ok(Action::Send(muc_stanza_error(
                root, &full_jid, "cancel", "conflict",
            )));
        }
        // The early check above is only a fast path. In single-node mode the
        // exact nickname and room capacity must be rechecked while holding the
        // room gate because independent client sessions join concurrently.
        if !self.state.muc_pg_authority_enabled()
            && self
                .state
                .local_muc_occupant_by_nick(&room_jid, nick)
                .is_some()
        {
            return Ok(Action::Send(muc_stanza_error(
                root, &full_jid, "cancel", "conflict",
            )));
        }
        let local_occupant_count = if self.state.muc_pg_authority_enabled() {
            0
        } else {
            self.state.muc_occupants_for(&room_jid).len()
        };
        // XEP-0045 requires a reasonable administrative reserve so a room
        // cannot be permanently locked by filling every public slot.
        let privileged_join = matches!(affiliation.as_deref(), Some("owner" | "admin"));
        let effective_capacity = room.max_occupants as usize + usize::from(privileged_join) * 10;
        if !self.state.muc_pg_authority_enabled() && local_occupant_count >= effective_capacity {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "wait",
                "service-unavailable",
            )));
        }

        let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
        let role = if matches!(affiliation.as_str(), "owner" | "admin") {
            "moderator"
        } else if room.moderated && affiliation == "none" {
            "visitor"
        } else {
            "participant"
        }
        .to_owned();

        let payload = muc_presence_payload(root, raw);

        let occupant = crate::xmpp::local_routes::muc::MucOccupant {
            full_jid: full_jid.clone(),
            room_jid: room_jid.clone(),
            nick: nick.to_owned(),
            endpoint: crate::xmpp::local_routes::muc::MucOccupantEndpoint::Local(
                self.outbound.clone(),
            ),
            affiliation,
            role,
            room_non_anonymous: room.non_anonymous,
            occupant_id: muc_occupant_id(&room.occupant_id_secret, bare_jid(&full_jid)),
            cluster_epoch: uuid::Uuid::new_v4(),
            connection_id: self.connection_id,
            sm_session_id: self.sm.db_id,
            payload,
        };
        let serializable = crate::services::muc::SerializableMucOccupant::from(&occupant);
        let mut cluster_event_id = None;
        if self.state.muc_pg_authority_enabled() {
            self.state.admit_muc_pg_mutation()?;
            // PostgreSQL authorizes the join in both runtime modes. Redis is
            // only a routing cache when multiple nodes are configured.
            let principal = ClusterMucPrincipal::Local {
                user_id: user.id,
                bare_jid: bare_jid(&full_jid).to_owned(),
            };
            let cluster_operation_id = uuid::Uuid::new_v4();
            match self
                .state
                .muc_service()
                .claim_local_cluster_occupancy(ClusterMucJoin {
                    operation_id: cluster_operation_id,
                    room_id: room.id,
                    expected_room_epoch: room.room_epoch,
                    expected_config_version: room.config_version,
                    principal,
                    full_jid: &full_jid,
                    nick,
                    owner_node_id: self.state.muc_cluster_node_id(),
                    connection_uuid: self.connection_id,
                    connection_epoch: 1,
                    sm_session_id: self.sm.db_id,
                    occupant_incarnation: occupant.cluster_epoch,
                    presence_payload: &occupant.payload,
                    lease: std::time::Duration::from_secs(90),
                })
                .await?
            {
                ClusterMucJoinOutcome::Joined(authority)
                | ClusterMucJoinOutcome::Replay(authority) => {
                    debug_assert_eq!(authority.occupant_incarnation, occupant.cluster_epoch);
                    debug_assert_eq!(authority.connection_uuid, self.connection_id);
                }
                ClusterMucJoinOutcome::Outcast => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "auth",
                        "forbidden",
                    )));
                }
                ClusterMucJoinOutcome::MembershipRequired => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "auth",
                        "registration-required",
                    )));
                }
                ClusterMucJoinOutcome::ReservedNickname
                | ClusterMucJoinOutcome::NicknameConflict
                | ClusterMucJoinOutcome::FullJidConflict => {
                    return Ok(Action::Send(muc_stanza_error(
                        root, &full_jid, "cancel", "conflict",
                    )));
                }
                ClusterMucJoinOutcome::Full => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "wait",
                        "service-unavailable",
                    )));
                }
                ClusterMucJoinOutcome::RoomMissing
                | ClusterMucJoinOutcome::RoomDestroyed
                | ClusterMucJoinOutcome::RoomLocked
                | ClusterMucJoinOutcome::StaleRoom => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "item-not-found",
                    )));
                }
            }
            cluster_event_id = Some(cluster_operation_id.to_string());
            if let Err(error) = self
                .state
                .wake_committed_muc_operation(cluster_operation_id)
                .await
            {
                tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                    "MUC join committed; signed wake failed and PostgreSQL polling will catch up");
            }
            if self.state.muc_redis_transport_enabled() {
                // The cache cannot authorize a join; PostgreSQL already did.
                let cache = self
                    .state
                    .cache_committed_muc_join(&serializable, effective_capacity)
                    .await?;
                if let Err(error) = cache.refresh {
                    tracing::warn!(?error, %room_jid,
                        "PostgreSQL committed MUC join; Redis occupancy cache refresh failed");
                }
                match cache.registration {
                    Ok(crate::cluster::MucRegistration::Joined) => {}
                    Ok(crate::cluster::MucRegistration::Conflict)
                    | Ok(crate::cluster::MucRegistration::Full) => {
                        tracing::warn!(%room_jid, %nick,
                            "Redis MUC cache disagreed with committed PostgreSQL occupancy; cache will reconcile");
                    }
                    Err(error) => tracing::warn!(?error, %room_jid,
                        "PostgreSQL committed MUC join; Redis cache update failed"),
                }
            }
        }
        // Snapshot local occupants for the joining client's initial roster.
        // The committed PostgreSQL event handles durable audience delivery.
        let local_existing = self.state.muc_occupants_for(&room_jid);
        let publication = self.state.publish_local_muc_join_if_vacant(&occupant);
        if publication != crate::xmpp::local_routes::muc::LocalMucJoinPublication::Published {
            if !self.state.muc_pg_authority_enabled() {
                return Ok(Action::Send(muc_stanza_error(
                    root, &full_jid, "cancel", "conflict",
                )));
            }
            if publication == crate::xmpp::local_routes::muc::LocalMucJoinPublication::Occupied {
                tracing::error!(%room_jid, %nick,
                    "committed MUC join found another local incarnation; preserving it and compensating this claim");
                drop(local_join_guard);
                compensate_unpublished_cluster_muc_join(&self.state, &room, &occupant).await;
                return Ok(Action::Send(muc_stanza_error(
                    root, &full_jid, "cancel", "conflict",
                )));
            }
        }
        self.joined_rooms.insert(
            room_jid.clone(),
            northstar_session_core::JoinedMucMembership {
                nick: nick.to_owned(),
                cluster_epoch: occupant.cluster_epoch,
            },
        );
        drop(local_join_guard);
        if self.state.muc_redis_transport_enabled() {
            if let Ok(json) = serde_json::to_string(&serializable) {
                let _ = self.state.join_cluster_muc_room(&room_jid).await;
                let _ = self
                    .state
                    .register_cluster_muc_occupant(&room_jid, nick, &json)
                    .await;
                if cluster_event_id.is_none() {
                    let _ = self
                        .state
                        .publish_muc_cluster_presence_with_id(
                            &room_jid,
                            &serializable,
                            false,
                            created,
                            root.attribute("id"),
                        )
                        .await;
                }
            }
        }

        let global_map = if self.state.muc_redis_transport_enabled() {
            self.state
                .cached_muc_cluster_occupants(&room_jid)
                .await
                .unwrap_or_default()
        } else {
            std::collections::HashMap::new()
        };
        let owner_bare = bare_jid(&full_jid);
        let blocked_patterns = self.state.muc_service().blocked_jids(user.id).await?;
        let mut replies = Vec::with_capacity(global_map.len() + 24);
        let mut roster_nicks = std::collections::HashSet::new();
        for (_, json_str) in global_map {
            if let Ok(present) =
                serde_json::from_str::<crate::services::muc::SerializableMucOccupant>(&json_str)
            {
                let visible_sender = format!("{room_jid}/{}", present.nick);
                let real_sender = room.non_anonymous.then_some(present.full_jid.as_str());
                if present.nick != nick
                    && !muc_sender_is_blocked(
                        &blocked_patterns,
                        owner_bare,
                        &visible_sender,
                        real_sender,
                    )
                    && roster_nicks.insert(present.nick.clone())
                {
                    replies.push(muc_presence_stanza(
                        &present,
                        &full_jid,
                        false,
                        false,
                        false,
                        None,
                        room.non_anonymous || occupant.role == "moderator",
                    ));
                }
            }
        }
        for (_, target) in &local_existing {
            let visible_sender = format!("{room_jid}/{}", target.nick);
            let real_sender = room.non_anonymous.then_some(target.full_jid.as_str());
            if !muc_sender_is_blocked(&blocked_patterns, owner_bare, &visible_sender, real_sender)
                && roster_nicks.insert(target.nick.clone())
            {
                replies.push(muc_presence_stanza(
                    &crate::services::muc::SerializableMucOccupant::from(target),
                    &full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                ));
            }
            if cluster_event_id.is_none() {
                let joined = muc_presence_stanza(
                    &serializable,
                    &target.full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || target.role == "moderator",
                );
                let _ = self.state.deliver_to_muc_occupant(target, joined).await;
            }
        }
        let mut self_join = muc_presence_stanza(
            &serializable,
            &full_jid,
            false,
            true,
            created,
            root.attribute("id").or(cluster_event_id.as_deref()),
            true,
        );
        if room.logging_enabled {
            self_join = add_muc_user_status(&self_join, 170);
        }
        replies.push(self_join);
        tracing::info!(
            room = %room_jid, user = %user.username,
            "MUC join: success"
        );

        // XEP-0045 requires initial room presence first, then all selected
        // history, and only then the current subject.  Subject-only archive
        // records remain available through MAM but are not join history.
        let mut history_stanzas = Vec::new();
        let history_candidates = if history_request.max_stanzas == 0 || !room.logging_enabled {
            Vec::new()
        } else {
            self.state
                .muc_service()
                .local_history_since(room.id, 100, history_request.since)
                .await?
        };
        for message in history_candidates {
            let visible_sender = roxmltree::Document::parse(&message.stanza)
                .ok()
                .and_then(|document| document.root_element().attribute("from").map(str::to_owned))
                .unwrap_or_else(|| room_jid.clone());
            if muc_sender_is_blocked(
                &blocked_patterns,
                owner_bare,
                &visible_sender,
                room.non_anonymous.then_some(message.sender_jid.as_str()),
            ) {
                continue;
            }
            let occupant_id = muc_occupant_id(&room.occupant_id_secret, &message.sender_jid);
            let authoritative = set_muc_occupant_id(&message.stanza, &occupant_id);
            let history = if room.non_anonymous {
                add_muc_sender(&authoritative, &message.sender_jid)
            } else {
                authoritative
            };
            history_stanzas.push(set_to(
                &add_delay_from(&history, message.created_at, Some(&room_jid)),
                &full_jid,
            ));
        }
        replies.extend(apply_muc_history_bounds(history_stanzas, history_request));
        replies.push(current_muc_subject_stanza(&room, &room_jid, &full_jid));
        Ok(Action::SendMany(replies))
    }
}
