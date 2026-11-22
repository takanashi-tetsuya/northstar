//! Existing membership checks, presence refresh and client resynchronization.

use super::*;
use std::convert::Infallible;

pub(super) enum JoinedPresence<H: MucHost> {
    NewJoin,
    Refreshed(Occupant<H>),
    NicknameChange {
        joined_nick: String,
        occupant: Occupant<H>,
    },
}

pub(super) async fn prepare_joined_presence<S: MucSession>(
    session: &S,
    request: &JoinRequest<'_, '_>,
    raw: &str,
) -> Result<JoinStep<JoinedPresence<S::Host>>> {
    let JoinRequest {
        root,
        user,
        full_jid,
        room_jid,
        nick,
    } = *request;
    // A moderator can remove an occupant from another protocol session.
    // That operation owns the shared occupant map but cannot mutate the
    // target session's private `joined_rooms` map.  Treat a local join
    // marker without its exact occupant as stale so the next presence is
    // a real rejoin (and re-evaluates outcast/members-only policy) rather
    // than returning a one-shot `not-acceptable` error.
    if let Some(joined) = session
        .joined_rooms()
        .get(room_jid)
        .map(|membership| membership.value().clone())
    {
        let stale = authorized_muc_occupant(session, room_jid).await?.is_none();
        if stale {
            session
                .joined_rooms()
                .remove_if(room_jid, |_, current| current == &joined);
        }
    }

    if let Some(joined) = session
        .joined_rooms()
        .get(room_jid)
        .map(|membership| membership.value().clone())
    {
        let joined_nick = joined.nick;
        let Some(mut occupant) = authorized_muc_occupant(session, room_jid).await? else {
            session.joined_rooms().remove(room_jid);
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "cancel",
                "not-acceptable",
            ))));
        };
        occupant.payload = muc_presence_payload(root, raw);
        if joined_nick == nick {
            let local_refresh_guard = if session.host().muc_pg_authority_enabled() {
                None
            } else {
                let Some(initial_room) = session
                    .host()
                    .muc_service()
                    .local_room_snapshot(localpart(room_jid))
                    .await?
                else {
                    return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                        root,
                        full_jid,
                        "cancel",
                        "item-not-found",
                    ))));
                };
                let guard = session
                    .host()
                    .muc_service()
                    .lock_local_room_mutation(initial_room.id)
                    .await;
                let Some(refreshed_room) = session
                    .host()
                    .muc_service()
                    .local_room_snapshot(localpart(room_jid))
                    .await?
                else {
                    return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                        root,
                        full_jid,
                        "cancel",
                        "item-not-found",
                    ))));
                };
                if refreshed_room.room_epoch != initial_room.room_epoch {
                    return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                        root,
                        full_jid,
                        "cancel",
                        "item-not-found",
                    ))));
                }
                let Some(current) = session.host().local_muc_occupant_exact(
                    northstar_room_application::muc_service::LocalMucOccupantIdentity {
                        room_jid,
                        nick: &joined_nick,
                        full_jid,
                        connection_id: session.connection_id(),
                        cluster_epoch: joined.cluster_epoch,
                    },
                ) else {
                    return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                        root,
                        full_jid,
                        "cancel",
                        "not-acceptable",
                    ))));
                };
                let requested_payload = occupant.payload.clone();
                occupant = current;
                occupant.payload = requested_payload;
                let affiliation = session
                    .host()
                    .muc_service()
                    .local_affiliation(refreshed_room.id, user.id)
                    .await?;
                if affiliation.as_deref() == Some("outcast") {
                    return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                        root,
                        full_jid,
                        "auth",
                        "forbidden",
                    ))));
                }
                if refreshed_room.members_only && affiliation.is_none() {
                    return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                        root,
                        full_jid,
                        "auth",
                        "registration-required",
                    ))));
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
            if session.host().muc_pg_authority_enabled() {
                let Some(room) = session
                    .host()
                    .muc_service()
                    .local_room_snapshot(localpart(room_jid))
                    .await?
                else {
                    return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                        root,
                        full_jid,
                        "cancel",
                        "item-not-found",
                    ))));
                };
                let Some(target) = session
                    .host()
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        occupant.cluster_epoch,
                        occupant.connection_id,
                    )
                    .await?
                else {
                    return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                        root,
                        full_jid,
                        "cancel",
                        "not-acceptable",
                    ))));
                };
                if !session
                    .host()
                    .muc_service()
                    .refresh_local_cluster_presence(
                        &target,
                        session.host().muc_cluster_node_id(),
                        &occupant.payload,
                        std::time::Duration::from_secs(90),
                    )
                    .await?
                {
                    return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                        root,
                        full_jid,
                        "cancel",
                        "not-acceptable",
                    ))));
                }
            }
            occupant = if let Some(updated) = session
                .host()
                .refresh_local_muc_presence_exact(&occupant, local_refresh_guard.is_some())
            {
                updated
            } else if session.host().muc_pg_authority_enabled() {
                tracing::warn!(room=%room_jid, %nick,
                        "PG-authoritative MUC presence refresh lost its exact local incarnation; reconciliation will repair the cache");
                return Ok(JoinStep::Done(MucAction::None));
            } else {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "cancel",
                    "not-acceptable",
                ))));
            };
            drop(local_refresh_guard);
            return Ok(JoinStep::Next(JoinedPresence::Refreshed(occupant)));
        }

        return Ok(JoinStep::Next(JoinedPresence::NicknameChange {
            joined_nick,
            occupant,
        }));
    }

    Ok(JoinStep::Next(JoinedPresence::NewJoin))
}

pub(super) async fn broadcast_presence_refresh<S: MucSession>(
    session: &S,
    request: &JoinRequest<'_, '_>,
    occupant: &Occupant<S::Host>,
) -> Result<JoinStep<Infallible>> {
    let JoinRequest {
        root,
        user,
        full_jid,
        room_jid,
        nick,
    } = *request;
    let serializable =
        northstar_room_application::muc_service::SerializableMucOccupant::from(occupant);
    if session.host().muc_redis_transport_enabled() {
        if let Ok(json) = serde_json::to_string(&serializable) {
            let cache_result = session
                .host()
                .register_cluster_muc_occupant(room_jid, nick, &json)
                .await;
            if session.host().muc_pg_authority_enabled() {
                if let Err(error) = cache_result {
                    tracing::warn!(?error, room=%room_jid, nick=%nick,
                        "could not refresh Redis MUC presence soft-state");
                }
            } else if !cache_result? {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "cancel",
                    "not-acceptable",
                ))));
            }
            session
                .host()
                .publish_muc_cluster_presence_with_id(
                    room_jid,
                    &serializable,
                    false,
                    false,
                    root.attribute("id"),
                )
                .await?;
        }
    }
    let resync = has_muc_join_extension(root);
    for (_, recipient) in session.host().muc_occupants_for(room_jid) {
        let self_presence = recipient.full_jid == *full_jid;
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
            serializable.room_non_anonymous || self_presence || recipient.role == "moderator",
        );
        let _ = session
            .host()
            .deliver_to_muc_occupant(&recipient, update)
            .await;
    }
    if resync {
        let Some(room) = session
            .host()
            .muc_service()
            .local_room_snapshot(localpart(room_jid))
            .await?
        else {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "cancel",
                "item-not-found",
            ))));
        };
        let history_request = match parse_muc_history_request(root, northstar_time::Utc::now()) {
            Ok(request) => request,
            Err(MalformedMucStanza) => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "modify",
                    "bad-request",
                ))));
            }
        };
        let owner_bare = bare_jid(full_jid);
        let blocked_patterns = session.host().muc_service().blocked_jids(user.id).await?;
        let mut replies = Vec::new();
        let mut roster_nicks = std::collections::HashSet::new();
        for (_, present) in session.host().muc_occupants_for(room_jid) {
            if present.cluster_epoch == occupant.cluster_epoch {
                continue;
            }
            let visible_sender = format!("{room_jid}/{}", present.nick);
            let real_sender = room.non_anonymous.then_some(present.full_jid.as_str());
            if !muc_sender_is_blocked(&blocked_patterns, owner_bare, &visible_sender, real_sender)
                && roster_nicks.insert(present.nick.clone())
            {
                replies.push(muc_presence_stanza(
                    &northstar_room_application::muc_service::SerializableMucOccupant::from(
                        &present,
                    ),
                    full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                ));
            }
        }
        for json in session
            .host()
            .cached_muc_cluster_occupants(room_jid)
            .await?
            .into_values()
        {
            let Ok(present) = serde_json::from_str::<
                northstar_room_application::muc_service::SerializableMucOccupant,
            >(&json) else {
                continue;
            };
            if present.cluster_epoch == occupant.cluster_epoch {
                continue;
            }
            let visible_sender = format!("{room_jid}/{}", present.nick);
            let real_sender = room.non_anonymous.then_some(present.full_jid.as_str());
            if !muc_sender_is_blocked(&blocked_patterns, owner_bare, &visible_sender, real_sender)
                && roster_nicks.insert(present.nick.clone())
            {
                replies.push(muc_presence_stanza(
                    &present,
                    full_jid,
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
            full_jid,
            false,
            true,
            false,
            root.attribute("id"),
            true,
        ));
        let mut history = Vec::new();
        if history_request.max_stanzas != 0 && room.logging_enabled {
            for message in session
                .host()
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
                    &add_delay_from(&authoritative, message.created_at, Some(room_jid)),
                    full_jid,
                ));
            }
        }
        replies.extend(apply_muc_history_bounds(history, history_request));
        replies.push(current_muc_subject_stanza(&room, room_jid, full_jid));
        return Ok(JoinStep::Done(MucAction::SendMany(replies)));
    }
    Ok(JoinStep::Done(MucAction::None))
}
