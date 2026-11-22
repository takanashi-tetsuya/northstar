//! Preflight admission and the room consistency recheck before a new join.

use super::*;
use tokio::sync::OwnedMutexGuard;

pub(super) struct PreparedJoin {
    pub(super) room: MucRoom,
    pub(super) affiliation: String,
    pub(super) role: String,
    pub(super) effective_capacity: usize,
    pub(super) local_join_guard: Option<OwnedMutexGuard<()>>,
}

pub(super) async fn check_join_admission<S: MucSession>(
    session: &S,
    request: &JoinRequest<'_, '_>,
) -> Result<JoinStep<(MucRoom, bool, MucHistoryRequest)>> {
    let JoinRequest {
        root,
        user,
        full_jid,
        room_jid,
        nick,
    } = *request;
    if session.joined_rooms().len() >= MAX_JOINED_ROOMS_PER_SESSION {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "wait",
            "resource-constraint",
        ))));
    }
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
    if !session.host().muc_pg_authority_enabled()
        && session
            .host()
            .local_muc_occupant_by_nick(room_jid, nick)
            .is_some()
    {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root, full_jid, "cancel", "conflict",
        ))));
    }
    let (room, created) = match session
        .host()
        .muc_service()
        .get_or_create_local_room(localpart(room_jid), user.id, full_jid)
        .await
    {
        Ok(result) => result,
        Err(error) if northstar_room_application::muc_service::is_capacity_exhausted(&error) => {
            session.host().muc_telemetry().capacity_rejected();
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "wait",
                "resource-constraint",
            ))));
        }
        Err(error) => return Err(error),
    };
    if !created && room.configuration_is_expired(northstar_time::Utc::now()) {
        let _ = session
            .host()
            .muc_service()
            .delete_expired_locked_room(room.id)
            .await?;
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "cancel",
            "item-not-found",
        ))));
    }
    if !created
        && room.is_locked()
        && !room.can_configure_locked_room(full_jid, northstar_time::Utc::now())
    {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "cancel",
            "item-not-found",
        ))));
    }
    if created {
        let actor_bare = format!("{}@{}", user.username, session.host().local_domain());
        let _ = northstar_room_application::mix_muc::maybe_link_local_mirror(
            session.host().mix_muc_mirror_enabled(),
            session.host().mix_service(),
            session.host().local_domain(),
            &room.localpart,
            &actor_bare,
        )
        .await?;
    }
    let affiliation = session
        .host()
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
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "auth",
            "forbidden",
        ))));
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
            Ok(
                northstar_room_application::muc_service::verify_room_password(
                    &password_hash,
                    &supplied_password,
                ),
            )
        })
        .await
        {
            Ok(valid) => valid,
            Err(error) if error.is_overloaded() => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "wait",
                    "resource-constraint",
                ))));
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "room password verification task failed: {error}"
                ));
            }
        };
        if !password_valid {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "auth",
                "not-authorized",
            ))));
        }
    }
    if room.members_only && affiliation.is_none() {
        tracing::warn!(room = %room_jid, user = %user.username, "MUC join denied: members-only and no affiliation");
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "auth",
            "registration-required",
        ))));
    }
    if session
        .host()
        .muc_service()
        .local_nick_reserved_for_other(room.id, user.id, nick)
        .await?
    {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root, full_jid, "cancel", "conflict",
        ))));
    }
    Ok(JoinStep::Next((room, created, history_request)))
}

pub(super) async fn recheck_join_admission<S: MucSession>(
    session: &S,
    request: &JoinRequest<'_, '_>,
    room: &MucRoom,
) -> Result<JoinStep<PreparedJoin>> {
    let JoinRequest {
        root,
        user,
        full_jid,
        room_jid,
        nick,
    } = *request;
    let local_join_guard = if session.host().muc_pg_authority_enabled() {
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
    match refreshed_room.join_snapshot_consistency(room) {
        Ok(()) => {}
        Err(MucJoinSnapshotError::RoomReplaced) => {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "cancel",
                "item-not-found",
            ))));
        }
        Err(MucJoinSnapshotError::ConfigurationChanged) => {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "wait",
                "resource-constraint",
            ))));
        }
    }
    let room = refreshed_room;
    if room.configuration_is_expired(northstar_time::Utc::now())
        || (room.is_locked()
            && !room.can_configure_locked_room(full_jid, northstar_time::Utc::now()))
    {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "cancel",
            "item-not-found",
        ))));
    }
    let affiliation = session
        .host()
        .muc_service()
        .local_affiliation(room.id, user.id)
        .await?;
    if affiliation.as_deref() == Some("outcast") {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "auth",
            "forbidden",
        ))));
    }
    if room.members_only && affiliation.is_none() {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "auth",
            "registration-required",
        ))));
    }
    if session
        .host()
        .muc_service()
        .local_nick_reserved_for_other(room.id, user.id, nick)
        .await?
    {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root, full_jid, "cancel", "conflict",
        ))));
    }
    // The early check above is only a fast path. In single-node mode the
    // exact nickname and room capacity must be rechecked while holding the
    // room gate because independent client sessions join concurrently.
    if !session.host().muc_pg_authority_enabled()
        && session
            .host()
            .local_muc_occupant_by_nick(room_jid, nick)
            .is_some()
    {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root, full_jid, "cancel", "conflict",
        ))));
    }
    let local_occupant_count = if session.host().muc_pg_authority_enabled() {
        0
    } else {
        session.host().muc_occupants_for(room_jid).len()
    };
    // XEP-0045 requires a reasonable administrative reserve so a room
    // cannot be permanently locked by filling every public slot.
    let privileged_join = matches!(affiliation.as_deref(), Some("owner" | "admin"));
    let effective_capacity = room.max_occupants as usize + usize::from(privileged_join) * 10;
    if !session.host().muc_pg_authority_enabled() && local_occupant_count >= effective_capacity {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "wait",
            "service-unavailable",
        ))));
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
    Ok(JoinStep::Next(PreparedJoin {
        room,
        affiliation,
        role,
        effective_capacity,
        local_join_guard,
    }))
}
