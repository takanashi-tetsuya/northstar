//! Room presence entry point: joins, nickname and status changes.

mod admission;
mod commit;
mod nickname;
mod publish;
mod rejoin;
mod validate;

use self::admission::PreparedJoin;
use self::commit::CommittedJoin;
use self::nickname::PreparedNicknameChange;
use self::rejoin::JoinedPresence;
use self::validate::JoinAddress;
use super::*;

enum JoinStep<T> {
    Next(T),
    Done(MucAction),
}

struct JoinRequest<'a, 'input> {
    root: Node<'a, 'input>,
    user: &'a MucSessionUser<'a>,
    full_jid: &'a String,
    room_jid: &'a String,
    nick: &'a str,
}

// Keep the live-session admission bound equal to the durable XEP-0198
// snapshot bound in the durable SM service. Rejecting the 257th room at join time is safer
// than discovering at disconnect that the session can no longer be resumed.
pub const MAX_JOINED_ROOMS_PER_SESSION: usize = 256;

pub fn muc_sender_is_blocked(
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
                .any(|pattern| northstar_xmpp_types::jid_scope_matches(pattern, sender))
        })
}

pub fn muc_presence_payload(root: Node<'_, '_>, raw: &str) -> String {
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

pub fn has_muc_join_extension(root: Node<'_, '_>) -> bool {
    root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "x"
            && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc")
    })
}

pub async fn muc_presence(
    session: &impl MucSession,
    root: Node<'_, '_>,
    raw: &str,
) -> Result<MucAction> {
    let JoinAddress {
        user,
        full_jid,
        to_jid,
        room_jid,
    } = match validate::validate_address(session, root) {
        JoinStep::Next(address) => address,
        JoinStep::Done(action) => return Ok(action),
    };
    let (full_jid, room_jid, nick) =
        match validate::validate_presence(session, root, full_jid, &to_jid, room_jid).await? {
            JoinStep::Next(presence) => presence,
            JoinStep::Done(action) => return Ok(action),
        };
    let request = JoinRequest {
        root,
        user: &user,
        full_jid: &full_jid,
        room_jid: &room_jid,
        nick,
    };

    let joined_presence = match rejoin::prepare_joined_presence(session, &request, raw).await? {
        JoinStep::Next(joined_presence) => joined_presence,
        JoinStep::Done(action) => return Ok(action),
    };
    match joined_presence {
        JoinedPresence::NewJoin => {}
        JoinedPresence::Refreshed(occupant) => {
            match rejoin::broadcast_presence_refresh(session, &request, &occupant).await? {
                JoinStep::Done(action) => return Ok(action),
                JoinStep::Next(never) => match never {},
            }
        }
        JoinedPresence::NicknameChange {
            joined_nick,
            mut occupant,
        } => {
            let PreparedNicknameChange {
                room,
                local_rename_guard,
            } = match nickname::prepare_nickname_change(session, &request, &mut occupant).await? {
                JoinStep::Next(prepared) => prepared,
                JoinStep::Done(action) => return Ok(action),
            };
            match nickname::apply_nickname_change(
                session,
                &request,
                &room,
                &mut occupant,
                &joined_nick,
                local_rename_guard,
            )
            .await?
            {
                JoinStep::Done(action) => return Ok(action),
                JoinStep::Next(never) => match never {},
            }
        }
    }

    let (room, created, history_request) =
        match admission::check_join_admission(session, &request).await? {
            JoinStep::Next(admission) => admission,
            JoinStep::Done(action) => return Ok(action),
        };
    let PreparedJoin {
        room,
        affiliation,
        role,
        effective_capacity,
        local_join_guard,
    } = match admission::recheck_join_admission(session, &request, &room).await? {
        JoinStep::Next(admission) => admission,
        JoinStep::Done(action) => return Ok(action),
    };

    let committed = match commit::commit_join(
        session,
        &request,
        raw,
        &room,
        affiliation,
        role,
        effective_capacity,
    )
    .await?
    {
        JoinStep::Next(committed) => committed,
        JoinStep::Done(action) => return Ok(action),
    };

    match publish::publish_join(
        session,
        &request,
        &room,
        &committed,
        created,
        local_join_guard,
        history_request,
    )
    .await?
    {
        JoinStep::Done(action) => Ok(action),
        JoinStep::Next(never) => match never {},
    }
}
