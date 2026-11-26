use super::availability::broadcast_directed_unavailable;
use super::avatar::project_avatar_presence;
use super::{inject_vcard_avatar_hash, PresenceSession};
use crate::AvatarPresenceGate;
use anyhow::Result;
use northstar_xml_builder::rewrite::set_from;
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;
use std::future::Future;

mod audience;
mod initial;

use self::audience::{broadcast_audience, read_broadcast_roster};

pub(super) async fn set_last_broadcast_presence(
    gate: &AvatarPresenceGate,
    root: Node<'_, '_>,
    raw: &str,
    available: bool,
    from: &str,
    avatar_hash: impl Future<Output = Result<Option<String>>>,
    set_last: impl FnOnce(Option<String>),
) -> Result<String> {
    project_avatar_presence(gate, bare_jid(from), avatar_hash, |hash| {
        let injected = if available {
            inject_vcard_avatar_hash(raw, root, hash)
        } else {
            raw.to_owned()
        };
        let rewritten = set_from(&injected, from);
        set_last(available.then(|| rewritten.clone()));
        rewritten
    })
    .await
}

/// Broadcasts initial, status or unavailable presence to roster contacts, the account's other
/// resources and directed presence targets.
pub async fn broadcast_presence<S: PresenceSession>(
    session: &S,
    root: Node<'_, '_>,
    raw: &str,
    kind: &str,
    from: &str,
    first_available: bool,
) -> Result<()> {
    let user = session.session_account().expect("authenticated session");
    let roster = read_broadcast_roster(session, user.id).await?;
    let available = kind == "available";
    let rewritten = set_last_broadcast_presence(
        session.avatar_presence_gate(),
        root,
        raw,
        available,
        from,
        async {
            if available {
                session.presence_service().avatar_hash(user.id).await
            } else {
                Ok(None)
            }
        },
        |presence| session.presence_set_last(presence),
    )
    .await?;
    let account = format!("{}@{}", user.username, session.session_local_domain());
    broadcast_audience(
        session,
        &user,
        roster,
        &account,
        from,
        &rewritten,
        first_available,
    )
    .await?;

    // RFC 6121 requires every available resource of the same account
    // to observe initial/subsequent presence. Unavailable presence is
    // also echoed to the resource that generated it.
    session
        .presence_echo_to_account(&account, from, &rewritten)
        .await;

    if kind == "unavailable" {
        broadcast_directed_unavailable(session, &rewritten, from).await;
    }

    Ok(())
}

pub(super) fn should_probe_contact_on_presence(first_available: bool, subscription: &str) -> bool {
    // RFC 6121 sections 4.2.2 and 4.3.1 tie automatic contact probes to the
    // start of a presence session. A subsequent status/show update must not
    // amplify into another roster-sized wave of probes.
    northstar_presence_core::should_probe_contact_on_presence(first_available, subscription)
}
