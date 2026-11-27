use super::availability::broadcast_directed_unavailable;
use super::PresenceSession;
use anyhow::Result;

mod audience;
mod initial;
mod prepared;

use self::audience::{broadcast_audience, read_broadcast_roster};
pub(crate) use self::prepared::PreparedBroadcastPresence;

#[cfg(test)]
pub(super) async fn set_last_broadcast_presence(
    gate: &crate::AvatarPresenceGate,
    _root: roxmltree::Node<'_, '_>,
    raw: &str,
    available: bool,
    from: &str,
    avatar_hash: impl std::future::Future<Output = Result<Option<String>>>,
    set_last: impl FnOnce(Option<String>),
) -> Result<String> {
    let _guard = gate.lock(from).await;
    let prepared =
        prepared::prepare(raw, available, from, async { Ok(Vec::new()) }, avatar_hash).await?;
    set_last(prepared.cached);
    Ok(prepared.wire)
}

pub(crate) async fn prepare_broadcast_presence<S: PresenceSession>(
    session: &S,
    raw: &str,
    kind: &str,
    from: &str,
) -> Result<PreparedBroadcastPresence> {
    let user = session.session_account().expect("authenticated session");
    prepared::prepare(
        raw,
        kind == "available",
        from,
        read_broadcast_roster(session, user.id),
        session.presence_service().avatar_hash(user.id),
    )
    .await
}

/// Broadcasts initial, status or unavailable presence to roster contacts, the account's other
/// resources and directed presence targets.
pub(crate) async fn broadcast_presence<S: PresenceSession>(
    session: &S,
    prepared: PreparedBroadcastPresence,
    kind: &str,
    from: &str,
    first_available: bool,
) -> Result<()> {
    let user = session.session_account().expect("authenticated session");
    let PreparedBroadcastPresence {
        roster,
        wire: rewritten,
        ..
    } = prepared;
    let account = format!("{}@{}", user.username, session.session_local_domain());
    let audience_result = broadcast_audience(
        session,
        &user,
        roster,
        &account,
        from,
        &rewritten,
        first_available,
    )
    .await;

    // RFC 6121 requires every available resource of the same account
    // to observe initial/subsequent presence. Unavailable presence is
    // also echoed to the resource that generated it.
    session
        .presence_echo_to_account(&account, from, &rewritten)
        .await;

    if kind == "unavailable" {
        broadcast_directed_unavailable(session, &rewritten, from).await;
    }

    audience_result
}

pub(super) fn should_probe_contact_on_presence(first_available: bool, subscription: &str) -> bool {
    // RFC 6121 sections 4.2.2 and 4.3.1 tie automatic contact probes to the
    // start of a presence session. A subsequent status/show update must not
    // amplify into another roster-sized wave of probes.
    northstar_presence_core::should_probe_contact_on_presence(first_available, subscription)
}
