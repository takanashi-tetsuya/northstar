use super::availability::broadcast_directed_unavailable;
use super::PresenceSession;
use crate::exact_presence::{ExactPresenceHost, PresenceEffect};
use anyhow::Result;
use northstar_roster_application::probe_decision::{BroadcastFacts, PresenceRoute};
use northstar_roster_core::{ExactPresenceRoute, RosterActor};

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
    let prepared = prepared::prepare(raw, available, from, async { Ok(()) }, avatar_hash).await?;
    set_last(prepared.cached);
    Ok(prepared.wire)
}

/// Samples the broadcast audience and projects the avatar before the presence is committed.
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
        capture_broadcast_audience(session),
        session.presence_service().avatar_hash(user.id),
    )
    .await
}

pub(crate) struct BroadcastAudience {
    actor: RosterActor,
    roster: Vec<BroadcastFacts>,
    siblings: Vec<PresenceRoute>,
}

async fn capture_broadcast_audience<S: PresenceSession>(session: &S) -> Result<BroadcastAudience> {
    let user = session.session_account().expect("authenticated session");
    let actor = session
        .roster_actor()
        .ok_or_else(|| anyhow::anyhow!("broadcast presence requires a bound actor"))?;
    let roster = read_broadcast_roster(session, &actor).await?;
    let host = session.exact_presence_host();
    let mut siblings = host
        .capture_presence_routes(actor.bare_jid(), &user, true)
        .await?;
    if !siblings
        .iter()
        .any(|route| route.exact.connection_id == actor.connection_id)
    {
        siblings.push(PresenceRoute {
            exact: ExactPresenceRoute {
                account_id: actor.account_id,
                auth_generation: actor.auth_generation,
                connection_id: actor.connection_id,
                full_jid: actor.full_jid.clone(),
                node_id: None,
            },
            active_list: session.privacy_active_list(),
        });
    }
    Ok(BroadcastAudience {
        actor,
        roster,
        siblings,
    })
}

/// Broadcasts the committed presence to the sampled roster, the account's sibling routes and
/// directed presence targets.
pub(crate) async fn broadcast_presence<S: PresenceSession>(
    session: &S,
    prepared: PreparedBroadcastPresence,
    kind: &str,
    from: &str,
    first_available: bool,
) -> Result<()> {
    let PreparedBroadcastPresence {
        audience:
            BroadcastAudience {
                actor,
                roster,
                siblings,
            },
        wire: rewritten,
        ..
    } = prepared;
    let host = session.exact_presence_host();
    let effect = PresenceEffect::Broadcast {
        source_epoch: session.presence_broadcast_epoch(),
    };
    let audience_result = broadcast_audience(
        session,
        &actor,
        roster,
        &rewritten,
        first_available,
        &siblings,
        effect,
    )
    .await;

    // RFC 6121 requires every available resource of the same account
    // to observe initial/subsequent presence. Unavailable presence is
    // also echoed to the resource that generated it.
    for sibling in siblings {
        let self_echo = sibling.exact.connection_id == actor.connection_id;
        let to = if sibling.exact.node_id.is_some() {
            actor.bare_jid()
        } else {
            &sibling.exact.full_jid
        };
        let delivery = northstar_xml_builder::rewrite::set_to(&rewritten, to);
        if let Err(error) = host
            .send_presence_route(&actor, &sibling, &delivery, effect, !self_echo)
            .await
        {
            tracing::warn!(?error, target = %sibling.exact.full_jid, "sibling presence delivery failed");
        }
    }

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
