use crate::PresenceDeliveryHost;
use anyhow::Result;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_core::{ExactPresenceRoute, PresenceAccount, RosterActor};
use northstar_stream::session_cleanup::unavailable::DirectedGrant;
use std::sync::atomic::Ordering;

/// One directed stanza and the grants already held for its address scope.
pub struct DirectedDelivery<'a> {
    pub source: &'a RosterActor,
    pub recipient: &'a PresenceAccount,
    pub scope: &'a str,
    pub stanza: &'a str,
    pub existing: &'a [DirectedGrant],
    pub free_slots: usize,
    pub track: bool,
    pub withdraw: bool,
}

#[derive(Default)]
pub struct DirectedDeliveryResult {
    pub accepted: Vec<ExactPresenceRoute>,
    pub remaining: Vec<ExactPresenceRoute>,
    pub error: Option<anyhow::Error>,
    pub at_capacity: bool,
}

impl DirectedDeliveryResult {
    fn record_attempt(
        &mut self,
        route: ExactPresenceRoute,
        result: Result<DirectedEnqueue>,
    ) -> bool {
        match result {
            Ok(DirectedEnqueue::Accepted) => {
                self.accepted.push(route);
                true
            }
            Ok(DirectedEnqueue::Gone) => false,
            Ok(DirectedEnqueue::Retry) => {
                self.remaining.push(route);
                false
            }
            Err(error) => {
                self.error.get_or_insert(error);
                if route.node_id.is_none() {
                    self.remaining.push(route);
                }
                false
            }
        }
    }
}

pub enum DirectedEnqueue {
    Accepted,
    Gone,
    Retry,
}

/// Each acceptance belongs to an exact transport. A positive receipt is
/// recorded even when a later route fails its policy read or enqueue.
pub async fn deliver_exact_directed<H: PresenceDeliveryHost>(
    host: &H,
    delivery: DirectedDelivery<'_>,
) -> DirectedDeliveryResult {
    let mut outcome = DirectedDeliveryResult::default();
    let bare = !delivery.scope.contains('/');
    let captured = delivery.withdraw && !delivery.existing.is_empty();
    let mut routes = if captured {
        delivery
            .existing
            .iter()
            .map(|grant| ExactPresenceRoute {
                account_id: grant.route.account_id,
                auth_generation: grant.route.auth_generation,
                connection_id: grant.route.connection_id,
                full_jid: grant.route.full_jid.clone(),
                node_id: grant.route.node_id.clone(),
            })
            .collect()
    } else {
        host.session_entries_for(delivery.scope)
            .into_iter()
            .filter_map(|(jid, session)| {
                (session.user_id == delivery.recipient.id
                    && session.auth_generation == delivery.recipient.auth_generation
                    && (!bare || session.available.load(Ordering::Acquire)))
                .then_some(ExactPresenceRoute {
                    account_id: session.user_id,
                    auth_generation: session.auth_generation,
                    connection_id: session.connection_id,
                    full_jid: jid,
                    node_id: None,
                })
            })
            .collect::<Vec<_>>()
    };
    if !captured {
        match host
            .capture_remote_directed_routes(delivery.scope, delivery.recipient)
            .await
        {
            Ok(remote) => routes.extend(remote),
            Err(error) => outcome.error = Some(error),
        }
    }
    routes.sort_by(|left, right| {
        (&left.node_id, &left.full_jid, left.connection_id).cmp(&(
            &right.node_id,
            &right.full_jid,
            right.connection_id,
        ))
    });
    routes.dedup();
    let mut free_slots = delivery.free_slots;
    for mut route in routes {
        if route.account_id != delivery.recipient.id
            || route.auth_generation != delivery.recipient.auth_generation
        {
            continue;
        }
        let new_grant = delivery.track
            && !delivery.existing.iter().any(|grant| {
                grant.route.connection_id == route.connection_id
                    && grant.route.full_jid == route.full_jid
                    && grant.route.account_id == route.account_id
                    && grant.route.auth_generation == route.auth_generation
            });
        if new_grant && free_slots == 0 {
            outcome.at_capacity = true;
            continue;
        }
        if captured {
            if host
                .session_entries_for(&route.full_jid)
                .into_iter()
                .any(|(_, current)| {
                    current.connection_id == route.connection_id
                        && current.user_id == route.account_id
                        && current.auth_generation == route.auth_generation
                })
            {
                route.node_id = None;
            } else if route.node_id.is_none() {
                match host
                    .capture_remote_directed_routes(&route.full_jid, delivery.recipient)
                    .await
                {
                    Ok(remote) => {
                        let Some(current) = remote
                            .into_iter()
                            .find(|current| current.connection_id == route.connection_id)
                        else {
                            continue;
                        };
                        route.node_id = current.node_id;
                    }
                    Err(error) => {
                        outcome.error.get_or_insert(error);
                        outcome.remaining.push(route);
                        continue;
                    }
                }
            }
        }
        let result = enqueue_directed(host, &delivery, &route, bare && !captured).await;
        if outcome.record_attempt(route, result) && new_grant {
            free_slots -= 1;
        }
    }
    if delivery.withdraw && !outcome.remaining.is_empty() {
        tokio::task::yield_now().await;
        for route in std::mem::take(&mut outcome.remaining) {
            let result = enqueue_directed(host, &delivery, &route, bare && !captured).await;
            outcome.record_attempt(route, result);
        }
    }
    outcome
}

async fn enqueue_directed<H: PresenceDeliveryHost>(
    host: &H,
    delivery: &DirectedDelivery<'_>,
    route: &ExactPresenceRoute,
    available_only: bool,
) -> Result<DirectedEnqueue> {
    if !host.directed_source_is_current(delivery.source) {
        return Ok(DirectedEnqueue::Gone);
    }
    if route.node_id.is_some() {
        return host
            .send_remote_directed_route(route, delivery.source, delivery.stanza, delivery.withdraw)
            .await;
    }
    let Some((_, recipient)) =
        host.session_entries_for(&route.full_jid)
            .into_iter()
            .find(|(_, session)| {
                session.user_id == route.account_id
                    && session.auth_generation == route.auth_generation
                    && session.connection_id == route.connection_id
            })
    else {
        return Ok(DirectedEnqueue::Gone);
    };
    if !host
        .privacy_allows_session(
            &recipient,
            &delivery.source.full_jid,
            PrivacyStanzaKind::PresenceIn,
        )
        .await?
    {
        return Ok(DirectedEnqueue::Gone);
    }
    if !host.directed_source_is_current(delivery.source) {
        return Ok(DirectedEnqueue::Gone);
    }
    Ok(host.enqueue_local_directed_route(route, delivery.stanza, available_only))
}

/// The node side of `RosterSessionHost::deliver_directed_presence`.
pub async fn deliver_directed_presence<H: PresenceDeliveryHost>(
    host: &H,
    to: &str,
    canonical_to: &str,
    from: &str,
    stanza: &str,
    bare_target: bool,
) -> Result<bool> {
    let mut targets = host.session_entries_for(to);
    if bare_target {
        targets.retain(|(_, target)| target.available.load(Ordering::Relaxed));
    }
    let mut delivered = false;
    for (_, target) in targets {
        if host
            .privacy_allows_session(&target, from, PrivacyStanzaKind::PresenceIn)
            .await?
            && target.sender.try_send(stanza.to_owned()).is_ok()
        {
            delivered = true;
        }
    }
    delivered |= host
        .route_directed_presence_remote(canonical_to, stanza, bare_target)
        .await;
    Ok(delivered)
}

/// The node side of `RosterSessionHost::directed_presence_recipient`.
pub fn directed_presence_recipient<H: PresenceDeliveryHost>(
    host: &H,
    owner_full: &str,
    requester: &str,
) -> bool {
    host.session_entries_for(owner_full)
        .into_iter()
        .any(|(_, owner)| {
            owner
                .directed_presence
                .iter()
                .any(|target| match DirectedGrant::decode(target.key()) {
                    Ok(Some(grant)) => {
                        host.session_entries_for(requester)
                            .into_iter()
                            .any(|(jid, current)| {
                                grant.route.full_jid == jid
                                    && grant.route.account_id == current.user_id
                                    && grant.route.auth_generation == current.auth_generation
                                    && grant.route.connection_id == current.connection_id
                            })
                    }
                    Ok(None) => {
                        northstar_xmpp_types::jid::CanonicalJid::parse(requester)
                            .is_ok_and(|jid| jid.domainpart() != host.local_domain())
                            && northstar_presence_core::directed_recipient_matches(
                                target.key(),
                                requester,
                            )
                    }
                    Err(_) => false,
                })
        })
}

#[cfg(test)]
mod tests;
