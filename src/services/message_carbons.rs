//! Post-accept XEP-0280 fanout. The transport port owns live session and
//! cluster access; this service owns target selection, privacy and deadlines.

use crate::services::privacy::PrivacyStanzaKind;
use anyhow::Result;
use futures::{stream::FuturesUnordered, StreamExt};
use std::{future::Future, pin::Pin, time::Duration};

const FANOUT_CONCURRENCY: usize = 8;
const TARGET_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Attempt {
    Delivered,
    Skipped,
    Failed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Summary {
    delivered: usize,
    failed: usize,
    timed_out: usize,
    timed_out_targets: Vec<String>,
}

type AttemptFuture<'a> = Pin<Box<dyn Future<Output = Attempt> + Send + 'a>>;

pub(crate) trait CarbonDeliveryPort {
    type Session: Send + Sync;

    fn enabled(&self) -> bool;
    fn sessions(&self, bare: &str) -> Vec<(String, Self::Session)>;
    fn carbon_enabled(&self, session: &Self::Session) -> bool;
    fn in_muc_scope(&self, session: &Self::Session, room: &str, nick: &str) -> bool;
    fn wrap(&self, direction: Direction, from: &str, to: &str, forwarded: &str) -> Option<String>;
    fn privacy_allows(
        &self,
        session: &Self::Session,
        peer: &str,
        kind: PrivacyStanzaKind,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn enqueue(&self, session: &Self::Session, stanza: String)
        -> impl Future<Output = bool> + Send;
    fn route_sent_remote(
        &self,
        bare: &str,
        forwarded: &str,
        current: &str,
        delivered_self: Option<&str>,
        muc_scope: Option<(&str, &str)>,
    ) -> impl Future<Output = ()> + Send;
    fn route_received_remote(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) -> impl Future<Output = ()> + Send;
    fn delivery_failed(&self);
    fn target_timed_out(&self);
}

async fn timed_attempt(
    target: String,
    attempt: AttemptFuture<'_>,
    timeout: Duration,
) -> (String, Result<Attempt, tokio::time::error::Elapsed>) {
    (target, tokio::time::timeout(timeout, attempt).await)
}

async fn bounded_fanout(
    attempts: Vec<(String, AttemptFuture<'_>)>,
    concurrency: usize,
    timeout: Duration,
) -> Summary {
    let mut pending = attempts.into_iter();
    let mut in_flight = FuturesUnordered::new();
    for (target, attempt) in pending
        .by_ref()
        .take(concurrency.clamp(1, FANOUT_CONCURRENCY))
    {
        in_flight.push(timed_attempt(target, attempt, timeout));
    }
    let mut summary = Summary::default();
    while let Some((target, result)) = in_flight.next().await {
        match result {
            Ok(Attempt::Delivered) => summary.delivered += 1,
            Ok(Attempt::Skipped) => {}
            Ok(Attempt::Failed) => summary.failed += 1,
            Err(_) => {
                summary.failed += 1;
                summary.timed_out += 1;
                summary.timed_out_targets.push(target);
            }
        }
        if let Some((target, attempt)) = pending.next() {
            in_flight.push(timed_attempt(target, attempt, timeout));
        }
    }
    summary
}

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Sent,
    Received,
}

impl Direction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }

    fn peer(self, forwarded: &str) -> Option<String> {
        match self {
            Self::Sent => northstar_xep_0280::forwarded_recipient(forwarded),
            Self::Received => northstar_xep_0280::forwarded_sender(forwarded),
        }
    }
}

async fn local_fanout<P: CarbonDeliveryPort + Sync>(
    port: &P,
    bare: &str,
    forwarded: &str,
    direction: Direction,
    peer: &str,
    excluded: &[Option<&str>],
    muc_scope: Option<(&str, &str)>,
) {
    let sessions = port.sessions(bare);
    let session_resources = sessions.len();
    let mut selected_resources = 0_usize;
    let attempts: Vec<(String, AttemptFuture<'_>)> = sessions
        .into_iter()
        .filter_map(|(jid, session)| {
            if !northstar_xep_0280::resource_selected(&jid, port.carbon_enabled(&session), excluded) {
                return None;
            }
            selected_resources += 1;
            if muc_scope.is_some_and(|(room, nick)| !port.in_muc_scope(&session, room, nick)) {
                return None;
            }
            let timeout_target = jid.clone();
            Some((timeout_target, Box::pin(async move {
                match port.privacy_allows(&session, peer, PrivacyStanzaKind::Message).await {
                    Ok(true) => {}
                    Ok(false) => return Attempt::Skipped,
                    Err(error) => {
                        tracing::warn!(?error, target_jid = %jid, direction = direction.as_str(), "privacy policy failed closed for a local Carbon");
                        return Attempt::Skipped;
                    }
                }
                let Some(carbon) = port.wrap(direction, bare, &jid, forwarded) else {
                    port.delivery_failed();
                    tracing::error!(target_jid = %jid, direction = direction.as_str(), "suppressed an invalid XEP-0280 Carbon payload");
                    return Attempt::Failed;
                };
                if port.enqueue(&session, carbon).await {
                    tracing::trace!(target_jid = %jid, %peer, direction = direction.as_str(), "delivered a local XEP-0280 Carbon");
                    Attempt::Delivered
                } else {
                    port.delivery_failed();
                    tracing::warn!(target_jid = %jid, direction = direction.as_str(), "post-accept Carbon could not be admitted to the local session queue");
                    Attempt::Failed
                }
            }) as AttemptFuture<'_>))
        })
        .collect();
    let summary = bounded_fanout(attempts, FANOUT_CONCURRENCY, TARGET_TIMEOUT).await;
    for target_jid in &summary.timed_out_targets {
        port.delivery_failed();
        port.target_timed_out();
        tracing::warn!(%target_jid, direction = direction.as_str(), "post-accept Carbon target exceeded its independent fanout deadline");
    }
    tracing::debug!(
        %bare,
        session_resources,
        selected_resources,
        delivered_resources = summary.delivered,
        failed_resources = summary.failed,
        timed_out_resources = summary.timed_out,
        direction = direction.as_str(),
        "completed local XEP-0280 Carbon fanout"
    );
}

pub(crate) async fn send_sent_carbons<P: CarbonDeliveryPort + Sync>(
    port: &P,
    from: &str,
    forwarded: &str,
    delivered_self: Option<&str>,
    muc_scope: Option<(&str, &str)>,
) {
    if !port.enabled() {
        return;
    }
    let current = crate::jid::canonical_session_key(from).unwrap_or_else(|_| from.to_owned());
    let bare = from.split('/').next().unwrap_or(from);
    // Invalid forwarded stanzas must not reach local or remote resources.
    let Some(peer) = Direction::Sent.peer(forwarded) else {
        tracing::warn!(%bare, direction = "sent", "suppressed a Carbon whose forwarded recipient was not a canonical JID");
        return;
    };
    local_fanout(
        port,
        bare,
        forwarded,
        Direction::Sent,
        &peer,
        &[Some(&current), delivered_self],
        muc_scope,
    )
    .await;
    port.route_sent_remote(bare, forwarded, &current, delivered_self, muc_scope)
        .await;
}

pub(crate) async fn send_received_carbons<P: CarbonDeliveryPort + Sync>(
    port: &P,
    recipient: &str,
    delivered: Option<&str>,
    forwarded: &str,
) {
    if !port.enabled() {
        return;
    }
    let Some(peer) = Direction::Received.peer(forwarded) else {
        tracing::warn!(%recipient, direction = "received", "suppressed a Carbon whose forwarded sender was not a canonical JID");
        return;
    };
    local_fanout(
        port,
        recipient,
        forwarded,
        Direction::Received,
        &peer,
        &[delivered],
        None,
    )
    .await;
    port.route_received_remote(recipient, delivered, forwarded)
        .await;
}

#[cfg(test)]
#[path = "message_carbons_tests.rs"]
mod tests;
