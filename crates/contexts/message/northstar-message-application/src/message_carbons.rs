//! Post-accept XEP-0280 fanout. The transport port owns live session and
//! cluster access; this service owns target selection, privacy and deadlines.

use crate::messaging::ExactMessageRoute;
use anyhow::Result;
use futures::{stream::FuturesUnordered, StreamExt};
use northstar_xep_0016::PrivacyStanzaKind;
use std::{future::Future, pin::Pin, time::Duration};
use uuid::Uuid;

mod policy;

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

pub trait CarbonDeliveryPort {
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
        _bare: &str,
        _forwarded: &str,
        _current: &str,
        _delivered_self: Option<&str>,
        _muc_scope: Option<(&str, &str)>,
    ) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }
    fn route_received_remote(
        &self,
        _recipient: &str,
        _delivered: Option<&str>,
        _forwarded: &str,
    ) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }
    fn delivery_failed(&self);
    fn target_timed_out(&self);

    fn local_route(&self, _jid: &str, _session: &Self::Session) -> Option<ExactMessageRoute> {
        None
    }

    fn capture_remote(
        &self,
        _bare: &str,
        _account_id: Option<Uuid>,
        _exclusions: CarbonExclusions<'_>,
        _muc_scope: Option<(&str, &str)>,
    ) -> impl Future<Output = Vec<ExactMessageRoute>> + Send {
        std::future::ready(Vec::new())
    }

    fn route_captured_remote(
        &self,
        request: CarbonFanout<'_>,
        _routes: &[ExactMessageRoute],
    ) -> impl Future<Output = ()> + Send
    where
        Self: Sync,
    {
        async move {
            match request.direction {
                Direction::Sent => {
                    self.route_sent_remote(
                        request.bare,
                        request.forwarded,
                        request
                            .exclusions
                            .origin
                            .map(CarbonExclusion::jid)
                            .unwrap_or_default(),
                        request.exclusions.primary.map(CarbonExclusion::jid),
                        request.muc_scope,
                    )
                    .await
                }
                Direction::Received => {
                    self.route_received_remote(
                        request.bare,
                        request.exclusions.primary.map(CarbonExclusion::jid),
                        request.forwarded,
                    )
                    .await
                }
            }
        }
    }

    fn enqueue_captured(
        &self,
        route: Option<&ExactMessageRoute>,
        session: &Self::Session,
        stanza: String,
        request: CarbonFanout<'_>,
        peer: &str,
    ) -> impl Future<Output = Result<bool>> + Send
    where
        Self: Sync,
    {
        async move {
            match self.policy_allows(request.bare, session, peer).await {
                Ok(true) => {}
                Ok(false) => return Ok(false),
                Err(error) => {
                    tracing::warn!(?error, %peer, "privacy policy failed closed for a local Carbon");
                    return Ok(false);
                }
            }
            if !self.carbon_enabled(session)
                || request
                    .muc_scope
                    .is_some_and(|(room, nick)| !self.in_muc_scope(session, room, nick))
                || route.is_some_and(|route| {
                    !self
                        .sessions(request.bare)
                        .into_iter()
                        .any(|(jid, current)| {
                            jid == route.full_jid
                                && self.local_route(&jid, &current).as_ref() == Some(route)
                        })
                })
            {
                return Ok(false);
            }
            anyhow::ensure!(self.enqueue(session, stanza).await, "Carbon queue closed");
            Ok(true)
        }
    }

    fn policy_allows(
        &self,
        _bare: &str,
        session: &Self::Session,
        peer: &str,
    ) -> impl Future<Output = Result<bool>> + Send {
        self.privacy_allows(session, peer, PrivacyStanzaKind::Message)
    }
}

#[derive(Clone, Copy)]
pub enum CarbonExclusion<'a> {
    FullJid(&'a str),
    Exact(&'a ExactMessageRoute),
}

impl<'a> CarbonExclusion<'a> {
    fn jid(self) -> &'a str {
        match self {
            Self::FullJid(jid) => jid,
            Self::Exact(route) => &route.full_jid,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct CarbonExclusions<'a> {
    pub origin: Option<CarbonExclusion<'a>>,
    pub primary: Option<CarbonExclusion<'a>>,
}

impl CarbonExclusions<'_> {
    pub fn excludes(self, jid: &str, route: Option<&ExactMessageRoute>) -> bool {
        [self.origin, self.primary]
            .into_iter()
            .flatten()
            .any(|excluded| match excluded {
                CarbonExclusion::FullJid(full_jid) => {
                    full_jid == jid
                        || northstar_xmpp_types::jid::canonical_session_key(full_jid)
                            .is_ok_and(|canonical| canonical == jid)
                }
                CarbonExclusion::Exact(exact) => route == Some(exact),
            })
    }
}

#[derive(Clone, Copy)]
pub struct CarbonFanout<'a> {
    pub bare: &'a str,
    pub forwarded: &'a str,
    pub direction: Direction,
    pub muc_scope: Option<(&'a str, &'a str)>,
    pub exclusions: CarbonExclusions<'a>,
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
pub enum Direction {
    Sent,
    Received,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
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
    request: CarbonFanout<'_>,
    peer: &str,
    sessions: Vec<LocalCarbonTarget<P::Session>>,
    session_resources: usize,
) {
    let CarbonFanout {
        bare,
        forwarded,
        direction,
        ..
    } = request;
    let selected_resources = sessions.len();
    let attempts: Vec<(String, AttemptFuture<'_>)> = sessions
        .into_iter()
        .map(|(jid, session, route)| {
            let timeout_target = jid.clone();
            (timeout_target, Box::pin(async move {
                let Some(carbon) = port.wrap(direction, bare, &jid, forwarded) else {
                    port.delivery_failed();
                    tracing::error!(target_jid = %jid, direction = direction.as_str(), "suppressed an invalid XEP-0280 Carbon payload");
                    return Attempt::Failed;
                };
                match port.enqueue_captured(route.as_ref(), &session, carbon, request, peer).await {
                    Ok(true) => {
                        tracing::trace!(target_jid = %jid, %peer, direction = direction.as_str(), "delivered a local XEP-0280 Carbon");
                        Attempt::Delivered
                    }
                    Ok(false) => Attempt::Skipped,
                    Err(error) => {
                        port.delivery_failed();
                        tracing::warn!(?error, target_jid = %jid, direction = direction.as_str(), "post-accept Carbon could not be admitted to the local session queue");
                        Attempt::Failed
                    }
                }
            }) as AttemptFuture<'_>)
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

pub async fn send_sent_carbons<P: CarbonDeliveryPort + Sync>(
    port: &P,
    from: &str,
    forwarded: &str,
    delivered_self: Option<&str>,
    muc_scope: Option<(&str, &str)>,
) {
    send_sent_carbons_from(
        port,
        from,
        forwarded,
        delivered_self.map(CarbonExclusion::FullJid),
        muc_scope,
        None,
    )
    .await;
}

pub async fn send_sent_carbons_from<P: CarbonDeliveryPort + Sync>(
    port: &P,
    from: &str,
    forwarded: &str,
    primary: Option<CarbonExclusion<'_>>,
    muc_scope: Option<(&str, &str)>,
    origin: Option<&ExactMessageRoute>,
) {
    if let Some(fanout) =
        prepare_sent_carbons(port, from, forwarded, primary, muc_scope, origin).await
    {
        fanout.deliver(port).await;
    }
}

pub async fn prepare_sent_carbons<'a, P: CarbonDeliveryPort + Sync>(
    port: &P,
    from: &'a str,
    forwarded: &'a str,
    primary: Option<CarbonExclusion<'a>>,
    muc_scope: Option<(&'a str, &'a str)>,
    origin: Option<&'a ExactMessageRoute>,
) -> Option<PreparedCarbonFanout<'a, P::Session>> {
    let bare = northstar_xmpp_types::jid_text::bare_jid(from);
    let exclusions = CarbonExclusions {
        origin: Some(origin.map_or(CarbonExclusion::FullJid(from), CarbonExclusion::Exact)),
        primary,
    };
    capture_carbons(
        port,
        CarbonFanout {
            bare,
            forwarded,
            direction: Direction::Sent,
            muc_scope,
            exclusions,
        },
        origin.map(|route| route.account_id),
    )
    .await
}

pub async fn send_received_carbons<P: CarbonDeliveryPort + Sync>(
    port: &P,
    recipient: &str,
    delivered: Option<&str>,
    forwarded: &str,
) {
    send_received_carbons_to(
        port,
        recipient,
        delivered.map(CarbonExclusion::FullJid),
        forwarded,
        None,
    )
    .await;
}

pub async fn send_received_carbons_to<P: CarbonDeliveryPort + Sync>(
    port: &P,
    recipient: &str,
    primary: Option<CarbonExclusion<'_>>,
    forwarded: &str,
    account_id: Option<Uuid>,
) {
    if let Some(fanout) =
        prepare_received_carbons(port, recipient, primary, forwarded, account_id).await
    {
        fanout.deliver(port).await;
    }
}

pub async fn prepare_received_carbons<'a, P: CarbonDeliveryPort + Sync>(
    port: &P,
    recipient: &'a str,
    primary: Option<CarbonExclusion<'a>>,
    forwarded: &'a str,
    account_id: Option<Uuid>,
) -> Option<PreparedCarbonFanout<'a, P::Session>> {
    capture_carbons(
        port,
        CarbonFanout {
            bare: recipient,
            forwarded,
            direction: Direction::Received,
            muc_scope: None,
            exclusions: CarbonExclusions {
                origin: None,
                primary,
            },
        },
        account_id,
    )
    .await
}

type LocalCarbonTarget<S> = (String, S, Option<ExactMessageRoute>);

pub struct PreparedCarbonFanout<'a, S> {
    request: CarbonFanout<'a>,
    peer: String,
    sessions: Vec<LocalCarbonTarget<S>>,
    session_resources: usize,
    routes: Vec<ExactMessageRoute>,
}

impl<S: Send + Sync> PreparedCarbonFanout<'_, S> {
    pub async fn deliver<P: CarbonDeliveryPort<Session = S> + Sync>(self, port: &P) {
        let request = self.request;
        local_fanout(
            port,
            request,
            &self.peer,
            self.sessions,
            self.session_resources,
        )
        .await;
        port.route_captured_remote(request, &self.routes).await;
    }
}

async fn capture_carbons<'a, P: CarbonDeliveryPort + Sync>(
    port: &P,
    request: CarbonFanout<'a>,
    account_id: Option<Uuid>,
) -> Option<PreparedCarbonFanout<'a, P::Session>> {
    if !port.enabled() {
        return None;
    }
    let CarbonFanout {
        bare,
        direction,
        forwarded,
        exclusions,
        muc_scope,
    } = request;
    let Some(peer) = direction.peer(forwarded) else {
        tracing::warn!(%bare, direction = direction.as_str(), "suppressed a Carbon whose forwarded peer was not a canonical JID");
        return None;
    };
    let sessions = port.sessions(bare);
    let session_resources = sessions.len();
    let sessions = sessions
        .into_iter()
        .filter_map(|(jid, session)| {
            let route = port.local_route(&jid, &session);
            let same_account = route.as_ref().is_none_or(|route| {
                account_id.is_none_or(|id| route.account_id == id)
                    && match exclusions.origin {
                        Some(CarbonExclusion::Exact(origin)) => {
                            route.auth_generation == origin.auth_generation
                        }
                        _ => true,
                    }
            });
            (port.carbon_enabled(&session)
                && same_account
                && !exclusions.excludes(&jid, route.as_ref())
                && muc_scope.is_none_or(|(room, nick)| port.in_muc_scope(&session, room, nick)))
            .then_some((jid, session, route))
        })
        .collect();
    let routes = port
        .capture_remote(bare, account_id, exclusions, muc_scope)
        .await;
    Some(PreparedCarbonFanout {
        request,
        peer,
        sessions,
        session_resources,
        routes,
    })
}

#[cfg(test)]
#[path = "message_carbons_tests.rs"]
mod tests;

#[cfg(test)]
mod audience_tests;
