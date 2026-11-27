use super::{DirectedDelivery, DirectedDeliveryResult, DirectedEnqueue};
use anyhow::Result;
use northstar_roster_core::{ExactPresenceRoute, PresenceAccount, RosterActor};
use std::future::Future;

/// Directed grants retained by the bound client session.
pub trait DirectedPresenceSession: Sync {
    fn presence_directed_entries(&self) -> Vec<String>;
    fn presence_deliver_exact_directed(
        &self,
        delivery: DirectedDelivery<'_>,
    ) -> impl Future<Output = DirectedDeliveryResult> + Send;
}

/// Exact directed delivery supplied by the session's host.
pub trait DirectedPresenceHost: Send + Sync {
    fn deliver_exact_directed(
        &self,
        delivery: DirectedDelivery<'_>,
    ) -> impl Future<Output = DirectedDeliveryResult> + Send;
}

/// Captures remote candidates and enqueues to an exact local or remote route.
pub trait DirectedPresenceTransport: Send + Sync {
    fn directed_source_is_current(&self, source: &RosterActor) -> bool;

    fn capture_remote_directed_routes(
        &self,
        scope: &str,
        recipient: &PresenceAccount,
    ) -> impl Future<Output = Result<Vec<ExactPresenceRoute>>> + Send;

    fn send_remote_directed_route(
        &self,
        route: &ExactPresenceRoute,
        source: &RosterActor,
        stanza: &str,
        unavailable: bool,
    ) -> impl Future<Output = Result<DirectedEnqueue>> + Send;

    fn enqueue_local_directed_route(
        &self,
        route: &ExactPresenceRoute,
        stanza: &str,
        available_only: bool,
    ) -> DirectedEnqueue;
}
