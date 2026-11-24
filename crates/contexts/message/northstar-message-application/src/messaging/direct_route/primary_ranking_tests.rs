use super::*;
use crate::messaging::{ExactMessageRoute, FullJidFallbackPort, OnlineRoutePort};
use crate::test_queue::TestItem;
use northstar_message_core::route_item::{RouteEnqueue, RouteItem, RouteSendError};
use std::sync::Mutex;

const BARE: &str = "alice@example.test";
const LOCAL: &str = "alice@example.test/local";
const REMOTE: &str = "alice@example.test/remote";
const STANZA: &str = "<message/>";

struct RankingPort {
    events: Mutex<Vec<&'static str>>,
    remote_accepts: bool,
    local_accepts: bool,
    delivery: Option<DurableDelivery>,
}

impl RankingPort {
    fn record(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }
}

impl OnlineRoutePort for RankingPort {
    type Session = i16;
    type Item = TestItem;

    fn try_local(
        &self,
        _: &i16,
        enqueue: RouteEnqueue<TestItem>,
    ) -> anyhow::Result<(), RouteSendError<TestItem>> {
        self.record("local");
        assert_eq!(enqueue.item().stanza(), STANZA);
        assert_eq!(enqueue.item().c2s_delivery(), self.delivery);
        enqueue.complete_for_fake(self.local_accepts)
    }

    fn record_local_accept(&self, durable: bool) {
        assert_eq!(durable, self.delivery.is_some());
        self.record("local telemetry");
    }

    async fn route_available_remote(&self, _: &str, _: &str, _: Option<DurableDelivery>) -> bool {
        self.record("remote headline");
        true
    }

    async fn route_remote_primary(
        &self,
        jid: &str,
        _: &str,
        _: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        assert_eq!(jid, REMOTE);
        self.record("remote full");
        OnlineRouteResult {
            delivered: true,
            accepted_full_jid: Some(REMOTE.to_owned()),
        }
    }
}

impl FullJidFallbackPort for RankingPort {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, i16)> {
        panic!("no full-JID fallback expected")
    }

    fn available_priority(&self, priority: &i16) -> Option<i16> {
        Some(*priority)
    }

    fn priority(&self, priority: &i16) -> i16 {
        *priority
    }

    async fn privacy_allows_fallback(&self, _: &i16, _: &str) -> anyhow::Result<bool> {
        panic!("no full-JID fallback expected")
    }

    fn post_accept_failed(&self) {
        panic!("no post-accept failure expected")
    }
}

impl DirectMessageRoutePort for RankingPort {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        self.record("health");
        DirectPostCommitMode::Live
    }

    fn clustered_direct_routes(&self) -> bool {
        true
    }

    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        assert_eq!(Some(delivery), self.delivery);
        self.record("rearm");
    }
}

impl ExactMessageRoutePort for RankingPort {
    async fn capture_remote_message_routes(
        &self,
        jid: &str,
        recipient_id: Uuid,
    ) -> Option<Vec<ExactMessageRoute>> {
        assert_eq!(jid, BARE);
        self.record("capture");
        Some(vec![ExactMessageRoute {
            full_jid: REMOTE.to_owned(),
            account_id: recipient_id,
            auth_generation: 1,
            connection_id: Uuid::from_u128(42),
            node_id: Some("peer".to_owned()),
            priority: Some(10),
            available: Some(true),
        }])
    }

    async fn route_exact_remote_primary(
        &self,
        jid: &str,
        route: &ExactMessageRoute,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        assert_eq!(jid, BARE);
        assert_eq!(route.full_jid, REMOTE);
        assert_eq!(route.connection_id, Uuid::from_u128(42));
        assert_eq!(stanza, STANZA);
        assert_eq!(delivery, self.delivery);
        self.record("remote exact");
        OnlineRouteResult {
            delivered: self.remote_accepts,
            accepted_full_jid: self.remote_accepts.then(|| route.full_jid.clone()),
        }
    }
}

#[tokio::test]
async fn ranks_bare_primary_offers_but_preserves_exact_full_and_headline_routing() {
    let recipient_id = Uuid::from_u128(17);
    let message_id = Uuid::from_u128(23);
    let delivery = DurableDelivery {
        recipient_id,
        message_id,
        claim_id: Some(message_id),
    };
    let local = [(LOCAL.to_owned(), 5)];
    let bare = DirectRouteTarget::Bare(BARE);
    let full = DirectRouteTarget::Full {
        jid: REMOTE,
        bare: BARE,
    };
    let cases: &[_] = &[
        (
            "chat",
            bare,
            true,
            true,
            &local[..],
            Some(delivery),
            Some(REMOTE),
            &["health", "capture", "remote exact", "health"][..],
        ),
        (
            "chat",
            bare,
            false,
            true,
            &local[..],
            Some(delivery),
            Some(LOCAL),
            &[
                "health",
                "capture",
                "remote exact",
                "local",
                "local telemetry",
                "health",
            ],
        ),
        (
            "chat",
            bare,
            false,
            false,
            &local[..],
            Some(delivery),
            None,
            &[
                "health",
                "capture",
                "remote exact",
                "local",
                "rearm",
                "health",
            ],
        ),
        (
            "chat",
            full,
            false,
            false,
            &[],
            None,
            Some(REMOTE),
            &["health", "remote full", "health"],
        ),
        (
            "headline",
            bare,
            false,
            true,
            &local[..],
            None,
            Some(LOCAL),
            &[
                "health",
                "local",
                "local telemetry",
                "remote headline",
                "health",
            ],
        ),
    ];
    for &(
        message_type,
        target,
        remote_accepts,
        local_accepts,
        approved_targets,
        delivery,
        accepted,
        events,
    ) in cases
    {
        let port = RankingPort {
            events: Mutex::new(Vec::new()),
            remote_accepts,
            local_accepts,
            delivery,
        };
        let result = DirectMessageRouter::route(
            &port,
            DirectRouteRequest {
                message_type,
                target,
                sender: "bob@example.test/sender",
                recipient_id,
                stanza: STANZA,
                delivery: delivery.map_or(
                    DirectRouteDelivery::Volatile,
                    DirectRouteDelivery::Committed,
                ),
                approved_targets,
                enforce_direct_health: true,
            },
        )
        .await
        .unwrap();
        let expected = accepted.map_or(DirectRouteOutcome::Unrouted, |jid| {
            DirectRouteOutcome::Routed {
                accepted_full_jid: Some(jid.to_owned()),
            }
        });
        assert_eq!(result, expected);
        assert_eq!(port.events.into_inner().unwrap().as_slice(), events);
    }
}
