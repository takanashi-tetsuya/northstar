use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tokio::sync::Notify;

const BARE: &str = "alice@example.test";
const FROM: &str = "alice@example.test/phone";
const TABLET: &str = "alice@example.test/tablet";
const LAPTOP: &str = "alice@example.test/laptop";
const FORWARDED: &str = "<message xmlns='jabber:client' from='alice@example.test/phone' to='bob@example.test'><body>hi</body></message>";

#[derive(Clone)]
struct Session {
    route: ExactMessageRoute,
    enabled: Arc<AtomicBool>,
}

#[derive(Default)]
struct Port {
    sessions: Mutex<Vec<Session>>,
    queued: Mutex<Vec<ExactMessageRoute>>,
    blocked: AtomicBool,
    lookup_error: Option<&'static str>,
    pause: Option<&'static str>,
    entered: Notify,
    resume: Notify,
}

impl Port {
    fn bind(&self, jid: &str, id: u128, enabled: bool) -> Session {
        let session = Session {
            route: ExactMessageRoute {
                full_jid: jid.to_owned(),
                account_id: Uuid::from_u128(1),
                auth_generation: 2,
                connection_id: Uuid::from_u128(id),
                node_id: None,
                priority: None,
                available: None,
            },
            enabled: Arc::new(AtomicBool::new(enabled)),
        };
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|current| current.route.full_jid != jid);
        sessions.push(session.clone());
        session
    }

    async fn capture(&self) -> PreparedCarbonFanout<'static, Session> {
        prepare_sent_carbons(self, FROM, FORWARDED, None, None, None)
            .await
            .unwrap()
    }
}

impl CarbonDeliveryPort for Port {
    type Session = Session;

    fn enabled(&self) -> bool {
        true
    }

    fn sessions(&self, bare: &str) -> Vec<(String, Session)> {
        assert_eq!(bare, BARE);
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .map(|session| (session.route.full_jid.clone(), session.clone()))
            .collect()
    }

    fn carbon_enabled(&self, session: &Session) -> bool {
        session.enabled.load(Ordering::Acquire)
    }

    fn in_muc_scope(&self, _: &Session, _: &str, _: &str) -> bool {
        false
    }

    fn wrap(&self, direction: Direction, from: &str, to: &str, forwarded: &str) -> Option<String> {
        northstar_message_core::validation::carbon_message(direction.as_str(), from, to, forwarded)
    }

    async fn privacy_allows(
        &self,
        session: &Session,
        peer: &str,
        _: PrivacyStanzaKind,
    ) -> Result<bool> {
        assert_eq!(peer, "bob@example.test");
        if self.pause == Some(session.route.full_jid.as_str()) {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        anyhow::ensure!(
            self.lookup_error != Some(session.route.full_jid.as_str()),
            "injected lookup failure"
        );
        Ok(true)
    }

    async fn policy_allows(&self, _: &str, session: &Session, peer: &str) -> Result<bool> {
        Ok(self
            .privacy_allows(session, peer, PrivacyStanzaKind::Message)
            .await?
            && !self.blocked.load(Ordering::Acquire))
    }

    async fn enqueue(&self, session: &Session, _: String) -> bool {
        self.queued.lock().unwrap().push(session.route.clone());
        true
    }

    fn local_route(&self, _: &str, session: &Session) -> Option<ExactMessageRoute> {
        Some(session.route.clone())
    }

    fn delivery_failed(&self) {
        panic!("unexpected failure")
    }

    fn target_timed_out(&self) {
        panic!("unexpected timeout")
    }
}

#[tokio::test]
async fn disable_during_policy_lookup_suppresses_selected_connection() {
    let port = Port {
        pause: Some(TABLET),
        ..Port::default()
    };
    let tablet = port.bind(TABLET, 2, true);
    let fanout = port.capture().await;
    tokio::join!(fanout.deliver(&port), async {
        port.entered.notified().await;
        tablet.enabled.store(false, Ordering::Release);
        port.resume.notify_one();
    });
    assert!(port.queued.lock().unwrap().is_empty());
}

#[tokio::test]
async fn late_enable_and_bind_do_not_expand_the_audience() {
    let port = Port::default();
    let tablet = port.bind(TABLET, 2, false);
    let fanout = port.capture().await;
    tablet.enabled.store(true, Ordering::Release);
    port.bind(LAPTOP, 3, true);
    fanout.deliver(&port).await;
    assert!(port.queued.lock().unwrap().is_empty());
}

#[tokio::test]
async fn captured_audience_does_not_follow_a_replacement() {
    let port = Port::default();
    port.bind(TABLET, 2, true);
    let fanout = port.capture().await;
    port.bind(TABLET, 3, true);
    fanout.deliver(&port).await;
    assert!(port.queued.lock().unwrap().is_empty());
}

#[tokio::test]
async fn exact_exclusion_does_not_suppress_the_captured_replacement() {
    let port = Port::default();
    let stale_origin = port.bind(FROM, 2, true);
    let stale_primary = port.bind(TABLET, 3, true);
    let replacement_origin = port.bind(FROM, 4, true);
    let replacement_primary = port.bind(TABLET, 5, true);
    send_sent_carbons_from(
        &port,
        FROM,
        FORWARDED,
        Some(CarbonExclusion::Exact(&stale_primary.route)),
        None,
        Some(&stale_origin.route),
    )
    .await;
    let queued = port.queued.lock().unwrap();
    assert_eq!(queued.len(), 2);
    assert!(queued.contains(&replacement_origin.route));
    assert!(queued.contains(&replacement_primary.route));
}

#[tokio::test]
async fn post_accept_block_is_applied_before_enqueue() {
    let port = Port::default();
    port.bind(TABLET, 2, true);
    let fanout = port.capture().await;
    port.blocked.store(true, Ordering::Release);
    fanout.deliver(&port).await;
    assert!(port.queued.lock().unwrap().is_empty());
}

#[tokio::test]
async fn lookup_failure_does_not_suppress_an_unrelated_resource() {
    let port = Port {
        lookup_error: Some(TABLET),
        pause: Some(TABLET),
        ..Port::default()
    };
    port.bind(TABLET, 2, true);
    let laptop = port.bind(LAPTOP, 3, true);
    let fanout = port.capture().await;
    port.bind("alice@example.test/late", 4, true);
    tokio::join!(fanout.deliver(&port), async {
        port.entered.notified().await;
        assert_eq!(
            *port.queued.lock().unwrap(),
            std::slice::from_ref(&laptop.route)
        );
        port.resume.notify_one();
    });
    assert_eq!(*port.queued.lock().unwrap(), [laptop.route]);
}
