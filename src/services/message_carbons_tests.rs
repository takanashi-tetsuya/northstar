use super::{
    bounded_fanout, send_received_carbons, send_sent_carbons, Attempt, AttemptFuture,
    CarbonDeliveryPort, Direction,
};
use crate::services::privacy::PrivacyStanzaKind;
use anyhow::Result;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

#[derive(Clone)]
struct Session {
    enabled: bool,
    room_nick: Option<(&'static str, &'static str)>,
    privacy: bool,
    sender: crate::outbound::OutboundSender,
}

#[derive(Default)]
struct Port {
    sessions: Vec<(String, Session)>,
    peers: Mutex<Vec<String>>,
    remote: Mutex<Vec<String>>,
    enqueues: AtomicUsize,
    failures: AtomicUsize,
    timeouts: AtomicUsize,
}

impl CarbonDeliveryPort for Port {
    type Session = Session;

    fn enabled(&self) -> bool {
        true
    }

    fn sessions(&self, _: &str) -> Vec<(String, Self::Session)> {
        self.sessions.clone()
    }

    fn carbon_enabled(&self, session: &Self::Session) -> bool {
        session.enabled
    }

    fn in_muc_scope(&self, session: &Self::Session, room: &str, nick: &str) -> bool {
        session.room_nick == Some((room, nick))
    }

    fn wrap(&self, direction: Direction, from: &str, to: &str, forwarded: &str) -> Option<String> {
        crate::xmpp::xml_util::carbon_message(direction.as_str(), from, to, forwarded)
    }

    async fn privacy_allows(
        &self,
        session: &Self::Session,
        peer: &str,
        _: PrivacyStanzaKind,
    ) -> Result<bool> {
        self.peers.lock().unwrap().push(peer.to_owned());
        Ok(session.privacy)
    }

    async fn enqueue(&self, session: &Self::Session, stanza: String) -> bool {
        let sent = session.sender.send(stanza).await.is_ok();
        if sent {
            self.enqueues.fetch_add(1, Ordering::SeqCst);
        }
        sent
    }

    async fn route_sent_remote(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<(&str, &str)>,
    ) {
        self.remote
            .lock()
            .unwrap()
            .push(format!("sent:{}", self.enqueues.load(Ordering::SeqCst)));
    }

    async fn route_received_remote(&self, _: &str, _: Option<&str>, _: &str) {
        self.remote
            .lock()
            .unwrap()
            .push(format!("received:{}", self.enqueues.load(Ordering::SeqCst)));
    }

    fn delivery_failed(&self) {
        self.failures.fetch_add(1, Ordering::SeqCst);
    }

    fn target_timed_out(&self) {
        self.timeouts.fetch_add(1, Ordering::SeqCst);
    }
}

fn session() -> (
    Session,
    tokio::sync::mpsc::Receiver<crate::outbound::OutboundItem>,
) {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    (
        Session {
            enabled: true,
            room_nick: None,
            privacy: true,
            sender: crate::outbound::OutboundSender::new(sender),
        },
        receiver,
    )
}

#[tokio::test]
async fn sent_carbon_respects_exclusions_scope_and_privacy_before_remote_route() {
    let (primary, mut primary_rx) = session();
    let (delivered, mut delivered_rx) = session();
    let (other, mut other_rx) = session();
    let (mut eligible, mut eligible_rx) = session();
    eligible.room_nick = Some(("room@example.test", "alice"));
    let (mut wrong_room, mut wrong_room_rx) = session();
    wrong_room.room_nick = Some(("room@example.test", "other"));
    let (mut blocked, mut blocked_rx) = session();
    blocked.room_nick = Some(("room@example.test", "alice"));
    blocked.privacy = false;
    let port = Port {
        sessions: vec![
            ("alice@example.test/phone".into(), primary),
            ("alice@example.test/laptop".into(), delivered),
            ("alice@example.test/tablet".into(), other),
            ("alice@example.test/eligible".into(), eligible),
            ("alice@example.test/other".into(), wrong_room),
            ("alice@example.test/blocked".into(), blocked),
        ],
        ..Default::default()
    };
    let forwarded = "<message xmlns='jabber:client' from='alice@example.test/phone' to='bob@example.test'><body>hi</body></message>";
    send_sent_carbons(
        &port,
        "alice@example.test/phone",
        forwarded,
        Some("alice@example.test/laptop"),
        Some(("room@example.test", "alice")),
    )
    .await;
    assert!(port
        .peers
        .lock()
        .unwrap()
        .iter()
        .all(|peer| peer == "bob@example.test"));
    assert_eq!(*port.remote.lock().unwrap(), ["sent:1"]);
    assert!(primary_rx.try_recv().is_err());
    assert!(delivered_rx.try_recv().is_err());
    assert!(other_rx.try_recv().is_err());
    assert!(wrong_room_rx.try_recv().is_err());
    assert!(blocked_rx.try_recv().is_err());
    let carbon = eligible_rx
        .try_recv()
        .expect("eligible matching resource should receive a Carbon");
    assert!(roxmltree::Document::parse(&carbon.stanza)
        .unwrap()
        .descendants()
        .any(|node| {
            node.is_element()
                && node.tag_name().name() == "sent"
                && node.tag_name().namespace() == Some("urn:xmpp:carbons:2")
        }));
    assert_eq!(port.failures.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn received_carbon_uses_forwarded_sender_and_excludes_primary() {
    let (primary, mut primary_rx) = session();
    let (other, mut other_rx) = session();
    let port = Port {
        sessions: vec![
            ("alice@example.test/phone".into(), primary),
            ("alice@example.test/tablet".into(), other),
        ],
        ..Default::default()
    };
    let forwarded = "<message xmlns='jabber:client' from='Blocked@Example.test/Phone' to='alice@example.test/phone'><body>hi</body></message>";
    send_received_carbons(
        &port,
        "alice@example.test",
        Some("alice@example.test/phone"),
        forwarded,
    )
    .await;
    assert!(primary_rx.try_recv().is_err());
    let carbon = other_rx
        .try_recv()
        .expect("secondary resource should receive a Carbon");
    assert!(roxmltree::Document::parse(&carbon.stanza)
        .unwrap()
        .descendants()
        .any(|node| {
            node.is_element()
                && node.tag_name().name() == "received"
                && node.tag_name().namespace() == Some("urn:xmpp:carbons:2")
        }));
    assert_eq!(*port.peers.lock().unwrap(), ["blocked@example.test/Phone"]);
    assert_eq!(*port.remote.lock().unwrap(), ["received:1"]);
}

#[tokio::test]
async fn invalid_forwarded_stanza_suppresses_local_and_remote_carbons() {
    let (target, mut receiver) = session();
    let port = Port {
        sessions: vec![("alice@example.test/tablet".into(), target)],
        ..Default::default()
    };
    send_received_carbons(&port, "alice@example.test", None, "<message/>").await;
    send_sent_carbons(&port, "alice@example.test/phone", "<message/>", None, None).await;
    assert!(receiver.try_recv().is_err());
    assert!(port.remote.lock().unwrap().is_empty());
}

#[tokio::test]
async fn timed_out_target_counts_failure_before_remote_fanout() {
    let (slow, _receiver) = session();
    slow.sender.try_send("occupied".to_owned()).unwrap();
    let port = Port {
        sessions: vec![("alice@example.test/tablet".into(), slow)],
        ..Default::default()
    };
    let forwarded = "<message xmlns='jabber:client' from='bob@example.test' to='alice@example.test'><body>hi</body></message>";
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        send_received_carbons(&port, "alice@example.test", None, forwarded),
    )
    .await
    .expect("Carbon fanout exceeded the target deadline");
    assert_eq!(port.failures.load(Ordering::SeqCst), 1);
    assert_eq!(port.timeouts.load(Ordering::SeqCst), 1);
    assert_eq!(*port.remote.lock().unwrap(), ["received:0"]);
}

#[tokio::test]
async fn one_slow_target_does_not_starve_healthy_resources() {
    let (slow_tx, _slow_rx) = tokio::sync::mpsc::channel(1);
    let slow = crate::outbound::OutboundSender::new(slow_tx);
    slow.try_send("occupied".to_owned()).unwrap();
    let (fast_one_tx, mut fast_one_rx) = tokio::sync::mpsc::channel(1);
    let (fast_two_tx, mut fast_two_rx) = tokio::sync::mpsc::channel(1);
    let targets = vec![
        ("slow", slow),
        (
            "fast-one",
            crate::outbound::OutboundSender::new(fast_one_tx),
        ),
        (
            "fast-two",
            crate::outbound::OutboundSender::new(fast_two_tx),
        ),
    ];
    let attempts: Vec<(String, AttemptFuture<'_>)> = targets
        .into_iter()
        .map(|(target, sender)| {
            (
                target.to_owned(),
                Box::pin(async move {
                    if sender.send(format!("carbon-{target}")).await.is_ok() {
                        Attempt::Delivered
                    } else {
                        Attempt::Failed
                    }
                }) as AttemptFuture<'_>,
            )
        })
        .collect();
    let summary = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        bounded_fanout(attempts, 2, std::time::Duration::from_millis(50)),
    )
    .await
    .expect("bounded Carbon fanout did not complete");
    assert_eq!(summary.delivered, 2);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.timed_out, 1);
    assert_eq!(summary.timed_out_targets, vec!["slow"]);
    assert_eq!(fast_one_rx.recv().await.unwrap().stanza, "carbon-fast-one");
    assert_eq!(fast_two_rx.recv().await.unwrap().stanza, "carbon-fast-two");
}

#[tokio::test]
async fn fanout_never_exceeds_fixed_concurrency_bound() {
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let attempts: Vec<(String, AttemptFuture<'_>)> = (0..24)
        .map(|index| {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            (
                format!("resource-{index}"),
                Box::pin(async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(now, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Attempt::Delivered
                }) as AttemptFuture<'_>,
            )
        })
        .collect();
    let summary = bounded_fanout(attempts, 3, std::time::Duration::from_secs(1)).await;
    assert_eq!(summary.delivered, 24);
    assert_eq!(summary.failed, 0);
    assert!(maximum.load(Ordering::SeqCst) <= 3);
}
