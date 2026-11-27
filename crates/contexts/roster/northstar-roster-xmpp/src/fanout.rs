//! Fan-out of committed block-list, privacy-list and blocking-presence changes.

use crate::roster_push::RemoteRouteFailure;
use anyhow::Result;
use northstar_roster_core::RosterActor;
use northstar_stream::local_routes::session::OnlineSession;
use std::future::Future;
use std::time::Duration;

mod blocking_presence;
mod policy_routes;
mod pushes;

pub use blocking_presence::deliver_blocking_presence_change;
pub use policy_routes::PolicyPushLocalRoutes;
pub use pushes::{blocking_push_stanza, push_blocklist_change, push_privacy_change};
pub(crate) use pushes::{resynchronize_blocklist, run_blocklist_observer};

pub const BLOCKING_PUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Node-owned routes for committed block-list, privacy-list and blocking-presence changes.
pub trait RosterFanoutRoutes: PolicyPushLocalRoutes {
    fn fanout_sessions(&self, jid: &str) -> Vec<(String, OnlineSession)>;
    fn record_fanout_failure(&self);
    fn remote_blocklist_push(
        &self,
        actor: &RosterActor,
        revision: i64,
        push: impl FnMut() -> Result<String> + Send,
    ) -> impl Future<Output = Result<Vec<RemoteRouteFailure>>> + Send;
    fn remote_privacy_push(
        &self,
        actor: &RosterActor,
        base: &str,
    ) -> impl Future<Output = Result<Vec<RemoteRouteFailure>>> + Send;
}

#[cfg(test)]
mod tests {
    use super::blocking_presence::tests::{change, contact};
    use super::*;
    use northstar_stream::local_routes::session::test_online_session;
    use northstar_xml_builder::rewrite::set_to;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    pub(super) mod policy_routes;
    use policy_routes::{actor, start_observer, TestJournal};

    #[derive(Debug, PartialEq)]
    enum RemoteCall {
        Blocklist(String),
        Privacy(String, String),
    }

    #[derive(Default)]
    struct Routes {
        request_push: bool,
        remote_pushes: Mutex<Vec<String>>,
        sessions: Vec<(String, OnlineSession)>,
        failures: Arc<AtomicU64>,
        calls: Mutex<Vec<RemoteCall>>,
    }

    impl RosterFanoutRoutes for Routes {
        fn fanout_sessions(&self, jid: &str) -> Vec<(String, OnlineSession)> {
            self.sessions
                .iter()
                .filter(|(full, _)| {
                    full == jid || northstar_xmpp_types::jid_text::bare_jid(full) == jid
                })
                .cloned()
                .collect()
        }

        fn record_fanout_failure(&self) {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }

        async fn remote_blocklist_push(
            &self,
            actor: &RosterActor,
            revision: i64,
            mut push: impl FnMut() -> Result<String> + Send,
        ) -> Result<Vec<RemoteRouteFailure>> {
            let owner = actor.bare_jid();
            assert_eq!(owner, "alice@example.test");
            assert_eq!(revision, 1);
            self.calls
                .lock()
                .unwrap()
                .push(RemoteCall::Blocklist(owner.to_owned()));
            if self.request_push {
                self.remote_pushes.lock().unwrap().push(push()?);
            }
            Ok(Vec::new())
        }

        async fn remote_privacy_push(
            &self,
            actor: &RosterActor,
            base: &str,
        ) -> Result<Vec<RemoteRouteFailure>> {
            self.calls.lock().unwrap().push(RemoteCall::Privacy(
                actor.bare_jid().to_owned(),
                base.to_owned(),
            ));
            Ok(Vec::new())
        }
    }

    fn run(future: impl Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(future);
    }

    fn session(
        resource: &str,
    ) -> (
        OnlineSession,
        tokio::sync::mpsc::Receiver<northstar_stream::outbound::OutboundItem>,
    ) {
        test_online_session(Uuid::from_u128(1), 7, Uuid::new_v4(), resource, 1)
    }

    fn assert_to(stanza: &str, target: &str) {
        let document = roxmltree::Document::parse(stanza).unwrap();
        assert_eq!(document.root_element().attribute("to"), Some(target));
    }

    #[test]
    fn blocklist_push_skips_sessions_that_did_not_request_it() {
        run(async {
            let (interested, mut interested_rx) = session("interested");
            let (uninterested, mut uninterested_rx) = session("uninterested");
            interested
                .blocklist_requested
                .store(true, Ordering::Release);
            let routes = Routes {
                request_push: true,
                sessions: vec![
                    ("alice@example.test/interested".into(), interested.clone()),
                    (
                        "alice@example.test/uninterested".into(),
                        uninterested.clone(),
                    ),
                ],
                ..Routes::default()
            };
            let payload = "<unblock xmlns='urn:xmpp:blocking'/>";
            let actor = actor("interested", interested.connection_id);
            let journal = TestJournal::unblock_all();
            start_observer(&routes, &interested, &actor, journal.clone());
            push_blocklist_change(&routes, &journal, &actor).await;
            let push = interested_rx.recv().await.unwrap().stanza;
            assert_to(&push, "alice@example.test/interested");
            assert!(push.contains(payload));
            assert!(interested_rx.try_recv().is_err());
            assert!(uninterested_rx.try_recv().is_err());
            assert!(!interested.disconnect.is_cancelled());
            assert!(!uninterested.disconnect.is_cancelled());
            assert_eq!(routes.failures.load(Ordering::Relaxed), 0);
            assert_eq!(
                *routes.calls.lock().unwrap(),
                vec![RemoteCall::Blocklist("alice@example.test".into())]
            );
            let pushes = routes.remote_pushes.lock().unwrap();
            assert_eq!(pushes.len(), 1);
            assert_to(&pushes[0], "alice@example.test");
            assert!(pushes[0].contains(payload));
        });
    }

    #[test]
    fn blocklist_push_closed_queue_disconnects_and_counts() {
        run(async {
            let (session, receiver) = session("closed");
            session.blocklist_requested.store(true, Ordering::Release);
            drop(receiver);
            let routes = Routes {
                sessions: vec![("alice@example.test/closed".into(), session.clone())],
                ..Routes::default()
            };
            let actor = actor("closed", session.connection_id);
            let journal = TestJournal::unblock_all();
            start_observer(&routes, &session, &actor, journal.clone());
            push_blocklist_change(&routes, &journal, &actor).await;
            session.disconnect.cancelled().await;
            assert!(session.disconnect.is_cancelled());
            assert!(session.sender.backpressure_disconnect().is_cancelled());
            assert_eq!(routes.failures.load(Ordering::Relaxed), 1);
            assert_eq!(
                *routes.calls.lock().unwrap(),
                vec![RemoteCall::Blocklist("alice@example.test".into())]
            );
        });
    }

    #[test]
    fn blocklist_push_full_queue_times_out_disconnects_and_counts() {
        run(async {
            let (session, mut receiver) = session("full");
            session.blocklist_requested.store(true, Ordering::Release);
            session.sender.try_send("older".into()).unwrap();
            let routes = Routes {
                sessions: vec![("alice@example.test/full".into(), session.clone())],
                ..Routes::default()
            };
            let started = tokio::time::Instant::now();
            let actor = actor("full", session.connection_id);
            let journal = TestJournal::unblock_all();
            start_observer(&routes, &session, &actor, journal.clone());
            push_blocklist_change(&routes, &journal, &actor).await;
            session.disconnect.cancelled().await;
            assert!(started.elapsed() >= Duration::from_secs(2));
            assert!(started.elapsed() < Duration::from_secs(3));
            assert!(session.disconnect.is_cancelled());
            assert!(session.sender.backpressure_disconnect().is_cancelled());
            assert_eq!(routes.failures.load(Ordering::Relaxed), 1);
            assert_eq!(receiver.try_recv().unwrap().stanza, "older");
            assert!(receiver.try_recv().is_err());
            assert_eq!(
                *routes.calls.lock().unwrap(),
                vec![RemoteCall::Blocklist("alice@example.test".into())]
            );
        });
    }

    #[test]
    fn privacy_push_returns_the_current_connection_push_instead_of_sending() {
        run(async {
            let (current, mut current_rx) = session("current");
            let (other, mut other_rx) = session("other");
            let (uninterested, mut uninterested_rx) = session("uninterested");
            current.privacy_requested.store(true, Ordering::Release);
            other.privacy_requested.store(true, Ordering::Release);
            let routes = Routes {
                sessions: vec![
                    ("alice@example.test/current".into(), current.clone()),
                    ("alice@example.test/other".into(), other.clone()),
                    (
                        "alice@example.test/uninterested".into(),
                        uninterested.clone(),
                    ),
                ],
                ..Routes::default()
            };
            let base = "<iq type='set' id='privacy'><query xmlns='jabber:iq:privacy'><list name='work'/></query></iq>";
            let returned = push_privacy_change(
                &routes,
                &actor("current", current.connection_id),
                "work",
                base,
            )
            .await;
            assert_eq!(returned, Some(set_to(base, "alice@example.test/current")));
            assert_to(returned.as_deref().unwrap(), "alice@example.test/current");
            assert!(current_rx.try_recv().is_err());
            let push = other_rx.try_recv().unwrap().stanza;
            assert_eq!(push, set_to(base, "alice@example.test/other"));
            assert_to(&push, "alice@example.test/other");
            assert!(other_rx.try_recv().is_err());
            assert!(uninterested_rx.try_recv().is_err());
            for session in [current, other, uninterested] {
                assert!(!session.disconnect.is_cancelled());
            }
            assert_eq!(routes.failures.load(Ordering::Relaxed), 0);
            assert_eq!(
                *routes.calls.lock().unwrap(),
                vec![RemoteCall::Privacy(
                    "alice@example.test".into(),
                    base.into()
                )]
            );
        });
    }

    #[test]
    fn privacy_push_full_queue_disconnects_and_counts() {
        run(async {
            let (session, mut receiver) = session("full");
            session.privacy_requested.store(true, Ordering::Release);
            session.sender.try_send("older".into()).unwrap();
            let routes = Routes {
                sessions: vec![("alice@example.test/full".into(), session.clone())],
                ..Routes::default()
            };
            let base = "<iq type='set' id='privacy'><query xmlns='jabber:iq:privacy'><list name='work'/></query></iq>";
            assert_eq!(
                push_privacy_change(&routes, &actor("other", Uuid::new_v4()), "work", base).await,
                None
            );
            assert!(session.disconnect.is_cancelled());
            assert!(session.sender.backpressure_disconnect().is_cancelled());
            assert_eq!(routes.failures.load(Ordering::Relaxed), 1);
            assert_eq!(receiver.try_recv().unwrap().stanza, "older");
            assert!(receiver.try_recv().is_err());
            assert_eq!(
                *routes.calls.lock().unwrap(),
                vec![RemoteCall::Privacy(
                    "alice@example.test".into(),
                    base.into()
                )]
            );
        });
    }

    #[test]
    fn blocking_presence_unavailable_reaches_roster_and_matching_directed_targets() {
        run(async {
            let roster = contact("bob@example.test/Desktop", None, false, true, true);
            let directed = contact("carol@example.test/Phone", None, false, true, false);
            let unrelated = contact("dave@example.test/Phone", None, false, false, true);
            let mut directed = directed;
            directed.route.directed = Some("carol@example.test/Phone".into());
            let mut pages = Vec::new();
            deliver_blocking_presence_change(
                change(vec![roster.clone(), directed.clone(), unrelated]),
                |page, available| {
                    pages.push((page, available));
                    std::future::ready(())
                },
            )
            .await;
            assert_eq!(pages, vec![(vec![roster.route, directed.route], false)]);
        });
    }

    #[test]
    fn blocking_presence_local_bare_target_skips_unavailable_recipients_and_routes_remote_nodes() {
        run(async {
            let mut local = contact("bob@example.test/available", None, true, false, true);
            local.route.address = "bob@example.test".into();
            let mut remote = contact("bob@example.test/remote", Some("node-b"), true, false, true);
            remote.route.address = "bob@example.test".into();
            let mut pages = Vec::new();
            deliver_blocking_presence_change(
                change(vec![local.clone(), remote.clone()]),
                |page, available| {
                    pages.push((page, available));
                    std::future::ready(())
                },
            )
            .await;
            assert_eq!(pages, vec![(vec![local.route, remote.route], true)]);
        });
    }

    #[test]
    fn blocking_presence_remote_domain_requires_policy() {
        run(async {
            for allowed in [false, true] {
                let mut external = contact("bob@remote.test/Phone", None, true, false, allowed);
                external.route.recipient = None;
                let mut pages = Vec::new();
                deliver_blocking_presence_change(
                    change(vec![external.clone()]),
                    |page, available| {
                        pages.push((page, available));
                        std::future::ready(())
                    },
                )
                .await;
                assert_eq!(
                    pages,
                    if allowed {
                        vec![(vec![external.route], true)]
                    } else {
                        Vec::new()
                    }
                );
            }
        });
    }
    #[test]
    fn blocklist_push_builds_the_remote_stanza_only_when_asked() {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let routes = Routes::default();
                let actor = actor("sender", Uuid::new_v4());
                let mut invalid = TestJournal::unblock_all();
                invalid.changes[0].action =
                    northstar_roster_application::blocklist_revisions::BlocklistAction::Block;
                invalid.changes[0].patterns = vec!["@".into()];
                push_blocklist_change(&routes, &invalid, &actor).await;
                assert!(routes.remote_pushes.lock().unwrap().is_empty());
                assert_eq!(routes.failures.load(Ordering::Relaxed), 0);

                let routes = Routes {
                    request_push: true,
                    ..Routes::default()
                };
                let payload = "<unblock xmlns='urn:xmpp:blocking'/>";
                let journal = TestJournal::unblock_all();
                push_blocklist_change(&routes, &journal, &actor).await;
                let pushes = routes.remote_pushes.lock().unwrap();
                assert_eq!(pushes.len(), 1);
                let push = roxmltree::Document::parse(&pushes[0]).unwrap();
                assert_eq!(
                    push.root_element().attribute("to"),
                    Some("alice@example.test")
                );
                assert!(pushes[0].contains(payload));
            });
    }

    #[test]
    fn push_targets_an_exact_resource() {
        let push = blocking_push_stanza(
            "alice@example.test/Phone",
            "<unblock xmlns='urn:xmpp:blocking'/>",
            Uuid::nil(),
        );
        assert!(push.contains("to='alice@example.test/Phone'"));
        assert!(push.contains("<unblock xmlns='urn:xmpp:blocking'/>"));
    }
}
