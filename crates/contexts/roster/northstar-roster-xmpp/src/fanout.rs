//! Fan-out of committed block-list, privacy-list and blocking-presence changes.

use crate::roster_push::RemoteRouteFailure;
use anyhow::Result;
use northstar_stream::local_routes::session::OnlineSession;
use std::future::Future;
use std::time::Duration;

mod blocking_presence;
mod pushes;

pub use blocking_presence::deliver_blocking_presence_change;
pub use pushes::{blocking_push_stanza, push_blocklist_change, push_privacy_change};

pub const BLOCKING_PUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Node-owned routes for committed block-list, privacy-list and blocking-presence changes.
pub trait RosterFanoutRoutes: Send + Sync {
    fn fanout_sessions(&self, jid: &str) -> Vec<(String, OnlineSession)>;
    fn fanout_local_domain(&self) -> &str;
    fn record_fanout_failure(&self);
    fn remote_blocklist_push(
        &self,
        owner: &str,
        push: impl FnMut() -> String + Send,
    ) -> impl Future<Output = Result<Vec<RemoteRouteFailure>>> + Send;
    fn remote_blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) -> impl Future<Output = Result<Vec<RemoteRouteFailure>>> + Send;
    fn remote_privacy_push(
        &self,
        account: &str,
        base: &str,
    ) -> impl Future<Output = Result<Vec<RemoteRouteFailure>>> + Send;
    fn remote_resource_nodes(
        &self,
        target: &str,
    ) -> impl Future<Output = Result<Vec<String>>> + Send;
    fn send_available_presence_to_node(
        &self,
        node_id: &str,
        target: &str,
        delivery: &str,
    ) -> impl Future<Output = ()> + Send;
    fn external_presence_domain_allowed(&self, domain: &str) -> bool;
    fn send_federated_presence(
        &self,
        domain: &str,
        delivery: String,
        from: String,
    ) -> impl Future<Output = ()> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_stream::local_routes::session::test_online_session;
    use northstar_xml_builder::rewrite::set_to;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Debug, PartialEq)]
    enum RemoteCall {
        Blocklist(String),
        BlockingPresence(String, Vec<String>, Vec<String>, bool),
        Privacy(String, String),
        ResourceNodes(String),
        NodePresence(String, String, String),
        DomainPolicy(String),
        FederatedPresence(String, String, String),
    }

    #[derive(Default)]
    struct Routes {
        request_push: bool,
        remote_pushes: Mutex<Vec<String>>,
        sessions: Vec<(String, OnlineSession)>,
        failures: AtomicU64,
        calls: Mutex<Vec<RemoteCall>>,
        nodes: Vec<String>,
        allowed_domains: Vec<String>,
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

        fn fanout_local_domain(&self) -> &str {
            "example.test"
        }

        fn record_fanout_failure(&self) {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }

        async fn remote_blocklist_push(
            &self,
            owner: &str,
            mut push: impl FnMut() -> String + Send,
        ) -> Result<Vec<RemoteRouteFailure>> {
            assert_eq!(owner, "alice@example.test");
            self.calls
                .lock()
                .unwrap()
                .push(RemoteCall::Blocklist(owner.to_owned()));
            if self.request_push {
                self.remote_pushes.lock().unwrap().push(push());
            }
            Ok(Vec::new())
        }

        async fn remote_blocking_presence_change(
            &self,
            owner: &str,
            targets: &[String],
            changed_patterns: &[String],
            available: bool,
        ) -> Result<Vec<RemoteRouteFailure>> {
            self.calls
                .lock()
                .unwrap()
                .push(RemoteCall::BlockingPresence(
                    owner.to_owned(),
                    targets.to_vec(),
                    changed_patterns.to_vec(),
                    available,
                ));
            Ok(Vec::new())
        }

        async fn remote_privacy_push(
            &self,
            account: &str,
            base: &str,
        ) -> Result<Vec<RemoteRouteFailure>> {
            self.calls
                .lock()
                .unwrap()
                .push(RemoteCall::Privacy(account.to_owned(), base.to_owned()));
            Ok(Vec::new())
        }

        async fn remote_resource_nodes(&self, target: &str) -> Result<Vec<String>> {
            self.calls
                .lock()
                .unwrap()
                .push(RemoteCall::ResourceNodes(target.to_owned()));
            Ok(self.nodes.clone())
        }

        async fn send_available_presence_to_node(
            &self,
            node_id: &str,
            target: &str,
            delivery: &str,
        ) {
            self.calls.lock().unwrap().push(RemoteCall::NodePresence(
                node_id.to_owned(),
                target.to_owned(),
                delivery.to_owned(),
            ));
        }

        fn external_presence_domain_allowed(&self, domain: &str) -> bool {
            self.calls
                .lock()
                .unwrap()
                .push(RemoteCall::DomainPolicy(domain.to_owned()));
            self.allowed_domains.iter().any(|allowed| allowed == domain)
        }

        async fn send_federated_presence(&self, domain: &str, delivery: String, from: String) {
            self.calls
                .lock()
                .unwrap()
                .push(RemoteCall::FederatedPresence(
                    domain.to_owned(),
                    delivery,
                    from,
                ));
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
            push_blocklist_change(&routes, "alice@example.test", payload, Uuid::new_v4).await;
            let push = interested_rx.try_recv().unwrap().stanza;
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
            push_blocklist_change(
                &routes,
                "alice@example.test",
                "<block xmlns='urn:xmpp:blocking'/>",
                Uuid::new_v4,
            )
            .await;
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
            push_blocklist_change(
                &routes,
                "alice@example.test",
                "<block xmlns='urn:xmpp:blocking'/>",
                Uuid::new_v4,
            )
            .await;
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
                "alice@example.test",
                "work",
                base,
                current.connection_id,
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
                push_privacy_change(&routes, "alice@example.test", "work", base, Uuid::new_v4())
                    .await,
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
            let (owner, _owner_rx) = session("source");
            owner.available.store(true, Ordering::Release);
            owner.directed_presence.insert("bob@example.test".into());
            owner
                .directed_presence
                .insert("carol@example.test/Phone".into());
            owner
                .directed_presence
                .insert("dave@example.test/Phone".into());
            let (unavailable_owner, _unavailable_owner_rx) = session("unavailable-source");
            unavailable_owner
                .directed_presence
                .insert("dave@example.test/Phone".into());
            let (bob, mut bob_rx) = session("bob");
            bob.available.store(true, Ordering::Release);
            let (carol, mut carol_rx) = session("Phone");
            let (dave, mut dave_rx) = session("Phone");
            let routes = Routes {
                sessions: vec![
                    ("alice@example.test/source".into(), owner),
                    (
                        "alice@example.test/unavailable-source".into(),
                        unavailable_owner,
                    ),
                    ("bob@example.test/Desktop".into(), bob),
                    ("carol@example.test/Phone".into(), carol),
                    ("dave@example.test/Phone".into(), dave),
                ],
                ..Routes::default()
            };
            let targets = vec!["bob@example.test".into()];
            let patterns = vec!["bob@example.test".into(), "carol@example.test/Phone".into()];
            deliver_blocking_presence_change(
                &routes,
                "alice@example.test",
                &targets,
                &patterns,
                false,
            )
            .await;
            for (target, receiver) in [
                ("bob@example.test", &mut bob_rx),
                ("carol@example.test/Phone", &mut carol_rx),
            ] {
                let stanza = receiver.try_recv().unwrap().stanza;
                let document = roxmltree::Document::parse(&stanza).unwrap();
                let presence = document.root_element();
                assert_eq!(presence.attribute("to"), Some(target));
                assert_eq!(
                    presence.attribute("from"),
                    Some("alice@example.test/source")
                );
                assert_eq!(presence.attribute("type"), Some("unavailable"));
                assert!(receiver.try_recv().is_err());
            }
            assert!(dave_rx.try_recv().is_err());
            let calls = routes.calls.lock().unwrap();
            assert_eq!(calls.len(), 3);
            for target in ["bob@example.test", "carol@example.test/Phone"] {
                assert!(calls.contains(&RemoteCall::ResourceNodes(target.into())));
            }
            assert_eq!(
                calls.last(),
                Some(&RemoteCall::BlockingPresence(
                    "alice@example.test".into(),
                    targets,
                    patterns,
                    false,
                ))
            );
            assert_eq!(routes.failures.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn blocking_presence_local_bare_target_skips_unavailable_recipients_and_routes_remote_nodes() {
        run(async {
            let (owner, _owner_rx) = session("source");
            owner.available.store(true, Ordering::Release);
            let base = "<presence from='alice@example.test/source'><show>away</show><status>Lunch</status></presence>";
            *owner.last_presence.write().unwrap() = Some(base.into());
            let (available, mut available_rx) = session("available");
            available.available.store(true, Ordering::Release);
            let (unavailable, mut unavailable_rx) = session("unavailable");
            let routes = Routes {
                sessions: vec![
                    ("alice@example.test/source".into(), owner),
                    ("bob@example.test/available".into(), available),
                    ("bob@example.test/unavailable".into(), unavailable),
                ],
                nodes: vec!["node-a".into(), "node-b".into()],
                ..Routes::default()
            };
            let targets = vec!["bob@example.test".into()];
            let patterns = vec!["bob@example.test".into()];
            deliver_blocking_presence_change(
                &routes,
                "alice@example.test",
                &targets,
                &patterns,
                true,
            )
            .await;
            let delivery = set_to(base, "bob@example.test");
            let queued = available_rx.try_recv().unwrap().stanza;
            assert_eq!(queued, delivery);
            assert_to(&queued, "bob@example.test");
            assert!(available_rx.try_recv().is_err());
            assert!(unavailable_rx.try_recv().is_err());
            assert_eq!(
                *routes.calls.lock().unwrap(),
                vec![
                    RemoteCall::ResourceNodes("bob@example.test".into()),
                    RemoteCall::NodePresence(
                        "node-a".into(),
                        "bob@example.test".into(),
                        delivery.clone(),
                    ),
                    RemoteCall::NodePresence("node-b".into(), "bob@example.test".into(), delivery,),
                    RemoteCall::BlockingPresence(
                        "alice@example.test".into(),
                        targets,
                        patterns,
                        true,
                    ),
                ]
            );
            assert_eq!(routes.failures.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn blocking_presence_remote_domain_requires_policy() {
        run(async {
            for allowed in [false, true] {
                let (owner, _owner_rx) = session("source");
                owner.available.store(true, Ordering::Release);
                let base =
                    "<presence from='alice@example.test/source'><status>Here</status></presence>";
                *owner.last_presence.write().unwrap() = Some(base.into());
                let routes = Routes {
                    sessions: vec![("alice@example.test/source".into(), owner)],
                    allowed_domains: if allowed {
                        vec!["remote.test".into()]
                    } else {
                        Vec::new()
                    },
                    ..Routes::default()
                };
                let targets = vec!["bob@remote.test/Phone".into()];
                let patterns = vec!["remote.test".into()];
                deliver_blocking_presence_change(
                    &routes,
                    "alice@example.test",
                    &targets,
                    &patterns,
                    true,
                )
                .await;
                let mut expected = vec![RemoteCall::DomainPolicy("remote.test".into())];
                if allowed {
                    let delivery = set_to(base, "bob@remote.test/Phone");
                    assert_to(&delivery, "bob@remote.test/Phone");
                    expected.push(RemoteCall::FederatedPresence(
                        "remote.test".into(),
                        delivery,
                        "alice@example.test/source".into(),
                    ));
                }
                expected.push(RemoteCall::BlockingPresence(
                    "alice@example.test".into(),
                    targets,
                    patterns,
                    true,
                ));
                assert_eq!(*routes.calls.lock().unwrap(), expected);
                assert_eq!(routes.failures.load(Ordering::Relaxed), 0);
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
                // Constructing a stanza with this payload would panic. The
                // remote route ignores the closure, so it must stay unbuilt.
                push_blocklist_change(&routes, "alice@example.test", "<unblock", Uuid::new_v4)
                    .await;
                assert!(routes.remote_pushes.lock().unwrap().is_empty());

                let routes = Routes {
                    request_push: true,
                    ..Routes::default()
                };
                let payload = "<unblock xmlns='urn:xmpp:blocking'/>";
                push_blocklist_change(&routes, "alice@example.test", payload, Uuid::new_v4).await;
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

    mod push_ids;
}
