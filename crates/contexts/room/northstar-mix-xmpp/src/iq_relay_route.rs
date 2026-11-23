//! Local and federated delivery of relayed MIX IQ responses.

use crate::ports::{MixFederationPolicy, MixIqRelayRoutePort};
use dashmap::DashMap;
use northstar_federation_core::FederationRoute;
use northstar_room_core::mix_iq_relay::RelayReturnRoute;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::local_routes::session_table::session_entries_for_in;
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use std::sync::{atomic::Ordering, Arc};

pub struct MixIqRelayRoute<F, P> {
    sessions: Arc<DashMap<String, OnlineSession>>,
    local_domain: String,
    policy: P,
    federation: F,
}

impl<F, P> MixIqRelayRoute<F, P> {
    pub fn new(
        sessions: Arc<DashMap<String, OnlineSession>>,
        local_domain: String,
        policy: P,
        federation: F,
    ) -> Self {
        Self {
            sessions,
            local_domain,
            policy,
            federation,
        }
    }
}

impl<F: FederationRoute, P: MixFederationPolicy> MixIqRelayRoutePort for MixIqRelayRoute<F, P> {
    async fn deliver(&self, recipient: &str, stanza: String) {
        let Ok(recipient_jid) = CanonicalJid::parse(recipient) else {
            return;
        };
        let domain = recipient_jid.domainpart();
        let Ok(domain) = prepare_domainpart(domain) else {
            return;
        };
        if domain == self.local_domain {
            for (_, target) in session_entries_for_in(&self.sessions, recipient) {
                let _ = target.sender.try_send(stanza.clone());
            }
        } else if self.policy.prepared_domain_allowed(&domain) {
            let _ = self.federation.send(&domain, stanza, None).await;
        }
    }

    async fn deliver_return(&self, route: &RelayReturnRoute, stanza: String) {
        match route {
            RelayReturnRoute::Local {
                jid,
                account,
                auth_generation,
                connection,
            } => {
                let Some(current) = self.sessions.get(&jid.to_string()) else {
                    return;
                };
                if current.connection_id == *connection
                    && current.user_id == *account
                    && current.auth_generation == *auth_generation
                    && current.routable.load(Ordering::Acquire)
                {
                    let _ = current.sender.try_send(stanza);
                }
            }
            RelayReturnRoute::Federated(jid) => {
                let domain = jid.domainpart();
                if domain != self.local_domain && self.policy.prepared_domain_allowed(domain) {
                    let _ = self.federation.send(domain, stanza, None).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_federation_core::{FederationOutboxAdmission, S2sOutboxPolicy};
    use northstar_stream::local_routes::session::test_online_session;
    use std::sync::Mutex;
    use uuid::Uuid;

    type Sends = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

    struct FakeFederation {
        sends: Sends,
        succeeds: bool,
    }

    impl FederationOutboxAdmission for FakeFederation {
        async fn admit(&self, _target_domain: &str, _stanza: String) -> bool {
            panic!("IQ relay delivery must use send")
        }
    }

    impl FederationRoute for FakeFederation {
        fn outbox_policy(&self) -> S2sOutboxPolicy {
            S2sOutboxPolicy::new(0, 0, 0, 0)
        }

        fn wake_outbox(&self) {
            panic!("IQ relay delivery must use send");
        }

        async fn send(
            &self,
            target_domain: &str,
            stanza: String,
            bounce_to: Option<String>,
        ) -> bool {
            self.sends
                .lock()
                .unwrap()
                .push((target_domain.into(), stanza, bounce_to));
            self.succeeds
        }
    }

    struct PolicyFlag(bool);

    impl MixFederationPolicy for PolicyFlag {
        fn prepared_domain_allowed(&self, _domain: &str) -> bool {
            self.0
        }
    }

    fn route(
        sessions: Arc<DashMap<String, OnlineSession>>,
        allowed: bool,
        succeeds: bool,
    ) -> (MixIqRelayRoute<FakeFederation, PolicyFlag>, Sends) {
        let sends = Sends::default();
        (
            MixIqRelayRoute::new(
                sessions,
                "example.test".into(),
                PolicyFlag(allowed),
                FakeFederation {
                    sends: Arc::clone(&sends),
                    succeeds,
                },
            ),
            sends,
        )
    }

    #[tokio::test]
    async fn iq_relay_invalid_jid_sends_nothing() {
        let sessions = Arc::new(DashMap::new());
        let (session, mut receiver) =
            test_online_session(Uuid::new_v4(), 1, Uuid::new_v4(), "one", 1);
        sessions.insert("alice@example.test/one".into(), session);
        let (route, sends) = route(sessions, true, true);
        for recipient in ["", "@example.test", "alice@bad domain"] {
            route.deliver(recipient, "<iq/>".into()).await;
        }
        assert!(receiver.try_recv().is_err());
        assert!(sends.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn iq_relay_local_bare_jid_delivers_to_every_resource() {
        let sessions = Arc::new(DashMap::new());
        let mut receivers = Vec::new();
        for resource in ["one", "two"] {
            let (session, receiver) =
                test_online_session(Uuid::new_v4(), 1, Uuid::new_v4(), resource, 1);
            sessions.insert(format!("alice@example.test/{resource}"), session);
            receivers.push(receiver);
        }
        let (route, sends) = route(sessions, false, true);
        route.deliver("alice@example.test", "<iq/>".into()).await;
        for receiver in &mut receivers {
            assert_eq!(receiver.try_recv().unwrap().stanza, "<iq/>");
            assert!(receiver.try_recv().is_err());
        }
        assert!(sends.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn iq_relay_local_full_jid_delivers_only_to_that_resource() {
        let sessions = Arc::new(DashMap::new());
        let (one, mut one_receiver) =
            test_online_session(Uuid::new_v4(), 1, Uuid::new_v4(), "one", 1);
        let (two, mut two_receiver) =
            test_online_session(Uuid::new_v4(), 1, Uuid::new_v4(), "two", 1);
        sessions.insert("alice@example.test/one".into(), one);
        sessions.insert("alice@example.test/two".into(), two);
        let (route, sends) = route(sessions, true, true);
        route
            .deliver("alice@example.test/two", "<iq/>".into())
            .await;
        assert!(one_receiver.try_recv().is_err());
        assert_eq!(two_receiver.try_recv().unwrap().stanza, "<iq/>");
        assert!(two_receiver.try_recv().is_err());
        assert!(sends.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn iq_relay_full_or_closed_channel_does_not_stop_other_resources() {
        for closed in [false, true] {
            let sessions = Arc::new(DashMap::new());
            let mut receivers = Vec::new();
            for resource in ["one", "two", "three"] {
                let (session, receiver) =
                    test_online_session(Uuid::new_v4(), 1, Uuid::new_v4(), resource, 1);
                sessions.insert(format!("alice@example.test/{resource}"), session);
                receivers.push((resource, receiver));
            }
            // Fail the first resource in this table's traversal so successful
            // delivery also proves that fanout continued after the failure.
            let targets = session_entries_for_in(&sessions, "alice@example.test");
            let failed_resource = targets[0].1.resource.clone();
            let failed_index = receivers
                .iter()
                .position(|(resource, _)| *resource == failed_resource)
                .unwrap();
            let (_, mut failed_receiver) = receivers.remove(failed_index);
            if closed {
                failed_receiver.close();
            } else {
                targets[0].1.sender.try_send("occupied".into()).unwrap();
            }
            let (route, sends) = route(sessions, true, true);
            route.deliver("alice@example.test", "<iq/>".into()).await;
            for (_, receiver) in &mut receivers {
                assert_eq!(receiver.try_recv().unwrap().stanza, "<iq/>");
                assert!(receiver.try_recv().is_err());
            }
            if !closed {
                assert_eq!(failed_receiver.try_recv().unwrap().stanza, "occupied");
            }
            assert!(failed_receiver.try_recv().is_err());
            assert!(sends.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn iq_relay_remote_allowed_sends_once_without_bounce() {
        let (route, sends) = route(Arc::new(DashMap::new()), true, true);
        route.deliver("alice@REMOTE.TEST/one", "<iq/>".into()).await;
        assert_eq!(
            *sends.lock().unwrap(),
            vec![("remote.test".into(), "<iq/>".into(), None)],
        );
    }

    #[tokio::test]
    async fn iq_relay_remote_denied_sends_nothing() {
        let (route, sends) = route(Arc::new(DashMap::new()), false, true);
        route.deliver("alice@remote.test", "<iq/>".into()).await;
        assert!(sends.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn iq_relay_failing_federation_send_is_ignored() {
        let (route, sends) = route(Arc::new(DashMap::new()), true, false);
        route.deliver("alice@remote.test", "<iq/>".into()).await;
        assert_eq!(
            *sends.lock().unwrap(),
            vec![("remote.test".into(), "<iq/>".into(), None)],
        );
    }

    #[tokio::test]
    async fn relay_reply_stays_on_the_exact_local_connection() {
        let sessions = Arc::new(DashMap::new());
        let jid = "alice@example.test/phone";
        let account = Uuid::new_v4();
        let connection = Uuid::new_v4();
        let (original, mut original_receiver) =
            test_online_session(account, 1, connection, "phone", 2);
        sessions.insert(jid.to_owned(), original);
        let (route, sends) = route(Arc::clone(&sessions), true, true);
        let admitted = RelayReturnRoute::Local {
            jid: CanonicalJid::parse(jid).unwrap(),
            account,
            auth_generation: 1,
            connection,
        };
        route.deliver_return(&admitted, "<iq/>".into()).await;
        assert_eq!(original_receiver.try_recv().unwrap().stanza, "<iq/>");

        let (replacement, mut replacement_receiver) =
            test_online_session(account, 1, Uuid::new_v4(), "phone", 2);
        sessions.insert(jid.to_owned(), replacement);
        route.deliver_return(&admitted, "<iq/>".into()).await;
        assert!(original_receiver.try_recv().is_err());
        assert!(replacement_receiver.try_recv().is_err());
        assert!(sends.lock().unwrap().is_empty());
    }
}
