use super::super::{
    ordinary::dispatch_ordinary_presence, probe::route_inbound_presence_probe,
    transition::forward_committed_subscription,
};
use crate::{FederatedPresenceEffect, FederatedPresenceHandoff, FederatedPresenceOwnerHost};
use anyhow::Result;
use northstar_roster_application::probe_decision::{PresenceRoute, ProbeStatus};
use northstar_roster_core::{ExactPresenceRoute, PresenceAccount};
use northstar_stream::local_routes::{
    pending_subscription::{deliver_pending_subscription, PendingSubscriptionKey},
    session::{test_online_session, OnlineSession},
};
use northstar_stream::outbound::OutboundItem;
use roxmltree::Document;
use std::sync::{atomic::Ordering, Mutex};
use tokio::sync::mpsc;
use uuid::Uuid;

const TARGET: &str = "bob@local.test";
const SENDER: &str = "alice@remote.test/Phone";
const PEER: &str = "remote.test";
const PROBE: &str =
    "<presence type='probe' id='probe' from='alice@remote.test/Phone' to='bob@local.test'/>";
const SUBSCRIBE: &str = "<presence type='subscribe' from='alice@remote.test' to='bob@local.test'/>";
const AVAILABLE: &str =
    "<presence from='alice@remote.test/Phone' to='bob@local.test'><status>ready</status></presence>";

struct OwnerHost {
    account: PresenceAccount,
    routes: Vec<PresenceRoute>,
    resources: Vec<OnlineSession>,
    status: Option<ProbeStatus>,
    handed_off: Mutex<Vec<(String, Uuid)>>,
}

impl OwnerHost {
    fn new(
        resources: &[&str],
        status: Option<ProbeStatus>,
    ) -> (Self, Vec<mpsc::Receiver<OutboundItem>>) {
        let account = PresenceAccount {
            id: Uuid::new_v4(),
            auth_generation: 7,
            username: "bob".to_owned(),
        };
        let mut host = Self {
            account,
            routes: Vec::new(),
            resources: Vec::new(),
            status,
            handed_off: Mutex::default(),
        };
        let mut output = Vec::new();
        for resource in resources {
            let connection_id = Uuid::new_v4();
            host.routes.push(PresenceRoute {
                exact: ExactPresenceRoute {
                    account_id: host.account.id,
                    auth_generation: host.account.auth_generation,
                    connection_id,
                    full_jid: format!("{TARGET}/{resource}"),
                    node_id: Some("owner-node".to_owned()),
                },
                active_list: None,
            });
            let (session, receiver) = test_online_session(
                host.account.id,
                host.account.auth_generation,
                connection_id,
                resource,
                4,
            );
            session.available.store(true, Ordering::Release);
            host.resources.push(session);
            output.push(receiver);
        }
        (host, output)
    }
}

impl FederatedPresenceOwnerHost for OwnerHost {
    async fn capture_federated_presence(
        &self,
        target: &str,
        account: &PresenceAccount,
    ) -> Result<Vec<PresenceRoute>> {
        assert_eq!(target, TARGET);
        assert_eq!(account, &self.account);
        Ok(self.routes.clone())
    }

    async fn handoff_federated_presence(
        &self,
        account: &PresenceAccount,
        request: FederatedPresenceHandoff<'_>,
        routes: &[PresenceRoute],
    ) -> Result<Option<ProbeStatus>> {
        assert_eq!(account, &self.account);
        assert_eq!(request.remote_peer, PEER);
        for (route, session) in routes.iter().zip(&self.resources) {
            let node = route
                .exact
                .node_id
                .as_ref()
                .expect("ingress holds no local routes");
            self.handed_off
                .lock()
                .unwrap()
                .push((node.clone(), route.exact.connection_id));
            let enqueue = || session.sender.try_send(request.stanza.to_owned()).is_ok();
            match request.effect {
                FederatedPresenceEffect::Forward {
                    pending_created_at_micros: Some(micros),
                } => {
                    let key =
                        PendingSubscriptionKey::federated("alice@remote.test".to_owned(), micros);
                    deliver_pending_subscription(session, 0, key, enqueue);
                }
                FederatedPresenceEffect::Forward {
                    pending_created_at_micros: None,
                } => {
                    enqueue();
                }
                _ => unreachable!(),
            }
        }
        Ok(self.status)
    }
}

fn handoff(stanza: &str, effect: FederatedPresenceEffect) -> FederatedPresenceHandoff<'_> {
    FederatedPresenceHandoff {
        target: TARGET,
        sender: SENDER,
        remote_peer: PEER,
        stanza,
        effect,
    }
}

#[tokio::test]
async fn federated_presence_ingress_with_no_local_routes_hands_off_to_the_owner() {
    let (host, mut output) = OwnerHost::new(&["Tablet"], None);
    dispatch_ordinary_presence(
        &host,
        &host.account,
        handoff(
            AVAILABLE,
            FederatedPresenceEffect::Forward {
                pending_created_at_micros: None,
            },
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        *host.handed_off.lock().unwrap(),
        [("owner-node".to_owned(), host.routes[0].exact.connection_id)],
    );
    assert_eq!(output[0].try_recv().unwrap().stanza, AVAILABLE);
}

#[tokio::test]
async fn blocked_federated_probe_has_no_response() {
    let (host, _) = OwnerHost::new(&[], Some(ProbeStatus::Silent));
    let document = Document::parse(PROBE).unwrap();
    assert!(route_inbound_presence_probe(
        &host,
        document.root_element(),
        &host.account,
        TARGET,
        handoff(PROBE, FederatedPresenceEffect::Probe),
    )
    .await
    .unwrap()
    .is_none());
}

#[tokio::test]
async fn unauthorized_federated_probe_returns_unsubscribed() {
    let (host, _) = OwnerHost::new(&[], Some(ProbeStatus::Unsubscribed));
    let document = Document::parse(PROBE).unwrap();
    let response = route_inbound_presence_probe(
        &host,
        document.root_element(),
        &host.account,
        TARGET,
        handoff(PROBE, FederatedPresenceEffect::Probe),
    )
    .await
    .unwrap()
    .unwrap();
    let document = Document::parse(&response).unwrap();
    assert_eq!(
        document.root_element().attribute("type"),
        Some("unsubscribed")
    );
    assert_eq!(document.root_element().attribute("id"), Some("probe"));
}

#[tokio::test]
async fn subscription_handoff_shares_one_pending_identity_per_resource() {
    let (host, mut output) = OwnerHost::new(&["Tablet", "Laptop"], None);
    let request = handoff(
        SUBSCRIBE,
        FederatedPresenceEffect::Forward {
            pending_created_at_micros: None,
        },
    );
    for _ in 0..2 {
        forward_committed_subscription(&host, &host.account, request, &host.routes, Some(123))
            .await
            .unwrap();
    }
    for receiver in &mut output {
        assert_eq!(receiver.try_recv().unwrap().stanza, SUBSCRIBE);
        assert!(receiver.try_recv().is_err());
    }
}
