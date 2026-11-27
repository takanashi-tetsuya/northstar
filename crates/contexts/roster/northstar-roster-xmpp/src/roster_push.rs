//! Delivery of committed roster pushes and roster-removal presence.

use crate::roster::{roster_change_item_element, roster_push_xml};
use anyhow::Result;
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_application::RosterPushDisposition;
use northstar_roster_core::{
    ClusterPresenceAuthority, ExactPresenceRoute, RosterChange, RosterEventSource, RosterVersion,
};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_xml_builder::rewrite::set_to;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use uuid::Uuid;

mod routes;
pub use self::routes::RosterPushRoutes;

/// Node-owned session and cluster delivery capabilities for committed roster pushes.
pub trait RosterPushDeliveryPorts: RosterPushRoutes + Send + Sync + 'static {
    type LocalSession;

    fn local_sessions(&self, jid: &str) -> Vec<(String, Self::LocalSession)>;
    fn send_roster_push(
        &self,
        node_id: &str,
        account: &str,
        owner: (Uuid, i64),
        routes: &BTreeMap<String, Uuid>,
        version: RosterVersion,
        pushes: (&str, Option<&str>),
    ) -> impl Future<Output = Result<bool>> + Send;
}

pub struct RemoteRouteFailure {
    pub node_id: String,
    pub error: anyhow::Error,
}

pub enum RemoteRosterPushFailure {
    NotAccepted { node_id: String },
    Delivery(RemoteRouteFailure),
}

pub struct RosterPushDelivery<P> {
    ports: P,
    post_accept_failures: Arc<AtomicU64>,
    domain: String,
}

impl<P: RosterPushDeliveryPorts> RosterPushDelivery<P> {
    pub fn new(ports: P, post_accept_failures: Arc<AtomicU64>, domain: String) -> Self {
        Self {
            ports,
            post_accept_failures,
            domain,
        }
    }

    pub fn local_domain(&self) -> &str {
        &self.domain
    }

    pub fn record_failure(&self) {
        self.post_accept_failures.fetch_add(1, Ordering::Relaxed);
    }

    async fn route_remote_push(
        &self,
        account: &str,
        owner: (Uuid, i64),
        captured: Vec<ExactPresenceRoute>,
        version: RosterVersion,
        pushes: (&str, Option<&str>),
    ) -> Vec<RemoteRosterPushFailure> {
        let mut failures = Vec::new();
        let mut by_node = BTreeMap::<_, BTreeMap<_, _>>::new();
        for route in captured {
            if let Some(node_id) = route
                .node_id
                .filter(|_| (route.account_id, route.auth_generation) == owner)
            {
                by_node
                    .entry(node_id)
                    .or_default()
                    .insert(route.full_jid, route.connection_id);
            }
        }
        for (node_id, routes) in by_node {
            match self
                .ports
                .send_roster_push(&node_id, account, owner, &routes, version, pushes)
                .await
            {
                Ok(true) => {}
                Ok(false) => failures.push(RemoteRosterPushFailure::NotAccepted { node_id }),
                Err(error) => {
                    failures.push(RemoteRosterPushFailure::Delivery(RemoteRouteFailure {
                        node_id,
                        error,
                    }))
                }
            }
        }
        failures
    }
}

pub async fn deliver_committed_roster_change<P>(
    delivery: &RosterPushDelivery<P>,
    owner_id: Uuid,
    owner: &str,
    change: &RosterChange,
    participant_id: Option<&str>,
    events: &dyn RosterEventSource,
) -> Result<()>
where
    P: RosterPushDeliveryPorts<LocalSession = OnlineSession>,
{
    let Some(authority @ (committed_owner, generation)) = change.owner_authority else {
        delivery.record_failure();
        tracing::warn!(%owner_id, version = change.version, "roster push lacks commit-time account authority");
        return Ok(());
    };
    if owner_id != committed_owner {
        delivery.record_failure();
        return Ok(());
    }
    let item = roster_change_item_element(change, None);
    let annotated = participant_id
        .map(|participant_id| roster_change_item_element(change, Some(participant_id)));
    let owner_jid = format!("{}@{}", owner, delivery.local_domain());
    let local = delivery
        .ports
        .local_sessions(&owner_jid)
        .into_iter()
        .filter(|(_, session)| {
            session.user_id == owner_id
                && session.auth_generation == generation
                && session.roster_requested.load(Ordering::Acquire)
        })
        .map(|(jid, session)| (jid, session.connection_id))
        .collect::<Vec<_>>();
    let remote = delivery
        .ports
        .capture_remote_roster_routes(&owner_jid, authority)
        .await;
    for (target_jid, connection_id) in local {
        let plain_push = roster_push_xml(
            &owner_jid,
            &target_jid,
            change.version,
            item.clone(),
            events.new_protocol_id(),
        );
        let annotated_push = annotated.as_ref().map(|annotated| {
            roster_push_xml(
                &owner_jid,
                &target_jid,
                change.version,
                annotated.clone(),
                events.new_protocol_id(),
            )
        });
        let _ = delivery.ports.with_local_roster_session(&target_jid, |target| {
            if target.user_id != owner_id || target.auth_generation != generation
                || target.connection_id != connection_id || !target.routable.load(Ordering::Acquire)
                || target.disconnect.is_cancelled()
            {
                return;
            }
            if target.roster_sync.route(
                &target.roster_requested,
                &target.mix_roster_annotations,
                change.version,
                plain_push,
                annotated_push,
                |stanza| !target.disconnect.is_cancelled() && target.sender.try_send(stanza).is_ok(),
            ) == RosterPushDisposition::Resync {
                target.sender.disconnect_backpressured_transport();
                target.disconnect.cancel();
                delivery.record_failure();
                tracing::warn!(owner = %owner_jid, target = %target_jid, version = change.version, "committed roster push could not be admitted in order; forcing a full resync");
            }
        });
    }
    // The immutable journal snapshot and exact committed version cross node
    // boundaries together; remote resources add their exact full-JID target.
    let push = roster_push_xml(
        &owner_jid,
        &owner_jid,
        change.version,
        item,
        events.new_protocol_id(),
    );
    let annotated_push = annotated.map(|annotated| {
        roster_push_xml(
            &owner_jid,
            &owner_jid,
            change.version,
            annotated,
            events.new_protocol_id(),
        )
    });
    match remote {
        Ok(routes) => {
            let failures = delivery
                .route_remote_push(
                    &owner_jid,
                    authority,
                    routes,
                    RosterVersion(change.version),
                    (&push, annotated_push.as_deref()),
                )
                .await;
            for failure in failures {
                delivery.record_failure();
                match failure {
                    RemoteRosterPushFailure::NotAccepted { node_id } => {
                        tracing::warn!(owner = %owner_jid, remote_node = %node_id, version = change.version, "committed roster push was not accepted by the remote node; roster version recovery remains authoritative");
                    }
                    RemoteRosterPushFailure::Delivery(failure) => {
                        tracing::warn!(owner = %owner_jid, remote_node = %failure.node_id, version = change.version, error=?failure.error, "committed roster push failed across the cluster; roster version recovery remains authoritative");
                    }
                }
            }
        }
        Err(error) => {
            delivery.record_failure();
            tracing::warn!(owner = %owner_jid, version = change.version, ?error, "could not discover remote resources for a committed roster push; roster version recovery remains authoritative");
        }
    }
    Ok(())
}

/// Node-owned routes for the presence that follows a roster removal.
pub trait RosterRemovalPresenceRoutes: Send + Sync {
    fn removal_presence_sessions(&self, target_bare: &str) -> Vec<(String, OnlineSession)>;
    fn removal_presence_privacy_allows(
        &self,
        session: &OnlineSession,
        owner_bare: &str,
        kind: PrivacyStanzaKind,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn route_remote_removal_presence(
        &self,
        target_bare: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
    ) -> impl Future<Output = ()> + Send;
}

pub async fn deliver_roster_removal_presence(
    routes: &impl RosterRemovalPresenceRoutes,
    owner_id: Uuid,
    owner_auth_generation: i64,
    recipient_id: Uuid,
    recipient_auth_generation: i64,
    target_bare: &str,
    stanza: &str,
) {
    let Some(owner_bare) = roxmltree::Document::parse(stanza)
        .ok()
        .and_then(|document| {
            document
                .root_element()
                .attribute("from")
                .and_then(|value| northstar_xmpp_types::jid::canonicalize_bare(value).ok())
        })
    else {
        // This is an internally constructed stanza. A malformed source must
        // fail closed instead of bypassing the recipient resource's active
        // XEP-0016 list.
        return;
    };
    for (target_full, session) in routes.removal_presence_sessions(target_bare) {
        // RFC 6121 section 2.2 distinguishes an "available resource" from
        // an "interested resource".  Subscription-related presence is sent
        // to every available resource; only the roster push which follows it
        // is restricted to resources that requested the roster.
        if session.user_id == recipient_id
            && session.auth_generation == recipient_auth_generation
            && session.available.load(Ordering::Acquire)
            && routes
                .removal_presence_privacy_allows(
                    &session,
                    &owner_bare,
                    PrivacyStanzaKind::PresenceIn,
                )
                .await
                .unwrap_or(false)
        {
            let _ = session.sender.try_send(set_to(stanza, &target_full));
        }
    }
    routes
        .route_remote_removal_presence(
            target_bare,
            stanza,
            ClusterPresenceAuthority {
                owner_id,
                owner_auth_generation,
                recipient_id,
                recipient_auth_generation,
            },
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_stream::local_routes::session::test_online_session;
    use std::sync::Mutex;

    fn run(future: impl Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future);
    }

    #[derive(Default)]
    struct PushPorts {
        lookup_error: bool,
        sessions: Vec<(String, OnlineSession)>,
        nodes: Vec<String>,
        sent_nodes: Mutex<Vec<String>>,
        capture_pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
        replacement: Arc<Mutex<Option<(String, OnlineSession)>>>,
    }

    impl RosterPushDeliveryPorts for PushPorts {
        type LocalSession = OnlineSession;

        fn local_sessions(&self, jid: &str) -> Vec<(String, OnlineSession)> {
            assert_eq!(jid, "alice@example.test");
            self.sessions.clone()
        }

        async fn send_roster_push(
            &self,
            node_id: &str,
            account: &str,
            owner: (Uuid, i64),
            routes: &BTreeMap<String, Uuid>,
            version: RosterVersion,
            (push, annotated_push): (&str, Option<&str>),
        ) -> Result<bool> {
            assert_eq!(account, "alice@example.test");
            assert_eq!(owner, (Uuid::from_u128(1), 7));
            assert_eq!(version, RosterVersion(42));
            assert_eq!(
                routes,
                &BTreeMap::from([(format!("{account}/{node_id}"), Uuid::from_u128(19),)])
            );
            for (stanza, annotated) in [(push, false), (annotated_push.unwrap(), true)] {
                let document = roxmltree::Document::parse(stanza).unwrap();
                let iq = document.root_element();
                assert_eq!(iq.attribute("from"), Some(account));
                assert_eq!(iq.attribute("to"), Some(account));
                let query = iq
                    .children()
                    .find(|node| node.has_tag_name(("jabber:iq:roster", "query")))
                    .unwrap();
                assert_eq!(query.attribute("ver"), Some("42"));
                let item = query
                    .children()
                    .find(|node| node.has_tag_name(("jabber:iq:roster", "item")))
                    .unwrap();
                assert_eq!(item.attribute("jid"), Some("room@mix.example.test"));
                let channel = item
                    .children()
                    .find(|node| node.has_tag_name(("urn:xmpp:mix:roster:0", "channel")));
                if annotated {
                    assert_eq!(
                        channel.unwrap().attribute("participant-id"),
                        Some("opaque-id")
                    );
                } else {
                    assert!(channel.is_none());
                }
            }
            self.sent_nodes.lock().unwrap().push(node_id.to_owned());
            match node_id {
                "rejected" => Ok(false),
                "failed" => anyhow::bail!("delivery failed"),
                "accepted" => Ok(true),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn remote_push_failures_and_lookup_error_each_count_once() {
        run(async {
            let change = RosterChange {
                version: 42,
                contact_jid: "room@mix.example.test".into(),
                display_name: None,
                subscription: Some("both".into()),
                ask: None,
                groups: Vec::new(),
                approved: false,
                removed: false,
                owner_authority: Some((Uuid::from_u128(1), 7)),
            };
            for (lookup_error, expected_failures) in [(false, 2), (true, 1)] {
                let failures = Arc::new(AtomicU64::new(0));
                let delivery = RosterPushDelivery::new(
                    PushPorts {
                        lookup_error,
                        nodes: vec!["rejected".into(), "failed".into(), "accepted".into()],
                        ..PushPorts::default()
                    },
                    Arc::clone(&failures),
                    "example.test".into(),
                );
                assert!(deliver_committed_roster_change(
                    &delivery,
                    Uuid::from_u128(1),
                    "alice",
                    &change,
                    Some("opaque-id"),
                    &northstar_roster_application::SystemRosterEvents,
                )
                .await
                .is_ok());
                assert_eq!(failures.load(Ordering::Relaxed), expected_failures);
                let expected_nodes: Vec<String> = if lookup_error {
                    Vec::new()
                } else {
                    vec!["accepted".into(), "failed".into(), "rejected".into()]
                };
                assert_eq!(*delivery.ports.sent_nodes.lock().unwrap(), expected_nodes);
            }
        });
    }

    #[derive(Debug, PartialEq)]
    enum RemovalEvent {
        Local(String),
        Remote(String, String, ClusterPresenceAuthority),
    }

    #[derive(Default)]
    struct RemovalRoutes {
        events: Mutex<Vec<RemovalEvent>>,
        sessions: Vec<(String, OnlineSession)>,
        privacy_calls: Mutex<Vec<(String, String, PrivacyStanzaKind)>>,
    }

    impl RosterRemovalPresenceRoutes for RemovalRoutes {
        fn removal_presence_sessions(&self, target_bare: &str) -> Vec<(String, OnlineSession)> {
            self.events
                .lock()
                .unwrap()
                .push(RemovalEvent::Local(target_bare.to_owned()));
            self.sessions.clone()
        }

        async fn removal_presence_privacy_allows(
            &self,
            session: &OnlineSession,
            owner_bare: &str,
            kind: PrivacyStanzaKind,
        ) -> Result<bool> {
            self.privacy_calls.lock().unwrap().push((
                session.resource.clone(),
                owner_bare.to_owned(),
                kind,
            ));
            match session.resource.as_str() {
                "denied" => Ok(false),
                "privacy-error" => anyhow::bail!("privacy lookup failed"),
                _ => Ok(true),
            }
        }

        async fn route_remote_removal_presence(
            &self,
            target_bare: &str,
            stanza: &str,
            authority: ClusterPresenceAuthority,
        ) {
            self.events.lock().unwrap().push(RemovalEvent::Remote(
                target_bare.to_owned(),
                stanza.to_owned(),
                authority,
            ));
        }
    }

    #[test]
    fn removal_presence_with_malformed_from_sends_nothing_and_skips_remote() {
        run(async {
            let routes = RemovalRoutes::default();
            for stanza in [
                "<presence",
                "<presence/>",
                "<presence from=''/>",
                "<presence from='alice@example.test/Phone'/>",
                "<presence from='alice@bad domain'/>",
            ] {
                deliver_roster_removal_presence(
                    &routes,
                    Uuid::from_u128(1),
                    17,
                    Uuid::from_u128(2),
                    29,
                    "bob@example.test",
                    stanza,
                )
                .await;
                assert!(routes.events.lock().unwrap().is_empty());
            }
        });
    }

    #[test]
    fn removal_presence_routes_remote_with_exact_authority_after_local() {
        run(async {
            let routes = RemovalRoutes::default();
            let stanza =
                "<presence from='Alice@Example.TEST' to='bob@example.test' type='unsubscribed'/>";
            let authority = ClusterPresenceAuthority {
                owner_id: Uuid::from_u128(1),
                owner_auth_generation: 17,
                recipient_id: Uuid::from_u128(2),
                recipient_auth_generation: 29,
            };
            deliver_roster_removal_presence(
                &routes,
                authority.owner_id,
                authority.owner_auth_generation,
                authority.recipient_id,
                authority.recipient_auth_generation,
                "bob@example.test",
                stanza,
            )
            .await;
            assert_eq!(
                *routes.events.lock().unwrap(),
                vec![
                    RemovalEvent::Local("bob@example.test".into()),
                    RemovalEvent::Remote("bob@example.test".into(), stanza.into(), authority),
                ]
            );
        });
    }

    fn change() -> RosterChange {
        RosterChange {
            version: 42,
            contact_jid: "room@mix.example.test".into(),
            display_name: None,
            subscription: Some("both".into()),
            ask: None,
            groups: Vec::new(),
            approved: false,
            removed: false,
            owner_authority: Some((Uuid::from_u128(1), 7)),
        }
    }

    fn roster_ready(session: &OnlineSession, annotated: bool) {
        let permit = session
            .roster_sync
            .begin(
                &session.roster_requested,
                &session.mix_roster_annotations,
                annotated,
            )
            .unwrap();
        assert_eq!(
            session.roster_sync.start_flush(permit, 41),
            northstar_roster_core::RosterFlushBatch::Complete
        );
    }

    #[test]
    fn committed_push_reaches_only_interested_sessions_of_the_owner() {
        run(async {
            let owner_id = Uuid::from_u128(1);
            let mut ports = PushPorts::default();
            let mut receivers = Vec::new();
            for (resource, user_id, interested) in [
                ("interested", owner_id, true),
                ("uninterested", owner_id, false),
                ("recreated", Uuid::from_u128(2), true),
            ] {
                let (session, receiver) =
                    test_online_session(user_id, 7, Uuid::new_v4(), resource, 1);
                if interested {
                    roster_ready(&session, false);
                }
                let target = format!("alice@example.test/{resource}");
                ports.sessions.push((target.clone(), session.clone()));
                receivers.push((target, session, receiver));
            }
            let failures = Arc::new(AtomicU64::new(0));
            let delivery = RosterPushDelivery::new(ports, failures.clone(), "example.test".into());
            deliver_committed_roster_change(
                &delivery,
                owner_id,
                "alice",
                &change(),
                None,
                &northstar_roster_application::SystemRosterEvents,
            )
            .await
            .unwrap();
            for (target, session, mut receiver) in receivers {
                if session.resource == "interested" {
                    let push = receiver.try_recv().unwrap().stanza;
                    let document = roxmltree::Document::parse(&push).unwrap();
                    assert_eq!(
                        document.root_element().attribute("to"),
                        Some(target.as_str())
                    );
                    assert!(document
                        .descendants()
                        .any(|node| node.attribute("ver") == Some("42")));
                }
                assert!(receiver.try_recv().is_err());
                assert!(!session.disconnect.is_cancelled());
            }
            assert_eq!(failures.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn committed_push_annotates_only_for_mix_annotation_sessions() {
        run(async {
            let owner_id = Uuid::from_u128(1);
            let mut ports = PushPorts::default();
            let mut receivers = Vec::new();
            for (resource, annotated) in [("plain", false), ("annotated", true)] {
                let (session, receiver) =
                    test_online_session(owner_id, 7, Uuid::new_v4(), resource, 1);
                roster_ready(&session, annotated);
                let target = format!("alice@example.test/{resource}");
                ports.sessions.push((target.clone(), session));
                receivers.push((target, annotated, receiver));
            }
            let delivery =
                RosterPushDelivery::new(ports, Arc::new(AtomicU64::new(0)), "example.test".into());
            deliver_committed_roster_change(
                &delivery,
                owner_id,
                "alice",
                &change(),
                Some("opaque-id"),
                &northstar_roster_application::SystemRosterEvents,
            )
            .await
            .unwrap();
            for (target, annotated, mut receiver) in receivers {
                let push = receiver.try_recv().unwrap().stanza;
                let document = roxmltree::Document::parse(&push).unwrap();
                assert_eq!(
                    document.root_element().attribute("to"),
                    Some(target.as_str())
                );
                let channel = document
                    .descendants()
                    .find(|node| node.has_tag_name(("urn:xmpp:mix:roster:0", "channel")));
                assert_eq!(channel.is_some(), annotated);
                if let Some(channel) = channel {
                    assert_eq!(channel.attribute("participant-id"), Some("opaque-id"));
                }
                assert!(receiver.try_recv().is_err());
            }
        });
    }

    #[test]
    fn committed_push_queue_failure_disconnects_and_counts() {
        run(async {
            for closed in [true, false] {
                let owner_id = Uuid::from_u128(1);
                let (session, receiver) =
                    test_online_session(owner_id, 7, Uuid::new_v4(), "full", 1);
                roster_ready(&session, false);
                let mut receiver = if closed {
                    drop(receiver);
                    None
                } else {
                    session.sender.try_send("older".into()).unwrap();
                    Some(receiver)
                };
                let failures = Arc::new(AtomicU64::new(0));
                let delivery = RosterPushDelivery::new(
                    PushPorts {
                        sessions: vec![("alice@example.test/full".into(), session.clone())],
                        ..PushPorts::default()
                    },
                    failures.clone(),
                    "example.test".into(),
                );
                deliver_committed_roster_change(
                    &delivery,
                    owner_id,
                    "alice",
                    &change(),
                    None,
                    &northstar_roster_application::SystemRosterEvents,
                )
                .await
                .unwrap();
                assert!(session.disconnect.is_cancelled());
                assert!(session.sender.backpressure_disconnect().is_cancelled());
                assert_eq!(failures.load(Ordering::Relaxed), 1);
                if let Some(receiver) = receiver.as_mut() {
                    assert_eq!(receiver.try_recv().unwrap().stanza, "older");
                    assert!(receiver.try_recv().is_err());
                }
            }
        });
    }

    #[test]
    fn removal_presence_requires_identity_generation_availability_and_privacy() {
        run(async {
            let authority = ClusterPresenceAuthority {
                owner_id: Uuid::from_u128(1),
                owner_auth_generation: 17,
                recipient_id: Uuid::from_u128(2),
                recipient_auth_generation: 29,
            };
            let mut routes = RemovalRoutes::default();
            let mut receivers = Vec::new();
            for (resource, user_id, generation, available) in [
                ("allowed", authority.recipient_id, 29, true),
                ("wrong-id", Uuid::from_u128(3), 29, true),
                ("wrong-generation", authority.recipient_id, 28, true),
                ("unavailable", authority.recipient_id, 29, false),
                ("denied", authority.recipient_id, 29, true),
                ("privacy-error", authority.recipient_id, 29, true),
            ] {
                let (session, receiver) =
                    test_online_session(user_id, generation, Uuid::new_v4(), resource, 1);
                session.available.store(available, Ordering::Release);
                let target = format!("bob@example.test/{resource}");
                routes.sessions.push((target.clone(), session.clone()));
                receivers.push((target, session, receiver));
            }
            let stanza = "<presence from='Alice@Example.TEST' type='unsubscribed'/>";
            deliver_roster_removal_presence(
                &routes,
                authority.owner_id,
                authority.owner_auth_generation,
                authority.recipient_id,
                authority.recipient_auth_generation,
                "bob@example.test",
                stanza,
            )
            .await;
            for (target, session, mut receiver) in receivers {
                if session.resource == "allowed" {
                    assert_eq!(receiver.try_recv().unwrap().stanza, set_to(stanza, &target));
                }
                assert!(receiver.try_recv().is_err());
                assert!(!session.disconnect.is_cancelled());
            }
            assert_eq!(
                *routes.privacy_calls.lock().unwrap(),
                ["allowed", "denied", "privacy-error"]
                    .map(|resource| (
                        resource.to_owned(),
                        "alice@example.test".to_owned(),
                        PrivacyStanzaKind::PresenceIn,
                    ))
                    .to_vec(),
            );
            assert_eq!(
                *routes.events.lock().unwrap(),
                vec![
                    RemovalEvent::Local("bob@example.test".into()),
                    RemovalEvent::Remote("bob@example.test".into(), stanza.into(), authority),
                ],
            );
        });
    }

    mod exact;
}
