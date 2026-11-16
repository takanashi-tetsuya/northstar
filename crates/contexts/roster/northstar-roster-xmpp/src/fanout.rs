//! Fan-out of committed block-list, privacy-list and blocking-presence changes.

use crate::roster_push::RemoteRouteFailure;
use anyhow::Result;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_xml_builder::rewrite::set_to;
use northstar_xml_builder::stream::stream_id;
use northstar_xml_builder::XmlElement;
use std::collections::HashSet;
use std::future::Future;
use std::sync::atomic::Ordering;
use std::time::Duration;
use uuid::Uuid;

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

pub fn blocking_push_stanza(target: &str, payload: &str) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("to", target)
        .attr("type", "set")
        .attr("id", format!("block-{}", stream_id()))
        .validated_fragment(payload)
        .expect("blocking payload was constructed structurally")
        .finish()
}

pub async fn push_blocklist_change(routes: &impl RosterFanoutRoutes, owner: &str, payload: &str) {
    for (jid, session) in routes.fanout_sessions(owner) {
        if !session.blocklist_requested.load(Ordering::Acquire) {
            continue;
        }
        let push = blocking_push_stanza(&jid, payload);
        match tokio::time::timeout(BLOCKING_PUSH_TIMEOUT, session.sender.send(push)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                // A committed block-list mutation must not be followed by
                // newer traffic on a resource which missed its ordered
                // push.  Disconnecting forces the client to query the
                // server-authoritative list again after reconnect.
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                routes.record_fanout_failure();
                tracing::warn!(%jid, ?error, "XEP-0191 blocklist push queue closed; disconnecting stale resource");
            }
            Err(_) => {
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                routes.record_fanout_failure();
                tracing::warn!(%jid, "timed out delivering XEP-0191 blocklist push; disconnecting stale resource");
            }
        }
    }
    match routes
        .remote_blocklist_push(owner, || blocking_push_stanza(owner, payload))
        .await
    {
        Ok(failures) => {
            for failure in failures {
                tracing::warn!(error=?failure.error, node_id=%failure.node_id,
                    "failed clustered XEP-0191 push");
            }
        }
        Err(error) => tracing::warn!(?error, "failed to locate clustered account resources"),
    }
}

/// Runs on every node that owns at least one resource of `owner`. This keeps
/// polite-blocking presence transitions complete without duplicating any one
/// resource's presence.
/// The cluster listener prepares remote replies in its current command turn,
/// then waits for their receipts without blocking the PubSub reader.
pub async fn deliver_blocking_presence_change(
    routes: &impl RosterFanoutRoutes,
    owner: &str,
    roster_targets: &[String],
    changed_patterns: &[String],
    available: bool,
) {
    for (from, session) in routes
        .fanout_sessions(owner)
        .into_iter()
        .filter(|(_, session)| session.available.load(Ordering::Acquire))
    {
        let base_presence = if available {
            session
                .last_presence
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        } else {
            Some(
                XmlElement::namespaced("presence", "jabber:client")
                    .attr("from", &from)
                    .attr("type", "unavailable")
                    .finish(),
            )
        };
        let Some(base_presence) = base_presence else {
            continue;
        };
        let mut targets = roster_targets.iter().cloned().collect::<HashSet<_>>();
        for directed in session.directed_presence.iter() {
            if changed_patterns.iter().any(|pattern| {
                northstar_roster_application::blocking::matches(pattern, directed.key())
            }) {
                targets.insert(directed.key().clone());
            }
        }
        for target in targets {
            let Ok(target_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(&target) else {
                continue;
            };
            let delivery = set_to(&base_presence, &target);
            if target_jid.domainpart() == routes.fanout_local_domain() {
                let mut recipients = routes.fanout_sessions(&target);
                if target_jid.resourcepart().is_none() {
                    recipients.retain(|(_, recipient)| recipient.available.load(Ordering::Acquire));
                }
                for (_, recipient) in recipients {
                    let _ = recipient.sender.try_send(delivery.clone());
                }
                if let Ok(nodes) = routes.remote_resource_nodes(&target).await {
                    for node_id in nodes {
                        routes
                            .send_available_presence_to_node(&node_id, &target, &delivery)
                            .await;
                    }
                }
            } else if routes.external_presence_domain_allowed(target_jid.domainpart()) {
                routes
                    .send_federated_presence(target_jid.domainpart(), delivery, from.clone())
                    .await;
            }
        }
    }
    match routes
        .remote_blocking_presence_change(owner, roster_targets, changed_patterns, available)
        .await
    {
        Ok(failures) => {
            for failure in failures {
                tracing::warn!(error=?failure.error, node_id=%failure.node_id,
                    "failed clustered blocking presence update");
            }
        }
        Err(error) => tracing::warn!(?error, "failed to locate clustered presence resources"),
    }
}

pub async fn push_privacy_change(
    routes: &impl RosterFanoutRoutes,
    account: &str,
    name: &str,
    base: &str,
    current_connection: Uuid,
) -> Option<String> {
    let mut current_push = None;
    for (jid, session) in routes.fanout_sessions(account) {
        if !session.privacy_requested.load(Ordering::Acquire) {
            continue;
        }
        let push = set_to(base, &jid);
        if session.connection_id == current_connection {
            current_push = Some(push);
        } else if let Err(error) = session.sender.try_send(push) {
            // The mutation has already committed.  Keeping this resource
            // alive after dropping its ordered IQ push would let the
            // client continue with a stale privacy-list view.  Force a
            // reconnect so its next query observes the authoritative
            // state instead of allowing later pushes to cross this gap.
            session.sender.disconnect_backpressured_transport();
            session.disconnect.cancel();
            routes.record_fanout_failure();
            tracing::warn!(
                %jid,
                list = %name,
                ?error,
                "XEP-0016 privacy-list push queue was unavailable; disconnecting stale resource"
            );
        }
    }
    match routes.remote_privacy_push(account, base).await {
        Ok(failures) => {
            for failure in failures {
                tracing::warn!(
                    error = ?failure.error,
                    node_id = %failure.node_id,
                    list = %name,
                    "clustered XEP-0016 push failed"
                );
            }
        }
        Err(error) => {
            tracing::warn!(?error, list = %name, "could not enumerate nodes for XEP-0016 push")
        }
    }
    current_push
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Routes {
        request_push: bool,
        remote_pushes: Mutex<Vec<String>>,
    }

    impl RosterFanoutRoutes for Routes {
        fn fanout_sessions(&self, _jid: &str) -> Vec<(String, OnlineSession)> {
            Vec::new()
        }

        fn fanout_local_domain(&self) -> &str {
            "example.test"
        }

        fn record_fanout_failure(&self) {
            panic!("unexpected fanout failure");
        }

        async fn remote_blocklist_push(
            &self,
            owner: &str,
            mut push: impl FnMut() -> String + Send,
        ) -> Result<Vec<RemoteRouteFailure>> {
            assert_eq!(owner, "alice@example.test");
            if self.request_push {
                self.remote_pushes.lock().unwrap().push(push());
            }
            Ok(Vec::new())
        }

        async fn remote_blocking_presence_change(
            &self,
            _owner: &str,
            _targets: &[String],
            _changed_patterns: &[String],
            _available: bool,
        ) -> Result<Vec<RemoteRouteFailure>> {
            panic!("unexpected remote blocking presence change");
        }

        async fn remote_privacy_push(
            &self,
            _account: &str,
            _base: &str,
        ) -> Result<Vec<RemoteRouteFailure>> {
            panic!("unexpected remote privacy push");
        }

        async fn remote_resource_nodes(&self, _target: &str) -> Result<Vec<String>> {
            panic!("unexpected remote resource lookup");
        }

        async fn send_available_presence_to_node(
            &self,
            _node_id: &str,
            _target: &str,
            _delivery: &str,
        ) {
            panic!("unexpected remote presence delivery");
        }

        fn external_presence_domain_allowed(&self, _domain: &str) -> bool {
            panic!("unexpected external domain policy lookup");
        }

        async fn send_federated_presence(&self, _domain: &str, _delivery: String, _from: String) {
            panic!("unexpected federated presence delivery");
        }
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
                push_blocklist_change(&routes, "alice@example.test", "<unblock").await;
                assert!(routes.remote_pushes.lock().unwrap().is_empty());

                let routes = Routes {
                    request_push: true,
                    ..Routes::default()
                };
                let payload = "<unblock xmlns='urn:xmpp:blocking'/>";
                push_blocklist_change(&routes, "alice@example.test", payload).await;
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
        );
        assert!(push.contains("to='alice@example.test/Phone'"));
        assert!(push.contains("<unblock xmlns='urn:xmpp:blocking'/>"));
    }
}
