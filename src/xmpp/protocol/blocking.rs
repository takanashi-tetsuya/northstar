use super::{Action, ProtocolSession};
use crate::services::xml_util::{set_to, stream_id};
use crate::state::AppState;
use crate::xmpp::xml_builder::XmlElement;
use anyhow::Result;
use northstar_roster_application::blocking::{BlockingRepository, BlockingService};
use roxmltree::Node;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

const BLOCKING_PUSH_TIMEOUT: Duration = Duration::from_secs(2);

impl ProtocolSession {
    pub(crate) async fn blocklist(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _blocklist: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::blocking::blocklist(self, id, root)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn block(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _block: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::blocking::block(self, id, root)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn unblock(
        &self,
        id: &str,
        root: Node<'_, '_>,
        _unblock: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::blocking::unblock(self, id, root)
            .await
            .map(Action::Send)
    }
}

impl northstar_roster_xmpp::blocking::BlockingSession for ProtocolSession {
    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository> {
        self.state.blocking_service()
    }

    fn blocking_mark_requested(&self) {
        self.blocklist_requested.store(true, Ordering::Release);
    }

    async fn blocking_push_change(&self, owner: &str, payload: &str) {
        for (jid, session) in self.state.session_entries_for(owner) {
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
                    self.state.post_accept_failure_telemetry().record_failure();
                    tracing::warn!(%jid, ?error, "XEP-0191 blocklist push queue closed; disconnecting stale resource");
                }
                Err(_) => {
                    session.sender.disconnect_backpressured_transport();
                    session.disconnect.cancel();
                    self.state.post_accept_failure_telemetry().record_failure();
                    tracing::warn!(%jid, "timed out delivering XEP-0191 blocklist push; disconnecting stale resource");
                }
            }
        }
        match self
            .state
            .route_remote_blocklist_push(owner, || blocking_push_stanza(owner, payload))
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

    async fn blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) {
        deliver_blocking_presence_change(&self.state, owner, targets, changed_patterns, available)
            .await;
        match self
            .state
            .route_remote_blocking_presence_change(owner, targets, changed_patterns, available)
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
}

fn blocking_push_stanza(target: &str, payload: &str) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("to", target)
        .attr("type", "set")
        .attr("id", format!("block-{}", stream_id()))
        .validated_fragment(payload)
        .expect("blocking payload was constructed structurally")
        .finish()
}

/// Runs on every node that owns at least one resource of `owner`. This keeps
/// polite-blocking presence transitions complete without duplicating any one
/// resource's presence.
pub(crate) async fn deliver_blocking_presence_change(
    state: &Arc<AppState>,
    owner: &str,
    roster_targets: &[String],
    changed_patterns: &[String],
    available: bool,
) {
    let _ = deliver_blocking_presence_change_with_remote(
        state,
        owner,
        roster_targets,
        changed_patterns,
        available,
        |node_id, target, delivery| async move {
            let _ = state
                .route_remote_available_presence_to_node(&node_id, &target, &delivery)
                .await;
            Ok(())
        },
    )
    .await;
}

/// The cluster listener prepares remote replies in its current command turn,
/// then waits for their receipts without blocking the PubSub reader.
pub(crate) async fn deliver_blocking_presence_change_with_remote<F, Fut>(
    state: &Arc<AppState>,
    owner: &str,
    roster_targets: &[String],
    changed_patterns: &[String],
    available: bool,
    mut send_remote: F,
) -> Result<()>
where
    F: FnMut(String, String, String) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    for (from, session) in state
        .session_entries_for(owner)
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
            if target_jid.domainpart() == state.local_domain() {
                let mut recipients = state.session_entries_for(&target);
                if target_jid.resourcepart().is_none() {
                    recipients.retain(|(_, recipient)| recipient.available.load(Ordering::Acquire));
                }
                for (_, recipient) in recipients {
                    let _ = recipient.sender.try_send(delivery.clone());
                }
                if let Ok(nodes) = state.remote_resource_nodes(&target).await {
                    for node_id in nodes {
                        send_remote(node_id, target.clone(), delivery.clone()).await?;
                    }
                }
            } else if state.xmpp_external_route_domain_allowed(target_jid.domainpart()) {
                let _ = state
                    .federation_outbox()
                    .send(target_jid.domainpart(), delivery, Some(from.clone()))
                    .await;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
