use super::{Action, ProtocolSession};
use crate::services::blocking::{BlockUpdateOutcome, UnblockUpdateOutcome};
use crate::state::AppState;
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::Result;
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
        blocklist: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if root.attribute("to").is_some() || !blocking_command_is_empty(blocklist) {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let items = self.state.blocking_service().blocked_jids(user.id).await?;
        self.blocklist_requested.store(true, Ordering::Release);
        let mut payload = XmlElement::namespaced("blocklist", "urn:xmpp:blocking");
        for jid in items {
            payload.push_child(XmlElement::new("item").attr("jid", jid));
        }
        Ok(Action::Send(iq_result(id, &payload.finish())))
    }

    pub(crate) async fn block(
        &self,
        id: &str,
        root: Node<'_, '_>,
        block: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if root.attribute("to").is_some() {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let Some(items) = blocking_items(block, self.full_jid.as_deref()) else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        if items.is_empty() {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        // Resolve presence authorization before mutating the blocklist.  A
        // post-commit roster failure must not turn a durable command into a
        // transport error that the client may retry without receiving the
        // required transition.
        let roster = self.state.blocking_service().roster(user.id).await?;
        let changed = match self.state.blocking_service().block(user.id, &items).await? {
            BlockUpdateOutcome::Changed(changed) => changed,
            BlockUpdateOutcome::QuotaExceeded => {
                return Ok(Action::Send(iq_error(id, "resource-constraint")));
            }
            BlockUpdateOutcome::Unavailable => {
                return Ok(Action::Send(iq_error(id, "not-authorized")));
            }
        };
        if !changed.is_empty() {
            self.notify_blocking_presence(user, &roster, &changed, false)
                .await;
            self.push_blocking_change("block", &changed).await;
        }
        Ok(Action::Send(iq_result(id, "")))
    }

    pub(crate) async fn unblock(
        &self,
        id: &str,
        root: Node<'_, '_>,
        unblock: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if root.attribute("to").is_some() {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let Some(items) = blocking_items(unblock, self.full_jid.as_deref()) else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let roster = self.state.blocking_service().roster(user.id).await?;
        let unblock_all = items.is_empty();
        let changed = match self
            .state
            .blocking_service()
            .unblock(user.id, if unblock_all { None } else { Some(&items) })
            .await?
        {
            UnblockUpdateOutcome::Changed(changed) => changed,
            UnblockUpdateOutcome::Unavailable => {
                return Ok(Action::Send(iq_error(id, "not-authorized")));
            }
        };
        if !changed.is_empty() {
            self.notify_blocking_presence(user, &roster, &changed, true)
                .await;
            self.push_blocking_change("unblock", if unblock_all { &[] } else { &changed })
                .await;
        }
        Ok(Action::Send(iq_result(id, "")))
    }

    async fn push_blocking_change(&self, action: &str, jids: &[String]) {
        let Some(user) = &self.authenticated else {
            return;
        };
        let owner = format!("{}@{}", user.username, self.state.config.domain);
        let Some(payload) = blocking_change_payload(action, jids) else {
            tracing::error!(action, "refused unknown XEP-0191 push action");
            return;
        };
        for (jid, session) in self.state.session_entries_for(&owner) {
            if !session.blocklist_requested.load(Ordering::Acquire) {
                continue;
            }
            let push = blocking_push_stanza(&jid, &payload);
            match tokio::time::timeout(BLOCKING_PUSH_TIMEOUT, session.sender.send(push)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    // A committed block-list mutation must not be followed by
                    // newer traffic on a resource which missed its ordered
                    // push.  Disconnecting forces the client to query the
                    // server-authoritative list again after reconnect.
                    session.sender.disconnect_backpressured_transport();
                    session.disconnect.cancel();
                    self.state
                        .metrics
                        .post_accept_side_effect_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%jid, ?error, "XEP-0191 blocklist push queue closed; disconnecting stale resource");
                }
                Err(_) => {
                    session.sender.disconnect_backpressured_transport();
                    session.disconnect.cancel();
                    self.state
                        .metrics
                        .post_accept_side_effect_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%jid, "timed out delivering XEP-0191 blocklist push; disconnecting stale resource");
                }
            }
        }
        match self.state.cluster.lookup_nodes(&owner).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id == self.state.cluster.node_id {
                        continue;
                    }
                    let push = blocking_push_stanza(&owner, &payload);
                    if let Err(error) = self
                        .state
                        .cluster
                        .send_to_node_blocklist(&node_id, &owner, &push)
                        .await
                    {
                        tracing::warn!(?error, %node_id, "failed clustered XEP-0191 push");
                    }
                }
            }
            Err(error) => tracing::warn!(?error, "failed to locate clustered account resources"),
        }
    }

    async fn notify_blocking_presence(
        &self,
        user: &crate::services::authentication::AuthenticatedAccount,
        roster: &[(String, Option<String>, String, Option<String>)],
        changed_patterns: &[String],
        available: bool,
    ) {
        let targets = blocking_presence_targets(roster, changed_patterns);
        let owner = format!("{}@{}", user.username, self.state.config.domain);
        deliver_blocking_presence_change(
            &self.state,
            &owner,
            &targets,
            changed_patterns,
            available,
        )
        .await;
        match self.state.cluster.lookup_nodes(&owner).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id == self.state.cluster.node_id {
                        continue;
                    }
                    if let Err(error) = self
                        .state
                        .cluster
                        .send_blocking_presence_change(
                            &node_id,
                            &owner,
                            &targets,
                            changed_patterns,
                            available,
                        )
                        .await
                    {
                        tracing::warn!(?error, %node_id, "failed clustered blocking presence update");
                    }
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

fn blocking_change_payload(action: &str, jids: &[String]) -> Option<String> {
    let mut payload = match action {
        "block" => XmlElement::namespaced("block", "urn:xmpp:blocking"),
        "unblock" => XmlElement::namespaced("unblock", "urn:xmpp:blocking"),
        _ => return None,
    };
    for jid in jids {
        payload.push_child(XmlElement::new("item").attr("jid", jid));
    }
    Some(payload.finish())
}

fn blocking_presence_targets(
    roster: &[(String, Option<String>, String, Option<String>)],
    patterns: &[String],
) -> Vec<String> {
    let mut targets = HashSet::new();
    for pattern in patterns {
        let Ok(blocked) = crate::jid::CanonicalJid::parse(pattern) else {
            continue;
        };
        if blocked.resourcepart().is_some() {
            let permission_jid = blocked.bare();
            if roster.iter().any(|(jid, _, subscription, _)| {
                crate::jid::canonical_bare_key(jid).ok().as_deref() == Some(&permission_jid)
                    && matches!(subscription.as_str(), "from" | "both")
            }) {
                targets.insert(blocked.to_string());
            }
        } else {
            for (jid, _, subscription, _) in roster {
                if matches!(subscription.as_str(), "from" | "both")
                    && crate::services::blocking::BlockingService::matches(pattern, jid)
                {
                    if let Ok(jid) = crate::jid::canonicalize_bare(jid) {
                        targets.insert(jid);
                    }
                }
            }
        }
    }
    let mut targets = targets.into_iter().collect::<Vec<_>>();
    targets.sort_unstable();
    targets
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
                crate::services::blocking::BlockingService::matches(pattern, directed.key())
            }) {
                targets.insert(directed.key().clone());
            }
        }
        for target in targets {
            let Ok(target_jid) = crate::jid::CanonicalJid::parse(&target) else {
                continue;
            };
            let delivery = set_to(&base_presence, &target);
            if target_jid.domainpart() == state.config.domain {
                let mut recipients = state.session_entries_for(&target);
                if target_jid.resourcepart().is_none() {
                    recipients.retain(|(_, recipient)| recipient.available.load(Ordering::Acquire));
                }
                for (_, recipient) in recipients {
                    let _ = recipient.sender.try_send(delivery.clone());
                }
                if let Ok(nodes) = state.cluster.lookup_nodes(&target).await {
                    for node_id in nodes {
                        if node_id != state.cluster.node_id {
                            let _ = state
                                .cluster
                                .send_to_node_available_presence(&node_id, &target, &delivery)
                                .await;
                        }
                    }
                }
            } else if state
                .config
                .external_route_domain_allowed(target_jid.domainpart())
            {
                let _ = state
                    .federation
                    .send(target_jid.domainpart(), delivery, Some(from.clone()))
                    .await;
            }
        }
    }
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

    #[test]
    fn blocking_values_cannot_escape_the_structural_builder() {
        let payload =
            blocking_change_payload("block", &["mallory@example.test/'/><injected/>".to_owned()])
                .unwrap();
        let document = roxmltree::Document::parse(&payload).unwrap();
        let root = document.root_element();
        let item = root.children().find(|node| node.is_element()).unwrap();
        assert_eq!(root.tag_name().name(), "block");
        assert_eq!(root.tag_name().namespace(), Some("urn:xmpp:blocking"));
        assert_eq!(
            item.attribute("jid"),
            Some("mallory@example.test/'/><injected/>")
        );
        assert_eq!(root.children().filter(|node| node.is_element()).count(), 1);
    }
}
