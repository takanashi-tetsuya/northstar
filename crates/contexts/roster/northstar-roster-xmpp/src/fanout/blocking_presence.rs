use super::RosterFanoutRoutes;
use northstar_xml_builder::rewrite::set_to;
use northstar_xml_builder::XmlElement;
use std::collections::HashSet;
use std::sync::atomic::Ordering;

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
