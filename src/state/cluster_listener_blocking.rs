//! Blocking-presence fanout after an authenticated cluster command.

use super::{session_entries_for_in, AppState, OnlineSession};
use crate::{
    cluster::ClusterListenerPresenceRoutes, config::ExternalRouteDomainPolicy,
    s2s::FederationRouter, xmpp::xml_builder::XmlElement,
};
use anyhow::Result;
use dashmap::DashMap;
use std::{
    collections::HashSet,
    sync::{atomic::Ordering, Arc},
};

pub(crate) struct ClusterListenerBlocking {
    sessions: Arc<DashMap<String, OnlineSession>>,
    remote_routes: ClusterListenerPresenceRoutes,
    local_domain: String,
    external_routes: ExternalRouteDomainPolicy,
    federation: FederationRouter,
}

impl AppState {
    pub(crate) fn cluster_listener_blocking(&self) -> ClusterListenerBlocking {
        ClusterListenerBlocking {
            sessions: Arc::clone(&self.sessions),
            remote_routes: self.cluster.listener_presence_routes(),
            local_domain: self.config.domain.clone(),
            external_routes: self.config.external_route_domain_policy(),
            federation: self.federation_outbox.clone(),
        }
    }
}

impl ClusterListenerBlocking {
    pub(crate) async fn deliver_presence_change(
        &self,
        owner: &str,
        roster_targets: &[String],
        changed_patterns: &[String],
        available: bool,
        mut send_remote: impl FnMut(String, String, String) -> Result<()>,
    ) -> Result<()> {
        for (from, session) in session_entries_for_in(&self.sessions, owner)
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
                if changed_patterns
                    .iter()
                    .any(|pattern| crate::services::blocking::matches(pattern, directed.key()))
                {
                    targets.insert(directed.key().clone());
                }
            }
            for target in targets {
                let Ok(target_jid) = crate::jid::CanonicalJid::parse(&target) else {
                    continue;
                };
                let delivery = crate::xmpp::xml_util::set_to(&base_presence, &target);
                if target_jid.domainpart() == self.local_domain {
                    let mut recipients = session_entries_for_in(&self.sessions, &target);
                    if target_jid.resourcepart().is_none() {
                        recipients
                            .retain(|(_, recipient)| recipient.available.load(Ordering::Acquire));
                    }
                    for (_, recipient) in recipients {
                        let _ = recipient.sender.try_send(delivery.clone());
                    }
                    if let Ok(nodes) = self.remote_routes.remote_nodes(&target).await {
                        for node_id in nodes {
                            send_remote(node_id, target.clone(), delivery.clone())?;
                        }
                    }
                } else if self
                    .external_routes
                    .external_route_domain_allowed(target_jid.domainpart())
                {
                    let _ = self
                        .federation
                        .send(target_jid.domainpart(), delivery, Some(from.clone()))
                        .await;
                }
            }
        }
        Ok(())
    }
}
