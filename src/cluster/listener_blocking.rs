//! Blocking-presence fanout after an authenticated cluster command.

use crate::xmpp::local_routes::{session::OnlineSession, session_table::session_entries_for_in};
use crate::{
    cluster::ClusterListenerPresenceRoutes, s2s::FederationRouter, xmpp::xml_builder::XmlElement,
};
use anyhow::Result;
use dashmap::DashMap;
use northstar_config::ExternalRouteDomainPolicy;
use std::{
    collections::HashSet,
    sync::{atomic::Ordering, Arc},
};

pub(crate) struct ClusterListenerBlocking {
    pub(crate) sessions: Arc<DashMap<String, OnlineSession>>,
    pub(crate) remote_routes: ClusterListenerPresenceRoutes,
    pub(crate) local_domain: String,
    pub(crate) external_routes: ExternalRouteDomainPolicy,
    pub(crate) federation: FederationRouter,
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
                let Ok(target_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(&target) else {
                    continue;
                };
                let delivery = crate::services::xml_util::set_to(&base_presence, &target);
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
