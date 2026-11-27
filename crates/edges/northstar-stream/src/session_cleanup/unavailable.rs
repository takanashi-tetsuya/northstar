//! Captured unavailable delivery after a local route has been fenced.

use crate::local_routes::session::OnlineSession;
use crate::local_routes::session_table::LocalSessionTable;
use anyhow::Result;
use dashmap::DashMap;
use northstar_message_application::messaging::ExactMessageRoute;
pub use northstar_session_application::sm_teardown_presence::{DirectedGrant, TerminalRoute};
use northstar_session_application::sm_teardown_presence::{
    ExactPresenceAcceptance, SmTeardownPresenceRepository, SmTeardownPresenceService,
    TerminalPresenceAudience, TerminalPresenceRepository, TerminalPresenceRequest,
    TerminalPresenceTarget, TerminalRouteCandidate,
};
use northstar_xmpp_types::jid_text::bare_jid;
use std::{
    future::Future,
    sync::{atomic::Ordering, Arc},
};

mod retry;

/// Cluster and federation delivery bound by the composition root.
pub trait SessionCleanupUnavailablePorts: Send + Sync {
    fn capture_remote_routes(
        &self,
        bare: &str,
    ) -> impl Future<Output = Result<Vec<TerminalRouteCandidate>>> + Send;

    fn send_terminal_unavailable(
        &self,
        source: &TerminalRoute,
        target: &TerminalRoute,
        stanza: &str,
    ) -> impl Future<Output = Result<ExactPresenceAcceptance>> + Send;

    fn external_route_domain_allowed(&self, domain: &str) -> bool;

    fn send_federation(
        &self,
        domain: &str,
        stanza: String,
        origin: Option<String>,
    ) -> impl Future<Output = bool> + Send;
}

pub struct SessionCleanupUnavailable<R, P> {
    policy: SmTeardownPresenceService<R>,
    recipients: Arc<DashMap<String, OnlineSession>>,
    ports: P,
    local_domain: String,
}

impl<R, P> SessionCleanupUnavailable<R, P>
where
    R: SmTeardownPresenceRepository + TerminalPresenceRepository,
    P: SessionCleanupUnavailablePorts,
{
    pub fn new(
        policy: SmTeardownPresenceService<R>,
        recipients: Arc<DashMap<String, OnlineSession>>,
        ports: P,
        local_domain: String,
    ) -> Self {
        Self {
            policy,
            recipients,
            ports,
            local_domain,
        }
    }

    pub async fn capture<'a>(
        &'a self,
        mut request: TerminalPresenceRequest<'a>,
    ) -> Result<Option<TerminalPresenceAudience>> {
        request.local_domain = &self.local_domain;
        let mut routes: Vec<_> = self
            .recipients
            .iter()
            .filter(|entry| entry.routable.load(Ordering::Acquire))
            .map(|entry| {
                let recipient = entry.value();
                TerminalRouteCandidate {
                    route: TerminalRoute {
                        full_jid: entry.key().clone(),
                        account_id: recipient.user_id,
                        auth_generation: recipient.auth_generation,
                        connection_id: recipient.connection_id,
                        node_id: None,
                    },
                    expects_active: recipient
                        .privacy_active
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .is_some(),
                    available: recipient.available.load(Ordering::Acquire),
                }
            })
            .collect();
        // A directed withdrawal uses its recorded transport even when its
        // recipient is no longer available. Policy will still fence its account.
        if request.available {
            // This list is only a hint for remote route discovery. Subscription
            // direction and every policy decision are sampled by the final read.
            let mut peers = match self.policy.roster_subscribers(request.owner_id).await {
                Ok(peers) => peers,
                Err(error) => {
                    tracing::warn!(?error, "could not discover remote terminal presence peers");
                    Vec::new()
                }
            };
            peers.push(bare_jid(request.full_jid).to_owned());
            peers.sort_unstable();
            peers.dedup();
            for peer in peers {
                if northstar_xmpp_types::jid::CanonicalJid::parse_bare(&peer)
                    .is_ok_and(|jid| jid.domainpart() == self.local_domain)
                {
                    match self.ports.capture_remote_routes(&peer).await {
                        Ok(captured) => routes.extend(captured),
                        Err(error) => {
                            tracing::warn!(?error, %peer, "could not capture remote terminal presence routes")
                        }
                    }
                }
            }
        }
        for entry in request.directed {
            let Some(grant) = DirectedGrant::decode(entry)? else {
                continue;
            };
            if routes
                .iter()
                .any(|candidate| candidate.route.same_transport(&grant.route))
            {
                continue;
            }
            match self
                .ports
                .capture_remote_routes(&grant.route.full_jid)
                .await
            {
                Ok(remote) => routes.extend(
                    remote
                        .into_iter()
                        .filter(|candidate| candidate.route.same_transport(&grant.route)),
                ),
                Err(error) => {
                    tracing::warn!(?error, jid = %grant.route.full_jid, "could not locate directed teardown route")
                }
            }
        }
        routes.sort_by(|left, right| {
            (
                &left.route.full_jid,
                !left.available,
                !left.expects_active,
                &left.route.node_id,
            )
                .cmp(&(
                    &right.route.full_jid,
                    !right.available,
                    !right.expects_active,
                    &right.route.node_id,
                ))
        });
        let mut seen = std::collections::HashSet::new();
        routes.retain(|candidate| seen.insert(candidate.route.clone()));
        self.policy
            .capture_terminal_presence(&request, &routes)
            .await
    }

    pub async fn publish(&self, audience: TerminalPresenceAudience) -> Result<()> {
        if let Some(deadline) = audience.deadline {
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "terminal presence lease expired"
            );
            return tokio::time::timeout_at(deadline.into(), self.publish_audience(audience))
                .await?;
        }
        self.publish_audience(audience).await
    }

    async fn publish_audience(&self, audience: TerminalPresenceAudience) -> Result<()> {
        let source = audience.source;
        let stanza = northstar_xml_builder::XmlElement::namespaced("presence", "jabber:client")
            .attr("from", &source.full_jid)
            .attr("type", "unavailable")
            .finish();
        retry::publish_remaining(audience.targets, |target| {
            let (source, stanza) = (&source, &stanza);
            async move {
                let result = self.send_target(source, &target, stanza).await;
                (target, result)
            }
        })
        .await
    }

    async fn send_target(
        &self,
        source: &TerminalRoute,
        target: &TerminalPresenceTarget,
        stanza: &str,
    ) -> Result<ExactPresenceAcceptance> {
        match target {
            TerminalPresenceTarget::Route { route, scope } if route.node_id.is_some() => {
                let delivery = northstar_xml_builder::rewrite::set_to(stanza, scope);
                self.ports
                    .send_terminal_unavailable(source, route, &delivery)
                    .await
            }
            TerminalPresenceTarget::Route { route, .. } => {
                let exact = ExactMessageRoute {
                    full_jid: route.full_jid.clone(),
                    account_id: route.account_id,
                    auth_generation: route.auth_generation,
                    connection_id: route.connection_id,
                    node_id: None,
                    priority: None,
                    available: None,
                };
                let table = LocalSessionTable::new(Arc::clone(&self.recipients));
                let delivery = northstar_xml_builder::rewrite::set_to(stanza, &route.full_jid);
                let accepted = table.with_exact_message_route(&exact, |current| {
                    match current.sender.try_send(delivery) {
                        Ok(()) => ExactPresenceAcceptance::Accepted,
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            ExactPresenceAcceptance::Retry
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            ExactPresenceAcceptance::Gone
                        }
                    }
                });
                Ok(accepted.unwrap_or(ExactPresenceAcceptance::Gone))
            }
            TerminalPresenceTarget::External(peer) => {
                let peer = northstar_xmpp_types::jid::CanonicalJid::parse(peer)?;
                let domain = peer.domainpart();
                if !self.ports.external_route_domain_allowed(domain) {
                    return Ok(ExactPresenceAcceptance::Gone);
                }
                let delivery = northstar_xml_builder::rewrite::set_to(stanza, &peer.to_string());
                Ok(
                    if self
                        .ports
                        .send_federation(domain, delivery, Some(source.full_jid.clone()))
                        .await
                    {
                        ExactPresenceAcceptance::Accepted
                    } else {
                        ExactPresenceAcceptance::Retry
                    },
                )
            }
        }
    }
}
