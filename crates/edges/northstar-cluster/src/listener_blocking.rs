//! Blocking-presence snapshot and handoff on the node that owns each route.

use crate::{ClusterAdapters, ClusterManager};
use anyhow::Result;
use dashmap::DashMap;
use futures::future::BoxFuture;
use northstar_federation_core::FederationRoute;
use northstar_roster_application::{
    blocking_mutation::{BlockingPresenceTarget, BlockingRouteCandidate},
    CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader, ExactPresenceRoute,
    RosterActor,
};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_xml_builder::{rewrite::set_to, XmlElement};
use northstar_xmpp_types::{jid::CanonicalJid, jid_text::bare_jid};
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

mod snapshot;
pub(crate) mod wire;

type ReadPolicies = dyn Fn(Vec<CommunicationPolicyQuery>) -> BoxFuture<'static, Result<Vec<CommunicationDecision>>>
    + Send
    + Sync;
type ReadRosterGrant = dyn Fn(Uuid, String) -> BoxFuture<'static, Result<bool>> + Send + Sync;

pub struct ClusterListenerBlocking<A: ClusterAdapters> {
    sessions: Arc<DashMap<String, OnlineSession>>,
    cluster: ClusterManager,
    local_domain: String,
    external_routes: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    federation: A::Federation,
    read_policies: Arc<ReadPolicies>,
    roster_grant: Arc<ReadRosterGrant>,
}

impl<A: ClusterAdapters> ClusterListenerBlocking<A> {
    pub fn new(
        sessions: Arc<DashMap<String, OnlineSession>>,
        cluster: ClusterManager,
        local_domain: String,
        external_routes: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        federation: A::Federation,
        policies: impl CommunicationPolicyReader + 'static,
        roster_grant: Arc<ReadRosterGrant>,
    ) -> Self {
        let policies = Arc::new(policies);
        Self {
            sessions,
            cluster,
            local_domain,
            external_routes,
            federation,
            read_policies: Arc::new(move |queries| {
                let policies = Arc::clone(&policies);
                Box::pin(async move { policies.read_communication_policies(&queries).await })
            }),
            roster_grant,
        }
    }

    pub fn admits_actor(&self, actor: &RosterActor) -> bool {
        self.sessions.get(&actor.full_jid).is_some_and(|session| {
            is_current(
                &session,
                actor.account_id,
                actor.auth_generation,
                actor.connection_id,
            )
        })
    }

    pub async fn capture_candidates(
        &self,
        actor: &RosterActor,
        patterns: Option<&[CanonicalJid]>,
    ) -> Vec<BlockingRouteCandidate> {
        let patterns =
            patterns.map(|patterns| patterns.iter().map(ToString::to_string).collect::<Vec<_>>());
        let mut entries = self.snapshot_entries(actor.bare_jid(), patterns.as_deref(), None, None);
        let (remote, failures) = self
            .cluster
            .capture_remote_blocking_routes(actor, patterns)
            .await;
        entries.extend(remote);
        for failure in failures {
            tracing::warn!(error = ?failure.error, node = %failure.node_id, "blocking route snapshot failed");
        }
        snapshot::assemble_candidates(entries)
    }

    pub async fn deliver_slice(&self, targets: &[BlockingPresenceTarget], available: bool) {
        for group in targets.chunk_by(|left, right| left.source == right.source) {
            if group[0].source.node_id.is_some() {
                for failure in self
                    .cluster
                    .route_remote_blocking_presence_change(group, available)
                    .await
                {
                    tracing::warn!(error = ?failure.error, node = %failure.node_id, "blocking presence slice failed");
                }
            } else {
                self.emit_slice(group.iter().cloned(), available).await;
            }
        }
    }

    pub(crate) async fn emit_slice(
        &self,
        targets: impl IntoIterator<Item = BlockingPresenceTarget>,
        available: bool,
    ) -> usize {
        let mut failed = 0;
        for target in targets {
            if let Err(error) = self.emit(target.clone(), available).await {
                tracing::warn!(?error, from = %target.source.full_jid, to = %target.address, "blocking presence handoff failed");
                failed += 1;
            }
        }
        failed
    }

    pub(crate) async fn emit(
        &self,
        mut target: BlockingPresenceTarget,
        available: bool,
    ) -> Result<()> {
        let Some(source) = self.local_session(&target.source) else {
            return Ok(());
        };
        if !source.available.load(Ordering::Acquire)
            || (target.source.node_id.is_some()
                && !self
                    .cluster
                    .blocking_route_owner_is_current(&target.source)
                    .await?)
        {
            return Ok(());
        }
        target.source_expects_active = expects_active(&source);
        if available {
            let still_directed = target
                .directed
                .as_ref()
                .is_some_and(|grant| source.directed_presence.contains(grant));
            if !still_directed
                && !(self.roster_grant)(
                    target.source.account_id,
                    bare_jid(&target.address).to_owned(),
                )
                .await?
            {
                return Ok(());
            }
        }
        let Some(stanza) = Self::render(&source, &target, available) else {
            return Ok(());
        };
        if let Some(recipient) = &target.recipient {
            if let Some(node) = recipient
                .node_id
                .as_deref()
                .filter(|node| *node != self.cluster.node_id)
            {
                if self.policy_allows(&target, available).await? && self.source_current(&target) {
                    self.cluster
                        .send_blocking_presence_recipient(node, &target, &stanza, available)
                        .await?;
                }
                return Ok(());
            }
            return self.receive(target, &stanza, available).await;
        }
        let jid = CanonicalJid::parse(&target.address)?;
        if jid.domainpart() != self.local_domain
            && (self.external_routes)(jid.domainpart())
            && self.policy_allows(&target, available).await?
            && self.source_current(&target)
        {
            anyhow::ensure!(
                self.federation
                    .send(jid.domainpart(), stanza, Some(target.source.full_jid))
                    .await,
                "federation refused blocking presence"
            );
        }
        Ok(())
    }

    pub(crate) async fn receive(
        &self,
        mut target: BlockingPresenceTarget,
        stanza: &str,
        available: bool,
    ) -> Result<()> {
        let Some(recipient) = &target.recipient else {
            return Ok(());
        };
        let Some(session) = self.local_session(recipient) else {
            return Ok(());
        };
        target.recipient_expects_active = expects_active(&session);
        if (!self.is_local(&target.source)
            && !self
                .cluster
                .blocking_route_owner_is_current(&target.source)
                .await?)
            || (recipient.node_id.is_some()
                && !self
                    .cluster
                    .blocking_route_owner_is_current(recipient)
                    .await?)
        {
            return Ok(());
        }
        if !self.policy_allows(&target, available).await?
            || (self.is_local(&target.source) && !self.source_current(&target))
        {
            return Ok(());
        }
        if let Some(current) = self.sessions.get(&recipient.full_jid).filter(|session| {
            is_current(
                session,
                recipient.account_id,
                recipient.auth_generation,
                recipient.connection_id,
            ) && expects_active(session) == target.recipient_expects_active
                && (target.address == recipient.full_jid
                    || session.available.load(Ordering::Acquire))
        }) {
            anyhow::ensure!(
                current.sender.try_send(stanza.to_owned()).is_ok(),
                "blocking presence queue refused"
            );
        }
        Ok(())
    }

    pub(crate) async fn snapshot_actor_is_current(
        &self,
        route: &ExactPresenceRoute,
    ) -> Result<bool> {
        self.cluster.blocking_route_owner_is_current(route).await
    }

    fn render(
        source: &OnlineSession,
        target: &BlockingPresenceTarget,
        available: bool,
    ) -> Option<String> {
        if available {
            let cached = source
                .last_presence
                .read()
                .unwrap_or_else(|error| error.into_inner());
            return cached
                .as_ref()
                .map(|stanza| set_to(stanza, &target.address));
        }
        Some(
            XmlElement::namespaced("presence", "jabber:client")
                .attr("from", &target.source.full_jid)
                .attr("type", "unavailable")
                .attr("to", &target.address)
                .finish(),
        )
    }

    fn source_current(&self, target: &BlockingPresenceTarget) -> bool {
        self.local_session(&target.source).is_some_and(|session| {
            session.available.load(Ordering::Acquire)
                && expects_active(&session) == target.source_expects_active
        })
    }

    async fn policy_allows(
        &self,
        target: &BlockingPresenceTarget,
        available: bool,
    ) -> Result<bool> {
        let queries = target.policies(true).into_iter().flatten().collect();
        let decisions = (self.read_policies)(queries).await?;
        let (source, recipient) = match decisions.as_slice() {
            [source] if target.recipient.is_none() => (*source, CommunicationDecision::Allow),
            [source, recipient] if target.recipient.is_some() => (*source, *recipient),
            _ => anyhow::bail!("blocking presence policy result has the wrong number of decisions"),
        };
        Ok(if available {
            source.allows() && recipient.allows()
        } else {
            source == CommunicationDecision::OwnerBlocks
                && recipient != CommunicationDecision::StaleAccount
        })
    }

    fn is_local(&self, route: &ExactPresenceRoute) -> bool {
        route
            .node_id
            .as_deref()
            .is_none_or(|node| node == self.cluster.node_id)
    }

    fn local_session(&self, route: &ExactPresenceRoute) -> Option<OnlineSession> {
        if !self.is_local(route) {
            return None;
        }
        self.sessions
            .get(&route.full_jid)
            .filter(|session| {
                is_current(
                    session,
                    route.account_id,
                    route.auth_generation,
                    route.connection_id,
                )
            })
            .map(|session| session.value().clone())
    }
}

fn is_current(session: &OnlineSession, account: Uuid, generation: i64, connection: Uuid) -> bool {
    session.routable.load(Ordering::Acquire)
        && !session.disconnect.is_cancelled()
        && session.user_id == account
        && session.auth_generation == generation
        && session.connection_id == connection
}

fn expects_active(session: &OnlineSession) -> bool {
    session
        .privacy_active
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .is_some()
}
