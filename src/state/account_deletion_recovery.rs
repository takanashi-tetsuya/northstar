//! Capabilities needed to finish a committed account deletion and retry it.

use super::{
    account_teardown_runtime::AccountTeardownRuntime, cluster_routing::RemoteRosterPushFailure,
    session_cleanup_sm_revoker::SessionCleanupSmRevoker, session_entries_for_in, AppState,
    OnlineSession, RuntimeFederationPolicy,
};
use crate::{
    account_recovery::AccountDeletionRecoveryTelemetry,
    cluster::{ClusterListenerPresenceRoutes, ClusterNodeDelivery},
    config::ExternalRouteDomainPolicy,
    db::account_repository::PostgresAccountRepository,
    s2s::FederationRouter,
    services::account::{AccountService, DeletionRecoveryJob, RemovedAccount},
    xmpp::xml_builder::XmlElement,
};
use anyhow::Result;
use dashmap::DashMap;
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub(crate) struct RosterPushDelivery {
    sessions: Arc<DashMap<String, OnlineSession>>,
    routes: ClusterListenerPresenceRoutes,
    sender: ClusterNodeDelivery,
    metrics: Arc<crate::metrics::Metrics>,
    domain: String,
}

impl RosterPushDelivery {
    pub(crate) fn local_domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn local_sessions(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        session_entries_for_in(&self.sessions, jid)
    }

    pub(crate) fn record_failure(&self) {
        self.metrics
            .post_accept_side_effect_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) async fn route_remote_push(
        &self,
        account: &str,
        owner_id: Uuid,
        version: i64,
        push: &str,
        annotated_push: Option<&str>,
    ) -> Result<Vec<RemoteRosterPushFailure>> {
        let mut failures = Vec::new();
        for node_id in self.routes.remote_nodes(account).await? {
            match self
                .sender
                .send_roster_push(&node_id, account, owner_id, version, push, annotated_push)
                .await
            {
                Ok(true) => {}
                Ok(false) => failures.push(RemoteRosterPushFailure::NotAccepted { node_id }),
                Err(error) => failures.push(RemoteRosterPushFailure::Delivery(
                    super::cluster_routing::RemoteRouteFailure { node_id, error },
                )),
            }
        }
        Ok(failures)
    }
}

struct AccountDeletionPresence {
    sessions: Arc<DashMap<String, OnlineSession>>,
    routes: ClusterListenerPresenceRoutes,
    sender: ClusterNodeDelivery,
    federation: FederationRouter,
    domains: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    local_domain: String,
}

impl AccountDeletionPresence {
    async fn route(&self, from: &str, to: &str, kind: &str) {
        let stanza = XmlElement::namespaced("presence", "jabber:client")
            .attr("from", from)
            .attr("to", to)
            .attr("type", kind)
            .finish();
        let Ok(target) = crate::jid::CanonicalJid::parse(to) else {
            return;
        };
        let domain = target.domainpart();
        if domain == self.local_domain {
            for (_, session) in session_entries_for_in(&self.sessions, to) {
                let _ = session.sender.try_send(stanza.clone());
            }
            if let Ok(nodes) = self.routes.remote_nodes(to).await {
                for node_id in nodes {
                    let _ = self
                        .sender
                        .send_account_removal_presence(&node_id, to, &stanza)
                        .await;
                }
            }
        } else if self.domains.federation_domain_allowed(domain)
            && self.runtime_policy.load().allows_domain(domain)
        {
            let _ = self
                .federation
                .send(domain, stanza, Some(from.to_owned()))
                .await;
        }
    }
}

pub(crate) struct AccountDeletionRecoveryContext {
    accounts: AccountService<PostgresAccountRepository>,
    sm: SessionCleanupSmRevoker,
    roster: RosterPushDelivery,
    presence: AccountDeletionPresence,
    teardown: AccountTeardownRuntime,
    metrics: Arc<crate::metrics::Metrics>,
    domain: String,
}

impl AppState {
    pub(crate) fn roster_push_delivery(&self) -> RosterPushDelivery {
        RosterPushDelivery {
            sessions: Arc::clone(&self.sessions),
            routes: self.cluster.listener_presence_routes(),
            sender: self.cluster.node_delivery(),
            metrics: Arc::clone(&self.metrics),
            domain: self.config.domain.clone(),
        }
    }

    pub(crate) fn account_deletion_recovery_context(&self) -> AccountDeletionRecoveryContext {
        AccountDeletionRecoveryContext {
            accounts: self.account_service.clone(),
            sm: self.session_cleanup_sm_revoker(),
            roster: self.roster_push_delivery(),
            presence: AccountDeletionPresence {
                sessions: Arc::clone(&self.sessions),
                routes: self.cluster.listener_presence_routes(),
                sender: self.cluster.node_delivery(),
                federation: self.federation_outbox.clone(),
                domains: self.config.external_route_domain_policy(),
                runtime_policy: Arc::clone(&self.federation_runtime_policy),
                local_domain: self.config.domain.clone(),
            },
            teardown: self.account_teardown_runtime(),
            metrics: Arc::clone(&self.metrics),
            domain: self.config.domain.clone(),
        }
    }
}

impl AccountDeletionRecoveryContext {
    pub(crate) fn local_domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn roster(&self) -> &RosterPushDelivery {
        &self.roster
    }

    pub(crate) fn telemetry(&self) -> AccountDeletionRecoveryTelemetry<'_> {
        AccountDeletionRecoveryTelemetry::new(
            &self.metrics.account_deletion_recovery_success_total,
            &self.metrics.account_deletion_recovery_failures_total,
            &self.metrics.account_deletion_recovery_lease_losses_total,
        )
    }

    pub(crate) async fn claim(&self) -> Result<Vec<DeletionRecoveryJob>> {
        self.accounts.claim_deletion_recovery(16, 900).await
    }

    pub(crate) async fn release(&self, job: &DeletionRecoveryJob) -> Result<bool> {
        self.accounts
            .release_deletion_recovery(job, "finalization-failed")
            .await
    }

    pub(crate) async fn revoke_sm(&self, user_id: Uuid) -> Result<usize> {
        self.sm.revoke_user_with_teardown(user_id).await
    }

    pub(crate) async fn delete_quiesced(&self, user_id: Uuid) -> Result<Option<RemovedAccount>> {
        self.accounts.delete_quiesced(user_id).await
    }

    pub(crate) async fn route_presence(&self, from: &str, to: &str, kind: &str) {
        self.presence.route(from, to, kind).await;
    }

    pub(crate) async fn disconnect_account(&self, user_id: Uuid, bare_jid: &str) {
        self.teardown.disconnect_account(user_id, bare_jid).await;
    }
}
