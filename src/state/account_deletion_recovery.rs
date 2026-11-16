//! Root bindings for auth-owned account deletion and recovery.

use super::{
    account_teardown_runtime::AccountTeardownRuntime,
    roster_session_host::deliver_roster_change_with,
    session_cleanup_sm_revoker::SessionCleanupSmRevoker, session_entries_for_in, AppState,
    OnlineSession, RuntimeFederationPolicy,
};
use crate::{
    cluster::{ClusterListenerPresenceRoutes, ClusterNodeDelivery},
    state::FederationRouter,
};
use anyhow::Result;
use dashmap::DashMap;
use northstar_auth_xmpp::account_deletion::{
    AccountDeletionRecoveryContext, AccountDeletionRecoveryPorts, RosterPushDelivery,
    RosterPushDeliveryPorts,
};
use northstar_config::ExternalRouteDomainPolicy;
use northstar_roster_core::RosterChange;
use northstar_workflows::account_repository::WorkflowAccountRepository;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct RosterPushDeliveryAdapters {
    sessions: Arc<DashMap<String, OnlineSession>>,
    routes: ClusterListenerPresenceRoutes,
    sender: ClusterNodeDelivery,
}

impl RosterPushDeliveryPorts for RosterPushDeliveryAdapters {
    type LocalSession = OnlineSession;

    fn local_sessions(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        session_entries_for_in(&self.sessions, jid)
    }

    async fn remote_nodes(&self, account: &str) -> Result<Vec<String>> {
        self.routes.remote_nodes(account).await
    }

    async fn send_roster_push(
        &self,
        node_id: &str,
        account: &str,
        owner_id: Uuid,
        version: i64,
        push: &str,
        annotated_push: Option<&str>,
    ) -> Result<bool> {
        self.sender
            .send_roster_push(node_id, account, owner_id, version, push, annotated_push)
            .await
    }
}

pub(crate) struct AccountDeletionRecoveryAdapters {
    sessions: Arc<DashMap<String, OnlineSession>>,
    sm: SessionCleanupSmRevoker,
    roster: RosterPushDelivery<RosterPushDeliveryAdapters>,
    routes: ClusterListenerPresenceRoutes,
    sender: ClusterNodeDelivery,
    federation: FederationRouter,
    domains: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    teardown: AccountTeardownRuntime,
}

impl AppState {
    pub(crate) fn roster_push_delivery(&self) -> RosterPushDelivery<RosterPushDeliveryAdapters> {
        RosterPushDelivery::new(
            RosterPushDeliveryAdapters {
                sessions: Arc::clone(&self.sessions),
                routes: self.cluster.listener_presence_routes(),
                sender: self.cluster.node_delivery(),
            },
            Arc::clone(&self.metrics.post_accept_side_effect_failures_total),
            self.config.domain.clone(),
        )
    }

    pub(crate) fn account_deletion_recovery_context(
        &self,
    ) -> AccountDeletionRecoveryContext<WorkflowAccountRepository, AccountDeletionRecoveryAdapters>
    {
        AccountDeletionRecoveryContext::new(
            self.auth.account_service.clone(),
            AccountDeletionRecoveryAdapters {
                sessions: Arc::clone(&self.sessions),
                sm: self.session_cleanup_sm_revoker(),
                roster: self.roster_push_delivery(),
                routes: self.cluster.listener_presence_routes(),
                sender: self.cluster.node_delivery(),
                federation: self.federation.federation_outbox.clone(),
                domains: self.config.external_route_domain_policy(),
                runtime_policy: Arc::clone(&self.federation.federation_runtime_policy),
                teardown: self.account_teardown_runtime(),
            },
            Arc::clone(&self.metrics),
            self.config.domain.clone(),
        )
    }
}

impl AccountDeletionRecoveryPorts for AccountDeletionRecoveryAdapters {
    async fn revoke_sm(&self, user_id: Uuid) -> Result<usize> {
        self.sm.revoke_user_with_teardown(user_id).await
    }

    async fn deliver_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
    ) -> Result<()> {
        deliver_roster_change_with(&self.roster, owner_id, owner, change, None).await
    }

    fn deliver_local_presence(&self, to: &str, stanza: &str) {
        for (_, session) in session_entries_for_in(&self.sessions, to) {
            let _ = session.sender.try_send(stanza.to_owned());
        }
    }

    async fn remote_nodes(&self, to: &str) -> Result<Vec<String>> {
        self.routes.remote_nodes(to).await
    }

    async fn send_account_removal_presence(
        &self,
        node_id: &str,
        to: &str,
        stanza: &str,
    ) -> Result<bool> {
        self.sender
            .send_account_removal_presence(node_id, to, stanza)
            .await
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        self.domains.federation_domain_allowed(domain)
            && self.runtime_policy.load().allows_domain(domain)
    }

    async fn send_federation_presence(&self, domain: &str, stanza: String, from: &str) -> bool {
        self.federation
            .send(domain, stanza, Some(from.to_owned()))
            .await
    }

    async fn disconnect_account(&self, user_id: Uuid, bare_jid: &str) {
        self.teardown.disconnect_account(user_id, bare_jid).await;
    }
}
