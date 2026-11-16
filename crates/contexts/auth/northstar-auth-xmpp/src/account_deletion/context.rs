//! Capabilities needed to finish a committed account deletion and retry it.

use super::AccountDeletionRecoveryTelemetry;
use anyhow::Result;
use northstar_auth_application::account::{
    AccountRepository, AccountService, DeletionRecoveryJob, RemovedAccount,
};
use northstar_roster_core::RosterChange;
use northstar_xml_builder::XmlElement;
use std::{future::Future, sync::Arc};
use uuid::Uuid;

/// Infrastructure reached by account removal; repositories remain generic application ports.
pub trait AccountDeletionRecoveryPorts: Send + Sync + 'static {
    fn revoke_sm(&self, user_id: Uuid) -> impl Future<Output = Result<usize>> + Send;
    fn deliver_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
    ) -> impl Future<Output = Result<()>> + Send;
    fn deliver_local_presence(&self, to: &str, stanza: &str);
    fn remote_nodes(&self, to: &str) -> impl Future<Output = Result<Vec<String>>> + Send;
    fn send_account_removal_presence(
        &self,
        node_id: &str,
        to: &str,
        stanza: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn federation_domain_allowed(&self, domain: &str) -> bool;
    fn send_federation_presence(
        &self,
        domain: &str,
        stanza: String,
        from: &str,
    ) -> impl Future<Output = bool> + Send;
    fn disconnect_account(&self, user_id: Uuid, bare_jid: &str) -> impl Future<Output = ()> + Send;
}

struct AccountDeletionPresence<'a, P> {
    ports: &'a P,
    local_domain: &'a str,
}

impl<P: AccountDeletionRecoveryPorts> AccountDeletionPresence<'_, P> {
    async fn route(&self, from: &str, to: &str, kind: &str) {
        let stanza = XmlElement::namespaced("presence", "jabber:client")
            .attr("from", from)
            .attr("to", to)
            .attr("type", kind)
            .finish();
        let Ok(target) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
            return;
        };
        let domain = target.domainpart();
        if domain == self.local_domain {
            self.ports.deliver_local_presence(to, &stanza);
            if let Ok(nodes) = self.ports.remote_nodes(to).await {
                for node_id in nodes {
                    let _ = self
                        .ports
                        .send_account_removal_presence(&node_id, to, &stanza)
                        .await;
                }
            }
        } else if self.ports.federation_domain_allowed(domain) {
            let _ = self
                .ports
                .send_federation_presence(domain, stanza, from)
                .await;
        }
    }
}

pub struct AccountDeletionRecoveryContext<R, P> {
    accounts: AccountService<R>,
    ports: P,
    metrics: Arc<northstar_telemetry::metrics::Metrics>,
    domain: String,
}

impl<R: AccountRepository, P: AccountDeletionRecoveryPorts> AccountDeletionRecoveryContext<R, P> {
    pub fn new(
        accounts: AccountService<R>,
        ports: P,
        metrics: Arc<northstar_telemetry::metrics::Metrics>,
        domain: String,
    ) -> Self {
        Self {
            accounts,
            ports,
            metrics,
            domain,
        }
    }

    pub fn local_domain(&self) -> &str {
        &self.domain
    }

    pub fn telemetry(&self) -> AccountDeletionRecoveryTelemetry<'_> {
        AccountDeletionRecoveryTelemetry::new(
            &self.metrics.account_deletion_recovery_success_total,
            &self.metrics.account_deletion_recovery_failures_total,
            &self.metrics.account_deletion_recovery_lease_losses_total,
        )
    }

    pub async fn claim(&self) -> Result<Vec<DeletionRecoveryJob>> {
        self.accounts.claim_deletion_recovery(16, 900).await
    }

    pub async fn release(&self, job: &DeletionRecoveryJob) -> Result<bool> {
        self.accounts
            .release_deletion_recovery(job, "finalization-failed")
            .await
    }

    pub async fn revoke_sm(&self, user_id: Uuid) -> Result<usize> {
        self.ports.revoke_sm(user_id).await
    }

    pub async fn delete_quiesced(&self, user_id: Uuid) -> Result<Option<RemovedAccount>> {
        self.accounts.delete_quiesced(user_id).await
    }

    pub async fn deliver_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
    ) -> Result<()> {
        self.ports
            .deliver_roster_change(owner_id, owner, change)
            .await
    }

    pub async fn route_presence(&self, from: &str, to: &str, kind: &str) {
        AccountDeletionPresence {
            ports: &self.ports,
            local_domain: &self.domain,
        }
        .route(from, to, kind)
        .await;
    }

    pub async fn disconnect_account(&self, user_id: Uuid, bare_jid: &str) {
        self.ports.disconnect_account(user_id, bare_jid).await;
    }
}
