//! Runtime federation rules as `ServerNode` applies them, and service control.

use crate::node::*;

pub(in crate::node) fn service_control_applies(
    process_started_at: chrono::DateTime<chrono::Utc>,
    control: &northstar_operations_postgres::admin_commands::DurableServiceControl,
) -> bool {
    control
        .fired_at
        .is_some_and(|fired_at| process_started_at < fired_at)
}

impl ServerNode {
    pub fn federation_domain_allowed(&self, domain: &str) -> bool {
        self.federation.effective_policy.domain_allowed(domain)
    }

    /// Apply the federation application's effective entity policy.
    pub fn federation_entity_allowed(&self, entity: &str) -> bool {
        self.federation.effective_policy.entity_allowed(entity)
    }

    pub fn replace_runtime_federation_cache(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
        self.federation
            .effective_policy
            .replace_runtime_cache(blacklist, whitelist);
    }

    pub fn install_service_shutdown(
        self: &Arc<Self>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        self.service_shutdown
            .set(cancel)
            .map_err(|_| anyhow::anyhow!("service shutdown control was already installed"))?;
        Ok(())
    }

    pub fn service_control_available(&self) -> bool {
        self.config.enable_xmpp_service_control && self.service_shutdown.get().is_some()
    }
}
