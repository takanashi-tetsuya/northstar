//! Runtime federation rules as `ServerNode` applies them, and service control.

use crate::node::*;

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
        self.runtime.install_service_shutdown(cancel)
    }

    pub fn service_control_available(&self) -> bool {
        self.runtime
            .service_control_available(self.config.enable_xmpp_service_control)
    }
}
