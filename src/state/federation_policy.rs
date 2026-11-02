//! Runtime federation rules as `AppState` applies them, and service control.

use super::*;

pub(super) fn service_control_applies(
    process_started_at: chrono::DateTime<chrono::Utc>,
    control: &northstar_operations_postgres::admin_commands::DurableServiceControl,
) -> bool {
    control
        .fired_at
        .is_some_and(|fired_at| process_started_at < fired_at)
}

impl AppState {
    pub fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = northstar_xmpp_types::jid::prepare_domainpart(domain) else {
            return false;
        };
        let policy = self.federation_runtime_policy.load();
        self.config.federation_domain_allowed(&domain) && policy.allows_domain(&domain)
    }

    /// Apply XEP-0133 entity rules using XEP-0016-style JID specificity: a
    /// domain rule matches the whole domain, a bare JID matches all of its
    /// resources, and a full JID matches exactly one resource.
    pub fn federation_entity_allowed(&self, entity: &str) -> bool {
        let Ok(entity) = northstar_xmpp_types::jid::CanonicalJid::parse(entity) else {
            return false;
        };
        if !self.config.federation_domain_allowed(entity.domainpart()) {
            return false;
        }
        self.federation_runtime_policy.load().allows_entity(&entity)
    }

    pub fn replace_runtime_federation_cache(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
        self.federation_runtime_policy
            .store(Arc::new(RuntimeFederationPolicy {
                blacklist: blacklist.into_iter().collect(),
                whitelist: whitelist.into_iter().collect(),
            }));
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
