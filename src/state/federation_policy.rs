//! Federation write policy, runtime federation rules and service control.

use super::*;

pub(super) struct FederationWritePolicy {
    pub(super) gate: RwLock<()>,
    pub(super) island_mode: Arc<AtomicBool>,
}

impl FederationWritePolicy {
    pub(super) fn new(island_mode: bool) -> Self {
        Self {
            gate: RwLock::new(()),
            island_mode: Arc::new(AtomicBool::new(island_mode)),
        }
    }

    pub(super) fn enabled(&self) -> bool {
        self.island_mode.load(Ordering::Acquire)
    }

    pub(super) async fn apply(&self, enabled: bool) {
        let _write_guard = self.gate.write().await;
        self.island_mode.store(enabled, Ordering::Release);
    }

    pub(super) async fn permit(&self) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        let guard = self.gate.read().await;
        (!self.island_mode.load(Ordering::Acquire)).then_some(guard)
    }

    pub(super) async fn refresh(&self, enabled: bool) -> bool {
        // An unchanged observation linearizes at this acquire load. It must
        // not wait behind a socket write merely to publish the same value.
        // Actual transitions still drain and fence writes under the gate.
        let previous = self.island_mode.load(Ordering::Acquire);
        if previous == enabled {
            return previous;
        }
        let _write_guard = self.gate.write().await;
        self.island_mode.swap(enabled, Ordering::AcqRel)
    }
}

#[derive(Default)]
pub(super) struct RuntimeFederationPolicy {
    pub(super) blacklist: std::collections::HashSet<String>,
    pub(super) whitelist: std::collections::HashSet<String>,
}

impl RuntimeFederationPolicy {
    pub(super) fn allows_domain(&self, domain: &str) -> bool {
        let domain_denied = self.blacklist.iter().any(|entry| {
            crate::jid::CanonicalJid::parse(entry)
                .is_ok_and(|jid| jid.localpart().is_none() && jid.domainpart() == domain)
        });
        let domain_admitted = self.whitelist.is_empty()
            || self.whitelist.iter().any(|entry| {
                crate::jid::CanonicalJid::parse(entry).is_ok_and(|jid| jid.domainpart() == domain)
            });
        !domain_denied && domain_admitted
    }
}

pub(super) fn federation_rule_matches(rule: &str, entity: &crate::jid::CanonicalJid) -> bool {
    crate::jid::CanonicalJid::parse(rule).is_ok_and(|rule| {
        if rule.domainpart() != entity.domainpart() {
            false
        } else if rule.localpart().is_none() {
            true
        } else if rule.resourcepart().is_none() {
            rule.bare() == entity.bare()
        } else {
            rule == *entity
        }
    })
}

pub(super) fn service_control_applies(
    process_started_at: chrono::DateTime<chrono::Utc>,
    control: &db::DurableServiceControl,
) -> bool {
    control
        .fired_at
        .is_some_and(|fired_at| process_started_at < fired_at)
}

impl AppState {
    pub fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = crate::jid::prepare_domainpart(domain) else {
            return false;
        };
        let policy = self.federation_runtime_policy.load();
        self.config.federation_domain_allowed(&domain) && policy.allows_domain(&domain)
    }

    /// Apply XEP-0133 entity rules using XEP-0016-style JID specificity: a
    /// domain rule matches the whole domain, a bare JID matches all of its
    /// resources, and a full JID matches exactly one resource.
    pub fn federation_entity_allowed(&self, entity: &str) -> bool {
        let Ok(entity) = crate::jid::CanonicalJid::parse(entity) else {
            return false;
        };
        if !self.config.federation_domain_allowed(entity.domainpart()) {
            return false;
        }
        let policy = self.federation_runtime_policy.load();
        let matches = |rule: &str| federation_rule_matches(rule, &entity);
        !policy.blacklist.iter().any(|entry| matches(entry))
            && (policy.whitelist.is_empty() || policy.whitelist.iter().any(|entry| matches(entry)))
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
