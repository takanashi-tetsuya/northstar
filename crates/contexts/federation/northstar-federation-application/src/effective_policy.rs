//! Static federation ceiling combined with the shared runtime federation rules.

use arc_swap::ArcSwap;
use northstar_config::ExternalRouteDomainPolicy;
use northstar_federation_core::policy::RuntimeFederationPolicy;
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use std::sync::Arc;

#[derive(Clone)]
pub struct EffectiveFederationPolicy {
    static_policy: ExternalRouteDomainPolicy,
    runtime: Arc<ArcSwap<RuntimeFederationPolicy>>,
}

impl EffectiveFederationPolicy {
    pub fn new(
        static_policy: ExternalRouteDomainPolicy,
        runtime: Arc<ArcSwap<RuntimeFederationPolicy>>,
    ) -> Self {
        Self {
            static_policy,
            runtime,
        }
    }

    pub fn domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = prepare_domainpart(domain) else {
            return false;
        };
        self.static_policy.federation_domain_allowed(&domain)
            && self.runtime.load().allows_domain(&domain)
    }

    /// Check a domainpart that the caller has already prepared.
    pub fn prepared_domain_allowed(&self, domain: &str) -> bool {
        self.static_policy.federation_domain_allowed(domain)
            && self.runtime.load().allows_domain(domain)
    }

    /// Apply XEP-0133 entity rules using XEP-0016-style JID specificity: a
    /// domain rule matches the whole domain, a bare JID matches all of its
    /// resources, and a full JID matches exactly one resource.
    pub fn entity_allowed(&self, entity: &str) -> bool {
        let Ok(entity) = CanonicalJid::parse(entity) else {
            return false;
        };
        if !self
            .static_policy
            .federation_domain_allowed(entity.domainpart())
        {
            return false;
        }
        self.runtime.load().allows_entity(&entity)
    }

    pub fn replace_runtime_cache(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
        self.runtime.store(Arc::new(RuntimeFederationPolicy {
            blacklist: blacklist.into_iter().collect(),
            whitelist: whitelist.into_iter().collect(),
        }));
    }
}
