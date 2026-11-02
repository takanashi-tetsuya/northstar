//! Builds federation endpoint discovery's view of the composition root (`northstar_s2s::dns`).

use super::AppState;
use northstar_s2s::dns::FederationDnsContext;

impl AppState {
    pub(crate) fn federation_dns_context(&self) -> FederationDnsContext<'_> {
        FederationDnsContext {
            resolver: self.s2s_dns_resolver(),
            overrides: &self.config.federation_dns_overrides,
            dane_required: self.s2s_dane_required(),
            private_addresses_allowed: self.s2s_private_addresses_allowed(),
            tls: self.tls_context(),
        }
    }
}
