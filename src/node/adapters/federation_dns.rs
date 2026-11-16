//! Builds federation endpoint discovery's view of the composition root (`northstar_s2s::dns`).

use crate::node::ServerNode;
use northstar_s2s::dns::FederationDnsContext;

impl ServerNode {
    pub(crate) fn federation_dns_context(&self) -> FederationDnsContext<'_> {
        FederationDnsContext {
            resolver: self.s2s_dns_resolver(),
            overrides: &self.config.federation_dns_overrides,
            dane_required: self.config.s2s_dane_required(),
            private_addresses_allowed: self.config.federation_allow_private_ips,
            tls: &self.tls_context,
        }
    }
}
