//! Federation resolver construction policy.

use anyhow::Context;
use hickory_resolver::{
    config::{ResolveHosts, ServerOrderingStrategy},
    net::runtime::TokioRuntimeProvider,
    system_conf::read_system_conf,
    TokioResolver,
};
use std::{path::Path, sync::Arc, time::Duration};

pub struct FederationResolvers {
    pub s2s: TokioResolver,
    pub dnssec: Option<TokioResolver>,
}

pub fn federation_resolvers(
    dane_mode: crate::dane::DaneMode,
    lab_trust_anchor_path: Option<&Path>,
) -> anyhow::Result<FederationResolvers> {
    let (resolver_config, mut resolver_options) =
        read_system_conf().context("failed to read the system DNS resolver configuration")?;
    resolver_options.try_tcp_on_error = true;
    resolver_options.server_ordering_strategy = ServerOrderingStrategy::RoundRobin;
    resolver_options.cache_size = 1024;
    let mut dnssec_options = resolver_options.clone();
    dnssec_options.validate = true;
    dnssec_options.use_hosts_file = ResolveHosts::Never;
    dnssec_options.preserve_intermediates = true;
    dnssec_options.positive_max_ttl = Some(Duration::from_secs(24 * 60 * 60));
    dnssec_options.negative_max_ttl = Some(Duration::from_secs(5 * 60));
    let s2s_dns_resolver = TokioResolver::builder_with_config(
        resolver_config.clone(),
        TokioRuntimeProvider::default(),
    )
    .with_options(resolver_options)
    .build()
    .context("failed to initialize the asynchronous DNS resolver")?;
    let lab_dnssec_anchor = lab_trust_anchor_path
        .map(crate::lab_dnssec::load_anchor)
        .transpose()?;
    let s2s_dnssec_resolver = (dane_mode != crate::dane::DaneMode::Off)
        .then(|| {
            let mut builder = TokioResolver::builder_with_config(
                resolver_config,
                TokioRuntimeProvider::default(),
            )
            .with_options(dnssec_options);
            if let Some(anchor) = lab_dnssec_anchor {
                builder = builder.with_trust_anchor(Arc::new(anchor));
            }
            builder
                .build()
                .context("failed to initialize the locally validating DNSSEC resolver")
        })
        .transpose()?;
    Ok(FederationResolvers {
        s2s: s2s_dns_resolver,
        dnssec: s2s_dnssec_resolver,
    })
}
