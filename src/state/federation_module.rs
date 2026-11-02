//! The federation context as the composition root builds it: outbox services, route and
//! resumption tables, component credentials, DNS resolvers, connection admission, dialback
//! material and the island-mode and runtime policies.

use super::*;

/// The federation context's runtime parts, built once at startup.
pub(super) struct FederationModule {
    pub(super) s2s_outbox_dispatch_service:
        northstar_federation_application::dispatch::S2sOutboxDispatchService<
            northstar_federation_postgres::dispatch_repository::PostgresS2sOutboxDispatchRepository,
        >,
    pub(super) s2s_sm_outbox_service: northstar_federation_application::sm_outbox::SmOutboxService<
        northstar_federation_postgres::sm_outbox_repository::PostgresSmOutboxRepository,
    >,
    pub(super) federation_outbox: FederationRouter,
    /// Full XEP-0114/XEP-0225 authentication records. `config.components`
    /// retains only redacted routing/discovery metadata after construction.
    pub(super) component_credentials: Arc<[northstar_config::ComponentCredential]>,
    pub(super) components: northstar_federation_application::components::ComponentRegistry,
    pub(super) s2s_connection_registry: Arc<S2sConnectionRegistry>,
    pub(super) s2s_resumption: crate::s2s::resume::Registry,
    /// Shared TTL-aware resolver for SRV, CNAME, A and AAAA federation lookups.
    pub(super) s2s_dns_resolver: TokioResolver,
    /// Separate locally validating DNSSEC resolver for RFC 7712. It never
    /// consults the hosts file and is absent when DANE is disabled, ensuring
    /// that an ordinary resolver answer can never be mistaken for secure
    /// TLSA material.
    pub(super) s2s_dnssec_resolver: Option<TokioResolver>,
    pub(super) dialback_secret: Zeroizing<Vec<u8>>,
    pub(super) dialback_verifications: Arc<Semaphore>,
    /// The unauthenticated OMEMO source completion capability is bounded
    /// independently from the general API and database pool. Keys are trusted-
    /// proxy-resolved IP addresses and expire from the one-minute window.
    pub(super) s2s_connections: Arc<Semaphore>,
    pub(super) s2s_connection_attempts: Arc<Semaphore>,
    pub(super) component_connections: Arc<Semaphore>,
    /// Linearization gate for the federation kill switch. Application
    /// stanza writes hold a read guard only across the socket write; island
    /// mode transitions take the exclusive guard.
    pub(super) federation_write_policy: Arc<FederationWritePolicy>,
    /// Durable XEP-0133 federation policy overlay. Static environment policy
    /// remains the outer ceiling; runtime rules may only restrict it further.
    pub(super) federation_runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
}

/// What the federation context is built from. Component credentials and the dialback secret
/// arrive here after `AppState::new` has taken them out of the configuration.
pub(super) struct FederationModuleParts<'a> {
    pub(super) config: &'a Config,
    pub(super) pool: &'a PgPool,
    pub(super) federation_outbox: FederationRouter,
    pub(super) component_credentials: Arc<[northstar_config::ComponentCredential]>,
    pub(super) components: northstar_federation_application::components::ComponentRegistry,
    pub(super) dialback_secret: Zeroizing<Vec<u8>>,
    pub(super) island_mode: bool,
    pub(super) runtime_blacklist: Vec<String>,
    pub(super) runtime_whitelist: Vec<String>,
}

impl FederationModule {
    /// Builds the resolvers from the system DNS configuration and the services over the primary
    /// pool.
    pub(super) fn new(parts: FederationModuleParts<'_>) -> anyhow::Result<Self> {
        let FederationModuleParts {
            config,
            pool,
            federation_outbox,
            component_credentials,
            components,
            dialback_secret,
            island_mode,
            runtime_blacklist,
            runtime_whitelist,
        } = parts;
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
        let lab_dnssec_anchor = config
            .federation_dnssec_lab_trust_anchor_path
            .as_deref()
            .map(northstar_security::lab_dnssec::load_anchor)
            .transpose()?;
        let s2s_dnssec_resolver = (config.federation_dane_mode
            != northstar_security::dane::DaneMode::Off)
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
        Ok(Self {
            s2s_outbox_dispatch_service:
            northstar_federation_application::dispatch::S2sOutboxDispatchService::new(
                northstar_federation_postgres::dispatch_repository::PostgresS2sOutboxDispatchRepository::new(
                    pool.clone(),
                ),
                northstar_federation_application::dispatch::S2sOutboxDispatchPolicy {
                    claim_batch: config.s2s_outbox_claim_batch,
                    lease_seconds: config.s2s_outbox_lease_seconds,
                    retry_base_seconds: config.s2s_outbox_retry_base_seconds,
                    retry_max_seconds: config.s2s_outbox_retry_max_seconds,
                    max_attempts: config.s2s_outbox_max_attempts,
                },
            ),
            s2s_sm_outbox_service: northstar_federation_application::sm_outbox::SmOutboxService::new(
                northstar_federation_postgres::sm_outbox_repository::PostgresSmOutboxRepository::new(pool.clone()),
            ),
            federation_outbox,
            component_credentials,
            components,
            s2s_connection_registry: Arc::new(S2sConnectionRegistry::default()),
            s2s_resumption: crate::s2s::resume::Registry::default(),
            s2s_dns_resolver,
            s2s_dnssec_resolver,
            dialback_secret,
            dialback_verifications: Arc::new(Semaphore::new(64)),
            s2s_connections: Arc::new(Semaphore::new(config.max_s2s_connections)),
            s2s_connection_attempts: Arc::new(Semaphore::new(config.max_s2s_connections)),
            component_connections: Arc::new(Semaphore::new(config.max_component_connections)),
            federation_write_policy: Arc::new(FederationWritePolicy::new(island_mode)),
            federation_runtime_policy: Arc::new(arc_swap::ArcSwap::from_pointee(
                RuntimeFederationPolicy {
                    blacklist: runtime_blacklist.into_iter().collect(),
                    whitelist: runtime_whitelist.into_iter().collect(),
                },
            )),
        })
    }
}
