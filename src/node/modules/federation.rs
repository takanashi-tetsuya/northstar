//! The federation context as the composition root builds it: outbox services, route and
//! resumption tables, component credentials, DNS resolvers, connection admission, dialback
//! material and the island-mode and runtime policies.

use crate::node::*;
use northstar_federation_application::components::credentials::ComponentCredentials;
use northstar_federation_application::effective_policy::EffectiveFederationPolicy;

/// The federation context's runtime parts, built once at startup.
pub(in crate::node) struct FederationModule {
    pub(in crate::node) s2s_outbox_dispatch_service:
        northstar_federation_application::dispatch::S2sOutboxDispatchService<
            northstar_federation_postgres::dispatch_repository::PostgresS2sOutboxDispatchRepository,
        >,
    pub(in crate::node) s2s_sm_outbox_service:
        northstar_federation_application::sm_outbox::SmOutboxService<
            northstar_federation_postgres::sm_outbox_repository::PostgresSmOutboxRepository,
        >,
    pub(in crate::node) federation_outbox: FederationRouter,
    /// Full XEP-0114/XEP-0225 authentication records. `config.components`
    /// retains only redacted routing/discovery metadata after construction.
    pub(in crate::node) component_credentials: ComponentCredentials,
    pub(in crate::node) components: northstar_federation_application::components::ComponentRegistry,
    pub(in crate::node) s2s_connection_registry: Arc<S2sConnectionRegistry>,
    pub(in crate::node) s2s_resumption: northstar_s2s::resume::Registry,
    /// Shared TTL-aware resolver for SRV, CNAME, A and AAAA federation lookups.
    pub(in crate::node) s2s_dns_resolver: TokioResolver,
    /// Separate locally validating DNSSEC resolver for RFC 7712. It never
    /// consults the hosts file and is absent when DANE is disabled, ensuring
    /// that an ordinary resolver answer can never be mistaken for secure
    /// TLSA material.
    pub(in crate::node) s2s_dnssec_resolver: Option<TokioResolver>,
    pub(in crate::node) dialback_secret: Zeroizing<Vec<u8>>,
    pub(in crate::node) dialback_verifications: Arc<Semaphore>,
    /// The unauthenticated OMEMO source completion capability is bounded
    /// independently from the general API and database pool. Keys are trusted-
    /// proxy-resolved IP addresses and expire from the one-minute window.
    pub(in crate::node) s2s_connections: Arc<Semaphore>,
    pub(in crate::node) s2s_connection_attempts: Arc<Semaphore>,
    pub(in crate::node) component_connections: Arc<Semaphore>,
    /// Linearization gate for the federation kill switch. Application
    /// stanza writes hold a read guard only across the socket write; island
    /// mode transitions take the exclusive guard.
    pub(in crate::node) federation_write_policy: Arc<FederationWritePolicy>,
    /// Durable XEP-0133 federation policy overlay. Static environment policy
    /// remains the outer ceiling; runtime rules may only restrict it further.
    pub(in crate::node) federation_runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    pub(in crate::node) effective_policy: EffectiveFederationPolicy,
}

/// What the federation context is built from. Component credentials and the dialback secret
/// arrive here after `ServerNode::new` has taken them out of the configuration.
pub(in crate::node) struct FederationModuleParts<'a> {
    pub(in crate::node) config: &'a Config,
    pub(in crate::node) pool: &'a PgPool,
    pub(in crate::node) federation_outbox: FederationRouter,
    pub(in crate::node) component_credentials: Arc<[northstar_config::ComponentCredential]>,
    pub(in crate::node) components: northstar_federation_application::components::ComponentRegistry,
    pub(in crate::node) dialback_secret: Zeroizing<Vec<u8>>,
    pub(in crate::node) island_mode: bool,
    pub(in crate::node) runtime_blacklist: Vec<String>,
    pub(in crate::node) runtime_whitelist: Vec<String>,
}

impl FederationModule {
    pub(crate) fn s2s_outbox_dispatch_service(
        &self,
    ) -> &northstar_federation_application::dispatch::S2sOutboxDispatchService<
        northstar_federation_postgres::dispatch_repository::PostgresS2sOutboxDispatchRepository,
    > {
        &self.s2s_outbox_dispatch_service
    }

    pub(crate) fn s2s_sm_outbox_service(
        &self,
    ) -> &northstar_federation_application::sm_outbox::SmOutboxService<
        northstar_federation_postgres::sm_outbox_repository::PostgresSmOutboxRepository,
    > {
        &self.s2s_sm_outbox_service
    }

    pub(crate) fn derive_dialback_key(
        &self,
        receiving_domain: &str,
        originating_domain: &str,
        stream_id: &str,
    ) -> String {
        northstar_federation_core::compute_dialback_key(
            self.dialback_secret.as_slice(),
            receiving_domain,
            originating_domain,
            stream_id,
        )
    }

    /// Builds the resolvers from the system DNS configuration and the services over the primary
    /// pool.
    pub(in crate::node) fn new(parts: FederationModuleParts<'_>) -> anyhow::Result<Self> {
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
        let resolvers = northstar_security::dns_resolvers::federation_resolvers(
            config.federation_dane_mode,
            config.federation_dnssec_lab_trust_anchor_path.as_deref(),
        )?;
        let federation_runtime_policy =
            Arc::new(arc_swap::ArcSwap::from_pointee(RuntimeFederationPolicy {
                blacklist: runtime_blacklist.into_iter().collect(),
                whitelist: runtime_whitelist.into_iter().collect(),
            }));
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
            component_credentials: ComponentCredentials::new(component_credentials),
            components,
            s2s_connection_registry: Arc::new(S2sConnectionRegistry::default()),
            s2s_resumption: northstar_s2s::resume::Registry::default(),
            s2s_dns_resolver: resolvers.s2s,
            s2s_dnssec_resolver: resolvers.dnssec,
            dialback_secret,
            dialback_verifications: Arc::new(Semaphore::new(64)),
            s2s_connections: Arc::new(Semaphore::new(config.max_s2s_connections)),
            s2s_connection_attempts: Arc::new(Semaphore::new(config.max_s2s_connections)),
            component_connections: Arc::new(Semaphore::new(config.max_component_connections)),
            federation_write_policy: Arc::new(FederationWritePolicy::new(island_mode)),
            effective_policy: EffectiveFederationPolicy::new(
                config.external_route_domain_policy(),
                Arc::clone(&federation_runtime_policy),
            ),
            federation_runtime_policy,
        })
    }
}
