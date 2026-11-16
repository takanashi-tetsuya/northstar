//! The node's capabilities as the server-to-server transport and external components see them.

use super::AppState;
use hickory_resolver::TokioResolver;
use northstar_config::ComponentCredential;
use northstar_federation_application::components::{ComponentRegistry, ComponentTelemetry};
use northstar_federation_application::dispatch::S2sOutboxDispatchService;
use northstar_federation_application::outbox::FederationOutboxService;
use northstar_federation_application::registry::S2sConnectionRegistry;
use northstar_federation_application::sm_outbox::SmOutboxService;
use northstar_federation_application::telemetry::{
    InboundConnectionTelemetry, OutboundDispositionTelemetry, OutboxDeliveryTelemetry,
};
use northstar_federation_core::dialback::S2sFeaturePolicy;
use northstar_federation_postgres::dispatch_repository::PostgresS2sOutboxDispatchRepository;
use northstar_federation_postgres::outbox_repository::PostgresFederationOutboxRepository;
use northstar_federation_postgres::sm_outbox_repository::PostgresSmOutboxRepository;
use northstar_runtime::connection_actors::ConnectionActorRegistry;
use northstar_s2s::dns::FederationDnsContext;
use northstar_s2s::host::{ComponentHost, ComponentRuntimePolicy, InboundFederationRoute, S2sHost};
use northstar_s2s::outbox::{S2sOutboxDispatchContext, S2sOutboxFailureEffects};
use northstar_s2s::resume;
use northstar_security::dane::DaneMode;
use northstar_security::tls::TlsContext;
use std::{sync::Arc, time::Duration};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, RwLockReadGuard, TryAcquireError};
use uuid::Uuid;

impl S2sHost for AppState {
    type OutboxStore = PostgresFederationOutboxRepository;
    type DispatchStore = PostgresS2sOutboxDispatchRepository;
    type SmOutboxStore = PostgresSmOutboxRepository;

    fn local_domain(&self) -> &str {
        &self.config.domain
    }

    fn island_mode_enabled(&self) -> bool {
        self.federation.federation_write_policy.enabled()
    }

    async fn federation_delivery_permit(&self) -> Option<RwLockReadGuard<'_, ()>> {
        AppState::federation_delivery_permit(self).await
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        AppState::federation_domain_allowed(self, domain)
    }

    fn s2s_federation_enabled(&self) -> bool {
        self.config.federation_enabled
    }

    fn s2s_dialback_enabled(&self) -> bool {
        self.config.dialback_enabled
    }

    fn s2s_sasl_external_enabled(&self) -> bool {
        self.config.s2s_sasl_external_enabled
    }

    fn s2s_ocsp_staple_required(&self) -> bool {
        self.config.federation_ocsp_staple_required
    }

    fn s2s_dane_mode(&self) -> DaneMode {
        self.config.federation_dane_mode
    }

    fn s2s_feature_policy(&self) -> S2sFeaturePolicy {
        northstar_federation_core::dialback::S2sFeaturePolicy {
            sasl_external: self.config.s2s_sasl_external_enabled,
            dialback: self.config.dialback_enabled,
            bidi: self.config.federation_enabled,
        }
    }

    fn tls_context(&self) -> &TlsContext {
        &self.tls_context
    }

    fn federation_dns_context(&self) -> FederationDnsContext<'_> {
        AppState::federation_dns_context(self)
    }

    fn s2s_dnssec_resolver(&self) -> Option<&TokioResolver> {
        AppState::s2s_dnssec_resolver(self)
    }

    fn derive_dialback_key(
        &self,
        receiving_domain: &str,
        originating_domain: &str,
        stream_id: &str,
    ) -> String {
        self.federation
            .derive_dialback_key(receiving_domain, originating_domain, stream_id)
    }

    fn connection_actors(&self) -> &ConnectionActorRegistry {
        AppState::connection_actors(self)
    }

    fn try_acquire_s2s_connection(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        AppState::try_acquire_s2s_connection(self)
    }

    fn try_acquire_dialback_verification(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        AppState::try_acquire_dialback_verification(self)
    }

    async fn acquire_s2s_connection_attempt(&self) -> Result<OwnedSemaphorePermit, AcquireError> {
        AppState::acquire_s2s_connection_attempt(self).await
    }

    fn s2s_connection_registry(&self) -> &S2sConnectionRegistry {
        AppState::s2s_connection_registry(self)
    }

    fn s2s_resumption(&self) -> &resume::Registry {
        AppState::s2s_resumption(self)
    }

    fn federation_outbox(&self) -> &FederationOutboxService<PostgresFederationOutboxRepository> {
        &self.federation.federation_outbox
    }

    fn s2s_outbox_dispatch_service(
        &self,
    ) -> &S2sOutboxDispatchService<PostgresS2sOutboxDispatchRepository> {
        self.federation.s2s_outbox_dispatch_service()
    }

    fn s2s_sm_outbox_service(&self) -> &SmOutboxService<PostgresSmOutboxRepository> {
        self.federation.s2s_sm_outbox_service()
    }

    fn s2s_outbox_dispatch_context(
        &self,
    ) -> S2sOutboxDispatchContext<PostgresS2sOutboxDispatchRepository> {
        AppState::s2s_outbox_dispatch_context(self)
    }

    fn s2s_outbox_failure_effects(
        &self,
    ) -> S2sOutboxFailureEffects<PostgresS2sOutboxDispatchRepository> {
        AppState::s2s_outbox_failure_effects(self)
    }

    fn s2s_inbound_connection_telemetry(&self) -> InboundConnectionTelemetry<'_> {
        northstar_federation_application::telemetry::InboundConnectionTelemetry::new(
            &self.metrics.federation_inbound_connections_total,
            &self.metrics.federation_inbound_active,
        )
    }

    fn s2s_outbox_delivery_telemetry(&self) -> OutboxDeliveryTelemetry<'_> {
        northstar_federation_application::telemetry::OutboxDeliveryTelemetry::new(
            &self.metrics.outbox_delivery_duration_seconds,
        )
    }

    fn s2s_outbound_disposition_telemetry(&self) -> OutboundDispositionTelemetry<'_> {
        northstar_federation_application::telemetry::OutboundDispositionTelemetry::new(
            &self.metrics.federation_failures_total,
            &self.metrics.s2s_outbox_lease_lost_total,
            &self.metrics.federation_outbound_deliveries_total,
            &self.metrics.s2s_outbox_permanent_failures_total,
            &self.metrics.s2s_outbox_expired_total,
            &self.metrics.s2s_outbox_retries_total,
        )
    }

    async fn route_inbound_stanza(
        self: Arc<Self>,
        authenticated_domain: String,
        local_domain: String,
        connection_id: Uuid,
        raw: String,
    ) -> anyhow::Result<InboundFederationRoute> {
        northstar_s2s::inbound::route_inbound_for_connection(
            &self,
            &authenticated_domain,
            &local_domain,
            connection_id,
            &raw,
        )
        .await
    }

    async fn federated_caps_connection_closed(&self, connection_id: Uuid) {
        crate::xmpp::protocol::caps::federated_caps_connection_closed(self, connection_id).await;
    }

    async fn federated_muc_connection_closed(
        &self,
        peer_domain: &str,
        connection_id: Uuid,
    ) -> anyhow::Result<()> {
        northstar_muc_xmpp::federated_muc::federated_muc_connection_closed(
            self,
            peer_domain,
            connection_id,
        )
        .await
    }
}

impl ComponentHost for AppState {
    fn component_runtime_policy(&self) -> ComponentRuntimePolicy {
        AppState::component_runtime_policy(self)
    }

    fn component_registry(&self) -> &ComponentRegistry {
        AppState::component_registry(self)
    }

    fn component_telemetry(&self) -> ComponentTelemetry<'_> {
        northstar_federation_application::components::ComponentTelemetry::new(
            &self.metrics.component_connections_active,
            &self.metrics.outbox_delivery_duration_seconds,
            &self.metrics.component_failures_total,
            &self.metrics.component_deliveries_total,
            &self.metrics.s2s_outbox_lease_lost_total,
        )
    }

    fn has_component_credentials(&self) -> bool {
        AppState::has_component_credentials(self)
    }

    fn accepts_component_connections(&self) -> bool {
        AppState::accepts_component_connections(self)
    }

    fn component_connect_credentials(&self) -> Vec<ComponentCredential> {
        AppState::component_connect_credentials(self)
    }

    fn component_authentication_credential(&self, domain: &str) -> Option<ComponentCredential> {
        AppState::component_authentication_credential(self, domain)
    }

    fn xmpp_component_domain_configured(&self, domain: &str) -> bool {
        self.config.component_domain_configured(domain)
    }

    fn try_acquire_component_connection(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        AppState::try_acquire_component_connection(self)
    }

    async fn acquire_component_connection(&self) -> Result<OwnedSemaphorePermit, AcquireError> {
        AppState::acquire_component_connection(self).await
    }

    async fn route_inbound_component_stanza(
        self: Arc<Self>,
        authenticated_domain: String,
        connection_id: Uuid,
        raw: String,
    ) -> anyhow::Result<Option<String>> {
        northstar_s2s::inbound::route_inbound_component(
            &self,
            &authenticated_domain,
            connection_id,
            &raw,
        )
        .await
    }
}

impl AppState {
    /// Cached ordinary DNS resolver used only by the federation discovery
    /// layer. Keeping it private prevents unrelated code from bypassing the
    /// S2S endpoint-validation path.
    pub(crate) fn s2s_dns_resolver(&self) -> &TokioResolver {
        &self.federation.s2s_dns_resolver
    }

    /// Locally validating resolver dedicated to DANE policy construction.
    pub(crate) fn s2s_dnssec_resolver(&self) -> Option<&TokioResolver> {
        self.federation.s2s_dnssec_resolver.as_ref()
    }

    /// Admit one bounded authoritative dialback verification without exposing
    /// or allowing replacement of the underlying global semaphore.
    pub(crate) fn try_acquire_dialback_verification(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.federation.dialback_verifications).try_acquire_owned()
    }

    /// Admit one process-local federation connection while keeping the global
    /// capacity semaphore replace-proof and unavailable to unrelated code.
    pub(crate) fn try_acquire_s2s_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.federation.s2s_connections).try_acquire_owned()
    }

    /// Wait for one bounded outbound federation dial attempt. Returning the
    /// original acquire error preserves the caller's existing timeout and
    /// closed-semaphore diagnostics.
    pub(crate) async fn acquire_s2s_connection_attempt(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.federation.s2s_connection_attempts)
            .acquire_owned()
            .await
    }

    /// Owner-fenced process-local S2S route registry. Its API returns cloned
    /// senders and value snapshots only; callers cannot obtain DashMap guards.
    pub(crate) fn s2s_connection_registry(&self) -> &S2sConnectionRegistry {
        &self.federation.s2s_connection_registry
    }

    /// Suspended S2S streams. These hold live TLS transports, so they stay out
    /// of the route registry above.
    pub(crate) fn s2s_resumption(&self) -> &northstar_s2s::resume::Registry {
        &self.federation.s2s_resumption
    }

    /// Admit an inbound component socket without exposing the semaphore as a
    /// generally clonable capability.
    pub(crate) fn try_acquire_component_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.federation.component_connections).try_acquire_owned()
    }

    /// Wait for a component slot while preserving cancellation through the
    /// caller's `select!` and the original closed-semaphore error.
    pub(crate) async fn acquire_component_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.federation.component_connections)
            .acquire_owned()
            .await
    }

    /// Acquire the application-stanza write boundary and revalidate island
    /// mode after route admission. The caller holds the returned guard over
    /// the socket write, making a completed policy transition linearizable.
    pub(crate) async fn federation_delivery_permit(
        &self,
    ) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        self.federation.federation_write_policy.permit().await
    }

    pub(crate) fn has_component_credentials(&self) -> bool {
        !self.federation.component_credentials.is_empty()
    }

    pub(crate) fn component_runtime_policy(&self) -> ComponentRuntimePolicy {
        ComponentRuntimePolicy {
            enabled: self.config.components_enabled,
            max_connections: self.config.max_component_connections,
            handshake_timeout: Duration::from_secs(self.config.component_handshake_timeout_seconds),
            queue_capacity: self.config.component_queue_capacity,
        }
    }

    /// Authenticated external-component ownership and wake-up authority.
    /// The registry exposes only owner-fenced operations; its concurrent map
    /// remains encapsulated inside the component subsystem.
    pub(crate) fn component_registry(
        &self,
    ) -> &northstar_federation_application::components::ComponentRegistry {
        &self.federation.components
    }

    /// Redacted configured routing domains used by observability and the S2S
    /// outbox exclusion query. Preserve the original Vec semantics, including
    /// configuration order and any duplicates across credentials.
    pub(crate) fn configured_component_domains(&self) -> Vec<String> {
        self.config
            .components
            .iter()
            .flat_map(|credential| credential.allowed_domains.iter().cloned())
            .collect()
    }

    pub(crate) fn component_connect_credentials(
        &self,
    ) -> Vec<northstar_config::ComponentCredential> {
        self.federation
            .component_credentials
            .iter()
            .filter(|credential| {
                credential.connection == northstar_config::ComponentConnectionMode::Connect
            })
            .cloned()
            .collect()
    }

    pub(crate) fn accepts_component_connections(&self) -> bool {
        self.federation
            .component_credentials
            .iter()
            .any(|credential| {
                credential.connection == northstar_config::ComponentConnectionMode::Accept
            })
    }

    pub(crate) fn component_authentication_credential(
        &self,
        domain: &str,
    ) -> Option<northstar_config::ComponentCredential> {
        let domain = northstar_xmpp_types::jid::prepare_domainpart(domain).ok()?;
        self.federation
            .component_credentials
            .iter()
            .find(|credential| {
                credential
                    .allowed_domains
                    .iter()
                    .any(|allowed| allowed == &domain)
            })
            .cloned()
    }
}
