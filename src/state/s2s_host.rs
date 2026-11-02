//! The node's capabilities as the server-to-server transport sees them.

use super::AppState;
use hickory_resolver::TokioResolver;
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
use northstar_s2s::host::{InboundFederationRoute, S2sHost};
use northstar_s2s::outbox::{S2sOutboxDispatchContext, S2sOutboxFailureEffects};
use northstar_s2s::resume;
use northstar_security::dane::DaneMode;
use northstar_security::tls::TlsContext;
use std::sync::Arc;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, RwLockReadGuard, TryAcquireError};
use uuid::Uuid;

impl S2sHost for AppState {
    type OutboxStore = PostgresFederationOutboxRepository;
    type DispatchStore = PostgresS2sOutboxDispatchRepository;
    type SmOutboxStore = PostgresSmOutboxRepository;

    fn local_domain(&self) -> &str {
        AppState::local_domain(self)
    }

    fn island_mode_enabled(&self) -> bool {
        AppState::island_mode_enabled(self)
    }

    async fn federation_delivery_permit(&self) -> Option<RwLockReadGuard<'_, ()>> {
        AppState::federation_delivery_permit(self).await
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        AppState::federation_domain_allowed(self, domain)
    }

    fn s2s_federation_enabled(&self) -> bool {
        AppState::s2s_federation_enabled(self)
    }

    fn s2s_dialback_enabled(&self) -> bool {
        AppState::s2s_dialback_enabled(self)
    }

    fn s2s_sasl_external_enabled(&self) -> bool {
        AppState::s2s_sasl_external_enabled(self)
    }

    fn s2s_ocsp_staple_required(&self) -> bool {
        AppState::s2s_ocsp_staple_required(self)
    }

    fn s2s_dane_mode(&self) -> DaneMode {
        AppState::s2s_dane_mode(self)
    }

    fn s2s_feature_policy(&self) -> S2sFeaturePolicy {
        AppState::s2s_feature_policy(self)
    }

    fn tls_context(&self) -> &TlsContext {
        AppState::tls_context(self)
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
        AppState::derive_dialback_key(self, receiving_domain, originating_domain, stream_id)
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
        AppState::federation_outbox(self)
    }

    fn s2s_outbox_dispatch_service(
        &self,
    ) -> &S2sOutboxDispatchService<PostgresS2sOutboxDispatchRepository> {
        AppState::s2s_outbox_dispatch_service(self)
    }

    fn s2s_sm_outbox_service(&self) -> &SmOutboxService<PostgresSmOutboxRepository> {
        AppState::s2s_sm_outbox_service(self)
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
        AppState::s2s_inbound_connection_telemetry(self)
    }

    fn s2s_outbox_delivery_telemetry(&self) -> OutboxDeliveryTelemetry<'_> {
        AppState::s2s_outbox_delivery_telemetry(self)
    }

    fn s2s_outbound_disposition_telemetry(&self) -> OutboundDispositionTelemetry<'_> {
        AppState::s2s_outbound_disposition_telemetry(self)
    }

    async fn route_inbound_stanza(
        self: Arc<Self>,
        authenticated_domain: String,
        local_domain: String,
        connection_id: Uuid,
        raw: String,
    ) -> anyhow::Result<InboundFederationRoute> {
        crate::s2s::route_inbound_for_connection(
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
