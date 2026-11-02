//! What the server-to-server transport needs from the node that runs it: the served domain and
//! the federation policy, TLS, discovery and dialback material, admission and the connection
//! actors, the registries of authenticated and resumable routes, the federation outbox and its
//! dispatch, the federation metrics, and the three ways a connection reaches back into the node:
//! routing a peer's stanza and cleaning up what a closed connection left in the entity
//! capabilities cache and in federated rooms. The node implements this once; the inbound and
//! outbound connection actors stay generic over it, so they never name the node's state. External
//! components (XEP-0114 and XEP-0225) need [`ComponentHost`] on top of it.

use crate::dns::FederationDnsContext;
use crate::outbox::{S2sOutboxDispatchContext, S2sOutboxFailureEffects};
use crate::resume;
use hickory_resolver::TokioResolver;
use northstar_config::ComponentCredential;
use northstar_federation_application::components::{ComponentRegistry, ComponentTelemetry};
use northstar_federation_application::dispatch::{
    S2sOutboxDispatchRepository, S2sOutboxDispatchService,
};
use northstar_federation_application::outbox::{
    FederationOutboxRepository, FederationOutboxService,
};
use northstar_federation_application::registry::S2sConnectionRegistry;
use northstar_federation_application::sm_outbox::{SmOutboxRepository, SmOutboxService};
use northstar_federation_application::telemetry::{
    InboundConnectionTelemetry, OutboundDispositionTelemetry, OutboxDeliveryTelemetry,
};
use northstar_federation_core::dialback::S2sFeaturePolicy;
use northstar_runtime::connection_actors::ConnectionActorRegistry;
use northstar_security::dane::DaneMode;
use northstar_security::tls::TlsContext;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, RwLockReadGuard, TryAcquireError};
use uuid::Uuid;

/// What the node made of a stanza a peer sent over an authenticated stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundFederationRoute {
    /// Accepted; the reply, if any, goes back over the same stream.
    Reply(Option<String>),
    /// The stanza violates the stream; it closes with this condition.
    StreamError(&'static str),
}

pub trait S2sHost: Send + Sync + 'static {
    /// The repository behind the durable federation outbox.
    type OutboxStore: FederationOutboxRepository + 'static;

    /// The repository behind outbox claims, leases and retries.
    type DispatchStore: S2sOutboxDispatchRepository + Clone + 'static;

    /// The repository behind the claims a stream management window holds.
    type SmOutboxStore: SmOutboxRepository + 'static;

    /// The served domain.
    fn local_domain(&self) -> &str;

    /// Island mode suspends all federation traffic.
    fn island_mode_enabled(&self) -> bool;

    /// Holds off island mode for one socket write; `None` once island mode is on.
    fn federation_delivery_permit(
        &self,
    ) -> impl Future<Output = Option<RwLockReadGuard<'_, ()>>> + Send;

    /// Whether the static and runtime federation policies admit `domain` as a peer.
    fn federation_domain_allowed(&self, domain: &str) -> bool;

    fn s2s_federation_enabled(&self) -> bool;

    fn s2s_dialback_enabled(&self) -> bool;

    fn s2s_sasl_external_enabled(&self) -> bool;

    fn s2s_ocsp_staple_required(&self) -> bool;

    fn s2s_dane_mode(&self) -> DaneMode;

    /// The stream features offered to and expected from a peer.
    fn s2s_feature_policy(&self) -> S2sFeaturePolicy;

    /// The current server TLS configuration.
    fn tls_context(&self) -> &TlsContext;

    /// Endpoint discovery for a peer domain.
    fn federation_dns_context(&self) -> FederationDnsContext<'_>;

    /// The locally validating resolver DANE policies are built from, when DANE is on.
    fn s2s_dnssec_resolver(&self) -> Option<&TokioResolver>;

    /// The XEP-0185 dialback key for one stream.
    fn derive_dialback_key(
        &self,
        receiving_domain: &str,
        originating_domain: &str,
        stream_id: &str,
    ) -> String;

    /// The registry that owns and drains connection tasks.
    fn connection_actors(&self) -> &ConnectionActorRegistry;

    /// Admits one more S2S connection, or refuses it at the configured capacity.
    fn try_acquire_s2s_connection(&self) -> Result<OwnedSemaphorePermit, TryAcquireError>;

    /// Admits one more dialback verification, or refuses it at the configured capacity.
    fn try_acquire_dialback_verification(&self) -> Result<OwnedSemaphorePermit, TryAcquireError>;

    /// Waits for an outbound connection attempt slot.
    fn acquire_s2s_connection_attempt(
        &self,
    ) -> impl Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send;

    /// The authenticated and bidirectional routes to peers.
    fn s2s_connection_registry(&self) -> &S2sConnectionRegistry;

    /// Streams a peer may resume.
    fn s2s_resumption(&self) -> &resume::Registry;

    fn federation_outbox(&self) -> &FederationOutboxService<Self::OutboxStore>;

    fn s2s_outbox_dispatch_service(&self) -> &S2sOutboxDispatchService<Self::DispatchStore>;

    fn s2s_sm_outbox_service(&self) -> &SmOutboxService<Self::SmOutboxStore>;

    fn s2s_outbox_dispatch_context(&self) -> S2sOutboxDispatchContext<Self::DispatchStore>;

    fn s2s_outbox_failure_effects(&self) -> S2sOutboxFailureEffects<Self::DispatchStore>;

    fn s2s_inbound_connection_telemetry(&self) -> InboundConnectionTelemetry<'_>;

    fn s2s_outbox_delivery_telemetry(&self) -> OutboxDeliveryTelemetry<'_>;

    fn s2s_outbound_disposition_telemetry(&self) -> OutboundDispositionTelemetry<'_>;

    /// Routes a stanza that `authenticated_domain` sent to `local_domain` over connection
    /// `connection_id`.
    fn route_inbound_stanza(
        self: Arc<Self>,
        authenticated_domain: String,
        local_domain: String,
        connection_id: Uuid,
        raw: String,
    ) -> impl Future<Output = anyhow::Result<InboundFederationRoute>> + Send;

    /// Forgets the entity capabilities learned over a connection that closed.
    fn federated_caps_connection_closed(
        &self,
        connection_id: Uuid,
    ) -> impl Future<Output = ()> + Send;

    /// Removes the room occupants `peer_domain` joined over a connection that closed.
    fn federated_muc_connection_closed(
        &self,
        peer_domain: &str,
        connection_id: Uuid,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// The configured limits of external component connections.
#[derive(Clone, Copy)]
pub struct ComponentRuntimePolicy {
    pub enabled: bool,
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub queue_capacity: usize,
}

/// What external component connections need from the node beyond [`S2sHost`]: their limits and
/// credentials, admission, the registry of the domains each connection has bound, their metrics,
/// and routing a component's stanza into the node.
pub trait ComponentHost: S2sHost {
    fn component_runtime_policy(&self) -> ComponentRuntimePolicy;

    /// Which connection owns each bound component domain.
    fn component_registry(&self) -> &ComponentRegistry;

    fn component_telemetry(&self) -> ComponentTelemetry<'_>;

    fn has_component_credentials(&self) -> bool;

    /// Whether any credential lets a component connect to the node.
    fn accepts_component_connections(&self) -> bool;

    /// The credentials of the components the node connects to itself.
    fn component_connect_credentials(&self) -> Vec<ComponentCredential>;

    /// The credential a component authenticating as `domain` must present.
    fn component_authentication_credential(&self, domain: &str) -> Option<ComponentCredential>;

    fn xmpp_component_domain_configured(&self, domain: &str) -> bool;

    /// Admits one more component connection, or refuses it at the configured capacity.
    fn try_acquire_component_connection(&self) -> Result<OwnedSemaphorePermit, TryAcquireError>;

    /// Waits for a component connection slot.
    fn acquire_component_connection(
        &self,
    ) -> impl Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send;

    /// Routes a stanza the component authenticated as `authenticated_domain` sent over
    /// connection `connection_id`. Everything is owned, so no parser borrow outlives the
    /// component actor's await.
    fn route_inbound_component_stanza(
        self: Arc<Self>,
        authenticated_domain: String,
        connection_id: Uuid,
        raw: String,
    ) -> impl Future<Output = anyhow::Result<Option<String>>> + Send;
}
