pub(crate) mod components;
pub mod inbound;
pub mod outbound;
mod sm;

pub use inbound::*;
use northstar_federation_application::endpoint::FederationEndpoint;
use northstar_federation_application::registry::*;
use northstar_federation_core::dialback::*;
use northstar_federation_core::wire::*;
use northstar_federation_core::{
    same_dialback_domain, AdvertisedStreamLimits, DialbackOutcome, DIALBACK_NS, IO_TIMEOUT,
    S2S_AUTHENTICATED_IDLE_TIMEOUT, STREAM_LIMITS_NS,
};
use northstar_s2s::dns::*;
use northstar_s2s::tls::*;
use northstar_s2s::util::*;
pub(crate) use outbound::*;

pub use northstar_federation_application::{FederationDeliveryMode, FederationEnvelope};

/// Application service backing the private federation outbox capability.
pub(crate) type FederationRouter =
    northstar_federation_application::outbox::FederationOutboxService<
        northstar_federation_postgres::outbox_repository::PostgresFederationOutboxRepository,
    >;
