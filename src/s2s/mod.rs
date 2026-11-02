pub(crate) mod components;
pub mod dns;
pub mod inbound;
pub mod outbound;
pub(crate) mod resume;
mod sm;
pub mod tls;
pub mod util;

pub(crate) use dns::*;
pub use inbound::*;
use northstar_federation_application::registry::*;
use northstar_federation_core::dialback::*;
use northstar_federation_core::wire::*;
use northstar_federation_core::{
    same_dialback_domain, AdvertisedStreamLimits, DialbackOutcome, DIALBACK_NS, IO_TIMEOUT,
    MAX_S2S_STANZA_BYTES, S2S_AUTHENTICATED_IDLE_TIMEOUT, STREAM_LIMITS_NS,
};
pub(crate) use outbound::*;
pub(crate) use tls::*;
pub(crate) use util::*;

pub use northstar_federation_application::{FederationDeliveryMode, FederationEnvelope};

/// Application service backing the private federation outbox capability.
pub(crate) type FederationRouter =
    northstar_federation_application::outbox::FederationOutboxService<
        northstar_federation_postgres::outbox_repository::PostgresFederationOutboxRepository,
    >;
