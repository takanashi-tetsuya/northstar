pub mod inbound;

pub(crate) use inbound::*;
use northstar_federation_core::wire::*;

/// Application service backing the private federation outbox capability.
pub(crate) type FederationRouter =
    northstar_federation_application::outbox::FederationOutboxService<
        northstar_federation_postgres::outbox_repository::PostgresFederationOutboxRepository,
    >;
