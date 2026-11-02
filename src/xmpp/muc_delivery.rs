//! The root's MUC endpoint delivery: northstar-stream's context over the PostgreSQL repositories and the
//! federation outbox.

pub(crate) type MucDeliveryContext = northstar_stream::muc_delivery::MucDeliveryContext<
    northstar_workflows::muc_delivery_repository::PostgresMucDeliveryRepository,
    northstar_room_postgres::cluster_muc_receipt_claim_repository::PostgresClusterMucReceiptClaimRepository,
    crate::s2s::FederationRouter,
>;
