//! The root's MUC endpoint delivery: northstar-stream's context over the PostgreSQL repositories and the
//! federation outbox, built from the composition root.

use crate::node::ServerNode;
use northstar_room_application::cluster_muc_receipt_claim::ClusterMucReceiptClaimService;
use northstar_workflows::muc_delivery_repository::PostgresMucDeliveryRepository;
use std::sync::Arc;

pub(crate) type MucDeliveryContext = northstar_stream::muc_delivery::MucDeliveryContext<
    northstar_workflows::muc_delivery_repository::PostgresMucDeliveryRepository,
    northstar_room_postgres::cluster_muc_receipt_claim_repository::PostgresClusterMucReceiptClaimRepository,
    crate::node::FederationRouter,
>;

impl ServerNode {
    pub(crate) fn muc_delivery_context(&self) -> MucDeliveryContext {
        MucDeliveryContext {
            repository: PostgresMucDeliveryRepository::new(self.pool.clone()),
            receipt_claim: ClusterMucReceiptClaimService::new(
                northstar_room_postgres::cluster_muc_receipt_claim_repository::PostgresClusterMucReceiptClaimRepository::new(
                    self.pool.clone(),
                ),
            ),
            local_domain: self.config.domain.clone(),
            sessions: Arc::clone(self.session.live().sessions()),
            muc_occupants: Arc::clone(&self.room.muc_occupants),
            suspended_muc_sessions: Arc::clone(&self.room.suspended_muc_sessions),
            sm_memory_governor: Arc::clone(&self.session.sm_memory_governor),
            sm_max_unacked_stanzas: self.config.sm_max_unacked_stanzas,
            sm_max_unacked_bytes: self.config.sm_max_unacked_bytes,
            federation_outbox: self.federation.federation_outbox.clone(),
        }
    }
}
