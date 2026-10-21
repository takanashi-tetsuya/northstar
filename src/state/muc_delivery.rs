//! Builds the purpose-limited MUC delivery context (`xmpp::muc_delivery`) from the composition root.

use super::AppState;
use crate::{
    db, db::muc_delivery_repository::PostgresMucDeliveryRepository,
    services::cluster_muc_receipt_claim::ClusterMucReceiptClaimService,
    xmpp::muc_delivery::MucDeliveryContext,
};
use std::sync::Arc;

impl AppState {
    pub(crate) fn muc_delivery_context(&self) -> MucDeliveryContext {
        MucDeliveryContext {
            repository: PostgresMucDeliveryRepository::new(self.pool.clone()),
            receipt_claim: ClusterMucReceiptClaimService::new(
                db::cluster_muc_receipt_claim_repository::PostgresClusterMucReceiptClaimRepository::new(
                    self.pool.clone(),
                ),
            ),
            local_domain: self.config.domain.clone(),
            sessions: Arc::clone(&self.sessions),
            muc_occupants: Arc::clone(&self.muc_occupants),
            suspended_muc_sessions: Arc::clone(&self.suspended_muc_sessions),
            sm_memory_governor: Arc::clone(&self.sm_memory_governor),
            sm_max_unacked_stanzas: self.config.sm_max_unacked_stanzas,
            sm_max_unacked_bytes: self.config.sm_max_unacked_bytes,
            federation_outbox: self.federation_outbox.clone(),
            message_service: self.message_service.clone(),
        }
    }
}
