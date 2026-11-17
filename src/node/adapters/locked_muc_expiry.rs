//! Builds the locked-room expiry context from the composition root.

use crate::node::ServerNode;
use northstar_muc_xmpp::locked_room_expiry::LockedMucExpiryLocal;
use std::sync::Arc;

pub(crate) type LockedMucExpiryContext =
    northstar_muc_xmpp::locked_room_expiry::LockedMucExpiryContext<
        northstar_room_postgres::locked_muc_expiry_repository::PostgresLockedMucExpiryRepository,
        northstar_workflows::muc_delivery_repository::PostgresMucDeliveryRepository,
        northstar_room_postgres::cluster_muc_receipt_claim_repository::PostgresClusterMucReceiptClaimRepository,
        crate::node::FederationRouter,
    >;

impl ServerNode {
    pub(crate) fn locked_muc_expiry_context(&self) -> LockedMucExpiryContext {
        LockedMucExpiryContext {
            service: self.room.locked_muc_expiry_service.clone(),
            local: LockedMucExpiryLocal {
                sessions: Arc::clone(self.session.live().sessions()),
                occupants: Arc::clone(&self.room.muc_occupants),
            },
            delivery: self.muc_delivery_context(),
            domain: self.config.domain.clone(),
            cluster_enabled: self.cluster.is_enabled(),
        }
    }
}
