//! Builds the cluster MUC outbox worker context (`cluster::muc_outbox_worker`) from the composition root.

use super::AppState;
use crate::{cluster::muc_outbox_worker::ClusterMucOutboxWorkerContext, db, services};
use std::sync::Arc;

impl AppState {
    pub(crate) fn cluster_muc_outbox_worker_context(&self) -> ClusterMucOutboxWorkerContext {
        ClusterMucOutboxWorkerContext {
            signal: self.cluster.muc_outbox_signal(),
            domain: self.local_domain().to_owned(),
            endpoints: self.cluster_muc_delivery_endpoints(),
            delivery: self.muc_delivery_context(),
            preclaim: services::cluster_muc_outbox_preclaim::ClusterMucOutboxPreclaimService::new(
                db::cluster_muc_outbox_preclaim_repository::PostgresClusterMucOutboxPreclaimRepository::new(
                    self.pool.clone(),
                ),
            ),
            claim: services::cluster_muc_outbox_claim::ClusterMucOutboxClaimService::new(
                db::cluster_muc_outbox_claim_repository::PostgresClusterMucOutboxClaimRepository::new(
                    self.pool.clone(),
                ),
            ),
            settlement: services::cluster_muc_outbox_settlement::ClusterMucOutboxSettlementService::new(
                db::cluster_muc_outbox_settlement_repository::PostgresClusterMucOutboxSettlementRepository::new(
                    self.pool.clone(),
                ),
            ),
            housekeeping: services::cluster_muc_outbox_housekeeping::ClusterMucOutboxHousekeepingService::new(
                db::cluster_muc_outbox_housekeeping_repository::PostgresClusterMucOutboxHousekeepingRepository::new(
                    self.pool.clone(),
                ),
            ),
            delivery_read: services::cluster_muc_delivery_read::ClusterMucDeliveryReadService::new(
                db::cluster_muc_delivery_read_repository::PostgresClusterMucDeliveryReadRepository::new(
                    self.pool.clone(),
                ),
            ),
            delivery_item: services::cluster_muc_delivery_item::ClusterMucDeliveryItemService::new(
                db::cluster_muc_delivery_item_repository::PostgresClusterMucDeliveryItemRepository::new(
                    self.pool.clone(),
                ),
            ),
            admission: self.durable_outbox_database_admission.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}
