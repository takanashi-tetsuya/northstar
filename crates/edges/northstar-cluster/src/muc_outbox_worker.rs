//! Bounded PostgreSQL turns for clustered MUC outbox dispatch. The delivery
//! renderer owns endpoint projection separately; this worker context cannot
//! sign messages or issue Redis commands.

use super::muc_delivery_endpoints::ClusterMucDeliveryEndpoints;
use crate::{ClusterAdapters, ClusterMucOutboxSignal};
use northstar_telemetry::metrics::Metrics;
use std::sync::{atomic::Ordering, Arc};
use tokio::sync::OwnedSemaphorePermit;

pub struct ClusterMucOutboxWorkerContext<A: ClusterAdapters> {
    pub signal: ClusterMucOutboxSignal,
    pub domain: String,
    pub endpoints: ClusterMucDeliveryEndpoints,
    pub delivery: super::ClusterMucDelivery<A>,
    pub preclaim: northstar_room_application::cluster_muc_outbox_preclaim::ClusterMucOutboxPreclaimService<
        A::MucOutboxPreclaim,
    >,
    pub claim: northstar_room_application::cluster_muc_outbox_claim::ClusterMucOutboxClaimService<
        A::MucOutboxClaim,
    >,
    pub settlement: northstar_room_application::cluster_muc_outbox_settlement::ClusterMucOutboxSettlementService<
        A::MucOutboxSettlement,
    >,
    pub housekeeping: northstar_room_application::cluster_muc_outbox_housekeeping::ClusterMucOutboxHousekeepingService<
        A::MucOutboxHousekeeping,
    >,
    pub delivery_read: northstar_room_application::cluster_muc_delivery_read::ClusterMucDeliveryReadService<
        A::MucDeliveryRead,
    >,
    pub delivery_item: northstar_room_application::cluster_muc_delivery_item::ClusterMucDeliveryItemService<
        A::MucDeliveryItem,
    >,
    pub admission: northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
    pub metrics: Arc<Metrics>,
}

impl<A: ClusterAdapters> ClusterMucOutboxWorkerContext<A> {
    pub async fn database_turn(&self) -> OwnedSemaphorePermit {
        self.admission.acquire().await
    }

    pub fn record_delivery(&self) {
        self.metrics
            .cluster_muc_outbox_deliveries_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_retry(&self) {
        self.metrics
            .cluster_muc_outbox_retries_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_gauges(
        &self,
        snapshot: northstar_room_application::cluster_muc_outbox_housekeeping::ClusterMucOutboxGaugeSnapshot,
    ) {
        self.metrics
            .cluster_muc_outbox_queued
            .store(snapshot.queued_rows.max(0) as u64, Ordering::Relaxed);
        self.metrics
            .cluster_muc_outbox_dead_letters
            .store(snapshot.dead_letter_rows.max(0) as u64, Ordering::Relaxed);
        self.metrics
            .cluster_muc_outbox_oldest_age_seconds
            .store(snapshot.oldest_age_seconds.max(0) as u64, Ordering::Relaxed);
    }
}
