//! Bounded PostgreSQL turns for clustered MUC outbox dispatch. The delivery
//! renderer owns endpoint projection separately; this worker context cannot
//! sign messages or issue Redis commands.

use super::muc_delivery_endpoints::ClusterMucDeliveryEndpoints;
use crate::cluster::{ClusterAdapters, ClusterMucOutboxSignal};
use northstar_telemetry::metrics::Metrics;
use std::sync::{atomic::Ordering, Arc};
use tokio::sync::OwnedSemaphorePermit;

pub(crate) struct ClusterMucOutboxWorkerContext<A: ClusterAdapters> {
    pub(crate) signal: ClusterMucOutboxSignal,
    pub(crate) domain: String,
    pub(crate) endpoints: ClusterMucDeliveryEndpoints,
    pub(crate) delivery: super::ClusterMucDelivery<A>,
    pub(crate) preclaim: northstar_room_application::cluster_muc_outbox_preclaim::ClusterMucOutboxPreclaimService<
        A::MucOutboxPreclaim,
    >,
    pub(crate) claim: northstar_room_application::cluster_muc_outbox_claim::ClusterMucOutboxClaimService<
        A::MucOutboxClaim,
    >,
    pub(crate) settlement: northstar_room_application::cluster_muc_outbox_settlement::ClusterMucOutboxSettlementService<
        A::MucOutboxSettlement,
    >,
    pub(crate) housekeeping: northstar_room_application::cluster_muc_outbox_housekeeping::ClusterMucOutboxHousekeepingService<
        A::MucOutboxHousekeeping,
    >,
    pub(crate) delivery_read: northstar_room_application::cluster_muc_delivery_read::ClusterMucDeliveryReadService<
        A::MucDeliveryRead,
    >,
    pub(crate) delivery_item: northstar_room_application::cluster_muc_delivery_item::ClusterMucDeliveryItemService<
        A::MucDeliveryItem,
    >,
    pub(crate) admission: northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
    pub(crate) metrics: Arc<Metrics>,
}

impl<A: ClusterAdapters> ClusterMucOutboxWorkerContext<A> {
    pub(crate) async fn database_turn(&self) -> OwnedSemaphorePermit {
        self.admission.acquire().await
    }

    pub(crate) fn record_delivery(&self) {
        self.metrics
            .cluster_muc_outbox_deliveries_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_retry(&self) {
        self.metrics
            .cluster_muc_outbox_retries_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_gauges(
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
