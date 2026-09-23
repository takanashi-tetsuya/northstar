//! Bounded PostgreSQL turns for clustered MUC outbox dispatch. The delivery
//! renderer owns endpoint projection separately; this worker context cannot
//! sign messages or issue Redis commands.

use super::AppState;
use crate::{cluster::ClusterMucOutboxSignal, db, metrics::Metrics, services};
use std::sync::{atomic::Ordering, Arc};
use tokio::sync::OwnedSemaphorePermit;

pub(crate) struct ClusterMucOutboxWorkerContext {
    pub(crate) signal: ClusterMucOutboxSignal,
    pub(crate) preclaim: services::cluster_muc_outbox_preclaim::ClusterMucOutboxPreclaimService<
        db::cluster_muc_outbox_preclaim_repository::PostgresClusterMucOutboxPreclaimRepository,
    >,
    pub(crate) claim: services::cluster_muc_outbox_claim::ClusterMucOutboxClaimService<
        db::cluster_muc_outbox_claim_repository::PostgresClusterMucOutboxClaimRepository,
    >,
    pub(crate) settlement: services::cluster_muc_outbox_settlement::ClusterMucOutboxSettlementService<
        db::cluster_muc_outbox_settlement_repository::PostgresClusterMucOutboxSettlementRepository,
    >,
    pub(crate) housekeeping: services::cluster_muc_outbox_housekeeping::ClusterMucOutboxHousekeepingService<
        db::cluster_muc_outbox_housekeeping_repository::PostgresClusterMucOutboxHousekeepingRepository,
    >,
    admission: services::durable_outbox::DurableOutboxDatabaseAdmission,
    metrics: Arc<Metrics>,
}

impl ClusterMucOutboxWorkerContext {
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
        snapshot: services::cluster_muc_outbox_housekeeping::ClusterMucOutboxGaugeSnapshot,
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

impl AppState {
    pub(crate) fn cluster_muc_outbox_worker_context(&self) -> ClusterMucOutboxWorkerContext {
        ClusterMucOutboxWorkerContext {
            signal: self.cluster.muc_outbox_signal(),
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
            admission: self.durable_outbox_database_admission.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}
