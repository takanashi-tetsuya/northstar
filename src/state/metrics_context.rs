//! Composition-root construction of the metrics context and its SM recovery gauges.

use super::AppState;
use crate::state::http_contexts::MetricsContext;
use northstar_http::contexts::metrics::{
    MetricsLimits, MetricsRenderProbe, MucOccupancyCountProbe, OccupancyCount,
};
use northstar_operations_application::metrics_snapshot::SmRecoveryGaugeSnapshot;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Snapshot-only view of the SM governor and recovery queue. Neither mutable
/// authority is exposed through MetricsContext's interface.
#[derive(Clone)]
struct SmRecoveryMetricsProbe {
    governor: Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>,
    recovery: Arc<northstar_stream::session_cleanup::recovery::SmSuspensionRecoveryQueue>,
}

impl SmRecoveryMetricsProbe {
    fn snapshot(&self) -> SmRecoveryGaugeSnapshot {
        let metrics = self.governor.metrics();
        let recovery = self.recovery.snapshot();
        SmRecoveryGaugeSnapshot {
            reserved_bytes: metrics.reserved_bytes.load(Ordering::Relaxed),
            limit_bytes: self.governor.max_bytes(),
            peak_reserved_bytes: metrics.peak_reserved_bytes.load(Ordering::Relaxed),
            admission_rejections_total: metrics.admission_rejections_total.load(Ordering::Relaxed),
            invariant_failures_total: metrics.invariant_failures_total.load(Ordering::Relaxed),
            recovery_jobs: recovery.jobs,
            recovery_job_limit: self.governor.max_recovery_jobs(),
            recovery_bytes: recovery.bytes,
            recovery_byte_limit: self.governor.max_recovery_bytes(),
            recovery_oldest_age_seconds: recovery.oldest_age_seconds,
        }
    }
}

impl northstar_http::contexts::metrics::SmRecoveryGauges for SmRecoveryMetricsProbe {
    fn sm_recovery_snapshot(&self) -> SmRecoveryGaugeSnapshot {
        self.snapshot()
    }
}

impl AppState {
    pub(crate) fn metrics_context(&self) -> MetricsContext {
        MetricsContext {
            bearer_token: self.metrics_bearer_token.clone(),
            persistence: self.operations.metrics_snapshot_service.clone(),
            registry: MetricsRenderProbe {
                registry: Arc::clone(&self.metrics),
            },
            // The configured list is immutable after startup. Keep original
            // order and duplicates for the component outbox query.
            component_domains: self.configured_component_domains(),
            limits: MetricsLimits {
                database_max_connections: self.config.database_max_connections,
                s2s_outbox_max_rows: self.config.s2s_outbox_max_rows,
                s2s_outbox_max_bytes: self.config.s2s_outbox_max_bytes,
                s2s_outbox_max_per_domain: self.config.s2s_outbox_max_per_domain,
            },
            tls: self.tls_context.metrics_probe(),
            cluster: Arc::new(self.cluster.metrics_probe()),
            muc_occupant_count: MucOccupancyCountProbe::new(
                Arc::clone(&self.room.muc_occupants) as Arc<dyn OccupancyCount>
            ),
            s2s_outbound_count: self
                .federation
                .s2s_connection_registry
                .outbound_count_probe(),
            sm: Arc::new(SmRecoveryMetricsProbe {
                governor: Arc::clone(&self.session.sm_memory_governor),
                recovery: Arc::clone(&self.session.sm_suspension_recovery),
            }),
            started_at: self.started_at,
            bind_fallback: self.config.metrics_bind,
        }
    }
}
