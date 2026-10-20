//! Composition-root construction of the metrics context and its SM recovery gauges.

use super::AppState;
use crate::api::contexts::metrics::{
    MetricsLimits, MetricsRenderProbe, MucOccupancyCountProbe, OccupancyCount,
};
use crate::api::contexts::MetricsContext;
use crate::services::metrics_snapshot::SmRecoveryGaugeSnapshot;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Snapshot-only view of the SM governor and recovery queue. Neither mutable
/// authority is exposed through MetricsContext's interface.
#[derive(Clone)]
struct SmRecoveryMetricsProbe {
    governor: Arc<crate::services::sm_capacity::SmMemoryGovernor>,
    recovery: Arc<crate::state::session_cleanup::SmSuspensionRecoveryQueue>,
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

impl crate::api::contexts::metrics::SmRecoveryGauges for SmRecoveryMetricsProbe {
    fn sm_recovery_snapshot(&self) -> SmRecoveryGaugeSnapshot {
        self.snapshot()
    }
}

pub(super) fn metrics_context(state: &AppState) -> MetricsContext {
    MetricsContext {
        bearer_token: state.metrics_bearer_token.clone(),
        persistence: state.metrics_snapshot_service.clone(),
        registry: MetricsRenderProbe {
            registry: Arc::clone(&state.metrics),
        },
        // The configured list is immutable after startup. Keep original
        // order and duplicates for the component outbox query.
        component_domains: state.configured_component_domains(),
        limits: MetricsLimits {
            database_max_connections: state.config.database_max_connections,
            s2s_outbox_max_rows: state.config.s2s_outbox_max_rows,
            s2s_outbox_max_bytes: state.config.s2s_outbox_max_bytes,
            s2s_outbox_max_per_domain: state.config.s2s_outbox_max_per_domain,
        },
        tls: state.tls_context.metrics_probe(),
        cluster: state.cluster.metrics_probe(),
        muc_occupant_count: MucOccupancyCountProbe::new(
            Arc::clone(&state.muc_occupants) as Arc<dyn OccupancyCount>
        ),
        s2s_outbound_count: state.s2s_connection_registry.outbound_count_probe(),
        sm: Arc::new(SmRecoveryMetricsProbe {
            governor: Arc::clone(&state.sm_memory_governor),
            recovery: Arc::clone(&state.sm_suspension_recovery),
        }),
        started_at: state.started_at,
        bind_fallback: state.config.metrics_bind,
    }
}
