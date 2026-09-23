//! TLS reload authority for committed administrator operations.

use super::AppState;
use crate::metrics::Metrics;
use crate::tls::{TlsContext, TlsReloadOutcome};
use anyhow::Result;
use std::sync::{atomic::Ordering, Arc};

pub(crate) struct OperationTlsReloadEffects {
    tls: TlsContext,
    metrics: Arc<Metrics>,
}

impl AppState {
    pub(crate) fn operation_tls_reload_effects(&self) -> OperationTlsReloadEffects {
        OperationTlsReloadEffects {
            tls: self.tls_context.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl OperationTlsReloadEffects {
    pub(crate) async fn reload(&self) -> Result<TlsReloadOutcome> {
        let tls = self.tls.clone();
        let outcome = match tokio::task::spawn_blocking(move || tls.reload()).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => {
                self.metrics
                    .tls_reload_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
            Err(error) => {
                self.metrics
                    .tls_reload_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error.into());
            }
        };
        self.metrics
            .tls_revocation_rechecks_total
            .fetch_add(outcome.evaluated_sessions, Ordering::Relaxed);
        self.metrics
            .tls_revocation_recheck_inconclusive_total
            .fetch_add(outcome.inconclusive_rechecks, Ordering::Relaxed);
        self.metrics
            .tls_revoked_sessions_drained_total
            .fetch_add(outcome.drained_total(), Ordering::Relaxed);
        self.metrics
            .tls_revoked_c2s_external_sessions_drained_total
            .fetch_add(outcome.drained_c2s_external, Ordering::Relaxed);
        self.metrics
            .tls_revoked_inbound_s2s_external_sessions_drained_total
            .fetch_add(outcome.drained_inbound_s2s_external, Ordering::Relaxed);
        self.metrics
            .tls_revoked_outbound_s2s_external_sessions_drained_total
            .fetch_add(outcome.drained_outbound_s2s_external, Ordering::Relaxed);
        Ok(outcome)
    }
}
