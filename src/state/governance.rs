//! Governance handlers own use-case calls and the existing outcome counters.
use crate::{
    metrics::Metrics,
    services::{api_mutations::*, api_queries::ApiReadAuthority, governance::*},
};
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct GovernanceContext<R> {
    service: GovernanceService<R>,
    metrics: Arc<Metrics>,
}
impl<R: GovernanceRepository> GovernanceContext<R> {
    pub(super) fn new(service: GovernanceService<R>, metrics: Arc<Metrics>) -> Self {
        Self { service, metrics }
    }
    fn record(
        &self,
        audit: bool,
        outcome: &Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure>,
    ) {
        match outcome {
            Ok(ApiMutationOutcome::Committed(_)) => {
                let counter = if audit {
                    &self.metrics.audit_export_operations_total
                } else {
                    &self.metrics.legal_hold_operations_total
                };
                counter.fetch_add(1, Ordering::Relaxed);
            }
            Err(failure) => {
                if failure.operation_failed {
                    let counter = if audit {
                        &self.metrics.audit_export_operation_failures_total
                    } else {
                        &self.metrics.legal_hold_operation_failures_total
                    };
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                if failure.cursor_rejected {
                    self.metrics
                        .governance_export_cursor_rejections_total
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }
    pub(crate) async fn list_holds(
        &self,
        actor: ApiReadAuthority<'_>,
        active_only: bool,
        limit: i64,
        access_key_sha256: &str,
    ) -> Result<Vec<LegalHoldSummary>, GovernanceFailure> {
        let result = self
            .service
            .list_holds(actor, active_only, limit, access_key_sha256)
            .await;
        if result.is_ok() {
            self.metrics
                .legal_hold_operations_total
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }
    pub(crate) async fn create_hold(
        &self,
        command: CreateHoldCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        let result = self.service.create_hold(command).await;
        self.record(false, &result);
        result
    }
    pub(crate) async fn release_hold(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
        reason: &str,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        let result = self.service.release_hold(admission, id, reason).await;
        self.record(false, &result);
        result
    }
    pub(crate) async fn export_hold(
        &self,
        command: HoldExportCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        let result = self.service.export_hold(command).await;
        self.record(false, &result);
        result
    }
    pub(crate) async fn export_audit(
        &self,
        command: AuditExportCommand<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>, GovernanceFailure> {
        let result = self.service.export_audit(command).await;
        self.record(true, &result);
        result
    }
}
