//! Atomic operation cancellation and audited manual reconciliation.
use crate::{
    db::{
        self,
        admin_mutations::{AdminMutationStart, AdminMutationStore},
    },
    services::{
        api_mutations::*,
        operations::{OperationAdminRepository, ReconciliationInput},
    },
};
use anyhow::Result;
use serde_json::json;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresOperationAdminRepository {
    mutations: AdminMutationStore,
}
impl PostgresOperationAdminRepository {
    pub(crate) fn new(mutations: AdminMutationStore) -> Self {
        Self { mutations }
    }
}

fn reconciliation<'a>(
    admission: &AdminMutationAdmission<'_>,
    lease: &db::IdempotencyLease,
    input: ReconciliationInput<'a>,
) -> db::ManualReconciliation<'a> {
    db::ManualReconciliation {
        reconciled_by: admission.authority.user_id,
        reconciler_auth_generation: admission.authority.auth_generation,
        request_id: lease.request_id,
        succeeded: input.succeeded,
        result: input.result,
        error_code: input.error_code,
        evidence_note: input.evidence_note,
    }
}
fn operation_reconciliation_response(
    outcome: db::ManualReconcileOutcome,
) -> Result<StoredApiResponse> {
    match outcome {
        db::ManualReconcileOutcome::NotFound => {
            error_response(404, "not_found", "operation does not exist")
        }
        db::ManualReconcileOutcome::NotIndeterminate => {
            error_response(409, "conflict", "operation is not indeterminate")
        }
        db::ManualReconcileOutcome::IndeterminateTargetsRemain => error_response(
            409,
            "conflict",
            "indeterminate operation targets must be reconciled first",
        ),
        db::ManualReconcileOutcome::TargetsPreventSuccess => error_response(
            409,
            "conflict",
            "operation cannot be marked succeeded because a target did not succeed",
        ),
        db::ManualReconcileOutcome::Succeeded => {
            StoredApiResponse::json(200, json!({"outcome":"succeeded"}))
        }
        db::ManualReconcileOutcome::Failed => {
            StoredApiResponse::json(200, json!({"outcome":"failed"}))
        }
    }
}
fn target_reconciliation_response(
    outcome: db::ManualReconcileOutcome,
) -> Result<StoredApiResponse> {
    match outcome {
        db::ManualReconcileOutcome::NotFound => {
            error_response(404, "not_found", "operation target does not exist")
        }
        db::ManualReconcileOutcome::NotIndeterminate => {
            error_response(409, "conflict", "operation target is not indeterminate")
        }
        db::ManualReconcileOutcome::Succeeded => {
            StoredApiResponse::json(200, json!({"outcome":"succeeded"}))
        }
        db::ManualReconcileOutcome::Failed => {
            StoredApiResponse::json(200, json!({"outcome":"failed"}))
        }
        db::ManualReconcileOutcome::IndeterminateTargetsRemain
        | db::ManualReconcileOutcome::TargetsPreventSuccess => {
            anyhow::bail!("target reconciliation returned a parent-target conflict")
        }
    }
}
impl OperationAdminRepository for PostgresOperationAdminRepository {
    async fn cancel(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(result) => return Ok(result),
        };
        let outcome = db::request_operation_cancel_in_tx(
            &mut tx,
            id,
            admission.authority.user_id,
            lease.request_id,
        )
        .await?;
        let response = match outcome {
            db::CancelOutcome::NotFound => {
                error_response(404, "not_found", "operation does not exist")?
            }
            db::CancelOutcome::NotCancelable => {
                error_response(409, "conflict", "operation does not support cancellation")?
            }
            db::CancelOutcome::PastPointOfNoReturn => error_response(
                409,
                "conflict",
                "operation has passed its point of no return",
            )?,
            db::CancelOutcome::Requested => {
                StoredApiResponse::json(200, json!({"outcome":"requested"}))?
            }
            db::CancelOutcome::Canceled => {
                StoredApiResponse::json(200, json!({"outcome":"canceled"}))?
            }
            db::CancelOutcome::AlreadyTerminal => {
                StoredApiResponse::json(200, json!({"outcome":"already_terminal"}))?
            }
        };
        self.mutations.finish(tx, &lease, response).await
    }
    async fn reconcile(
        &self,
        admission: AdminMutationAdmission<'_>,
        id: Uuid,
        input: ReconciliationInput<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(result) => return Ok(result),
        };
        let input = reconciliation(&admission, &lease, input);
        let outcome = db::reconcile_indeterminate_operation_in_tx(&mut tx, id, &input).await?;
        self.mutations
            .finish(tx, &lease, operation_reconciliation_response(outcome)?)
            .await
    }
    async fn reconcile_target(
        &self,
        admission: AdminMutationAdmission<'_>,
        operation_id: Uuid,
        target_id: Uuid,
        input: ReconciliationInput<'_>,
    ) -> Result<ApiMutationOutcome<StoredApiResponse>> {
        let (mut tx, lease) = match self.mutations.start(&admission).await? {
            AdminMutationStart::Ready(tx, lease) => (tx, lease),
            AdminMutationStart::Finished(result) => return Ok(result),
        };
        if db::operation_target_by_id(&mut tx, target_id)
            .await?
            .is_none_or(|target| target.operation_id != operation_id)
        {
            return self
                .mutations
                .finish(
                    tx,
                    &lease,
                    error_response(404, "not_found", "operation target does not exist")?,
                )
                .await;
        }
        let input = reconciliation(&admission, &lease, input);
        let outcome = db::reconcile_indeterminate_target_in_tx(&mut tx, target_id, &input).await?;
        self.mutations
            .finish(tx, &lease, target_reconciliation_response(outcome)?)
            .await
    }
}
