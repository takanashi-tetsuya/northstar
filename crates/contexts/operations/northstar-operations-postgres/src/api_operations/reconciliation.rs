//! Exhausted-operation expiry and manual reconciliation of indeterminate operations and targets.

use super::*;

/// Bound one maintenance pass. Once a worker has crossed the point of no
/// return, an expired lease is never reclaimed and never guessed to have
/// failed: the durable state becomes `indeterminate` until an administrator
/// reconciles the real external outcome.
pub async fn expire_exhausted_operations_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    limit: i64,
) -> Result<u64> {
    anyhow::ensure!((1..=1000).contains(&limit), "invalid expiry batch size");
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT operation.id FROM api_operation_journal AS operation
         WHERE operation.status IN ('pending','running')
           AND (
                operation.deadline_at <= clock_timestamp()
             OR (operation.attempts >= operation.max_attempts AND
                 (operation.status='pending' OR operation.lease_expires_at <= clock_timestamp()))
             OR (operation.status='running' AND operation.point_of_no_return_at IS NOT NULL
                 AND operation.lease_expires_at <= clock_timestamp())
             OR (operation.status='running' AND operation.cancel_requested_at IS NOT NULL
                 AND operation.lease_expires_at <= clock_timestamp())
             OR EXISTS (
                 SELECT 1 FROM api_operation_targets AS expired_target
                 WHERE expired_target.operation_id=operation.id
                   AND expired_target.status='running'
                   AND expired_target.point_of_no_return_at IS NOT NULL
                   AND (expired_target.lease_expires_at <= clock_timestamp()
                        OR expired_target.deadline_at <= clock_timestamp())
             )
           )
           AND NOT EXISTS (
               SELECT 1 FROM api_operation_targets AS target
               WHERE target.operation_id=operation.id AND target.status='running'
                 AND target.lease_expires_at > clock_timestamp()
           )
         ORDER BY operation.deadline_at,operation.id
         FOR UPDATE SKIP LOCKED LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&mut **tx)
    .await?;
    let mut expired = 0_u64;
    for id in ids {
        let operation_row =
            sqlx::query("SELECT * FROM api_operation_journal WHERE id=$1 FOR UPDATE")
                .bind(id)
                .fetch_one(&mut **tx)
                .await?;
        let operation = operation_from_row(&operation_row)?;
        let target_pnr: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT MIN(point_of_no_return_at) FROM api_operation_targets
             WHERE operation_id=$1 AND status IN ('running','indeterminate')
               AND point_of_no_return_at IS NOT NULL",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
        let is_indeterminate = operation.point_of_no_return_at.is_some() || target_pnr.is_some();
        let is_canceled = operation.cancel_requested_at.is_some() && !is_indeterminate;

        if is_indeterminate {
            sqlx::query(
                "UPDATE api_operation_targets
                 SET status=CASE WHEN point_of_no_return_at IS NOT NULL
                                 THEN 'indeterminate' ELSE 'failed' END,
                     error_code=CASE WHEN point_of_no_return_at IS NOT NULL
                                     THEN 'worker_lost_after_point_of_no_return'
                                     ELSE 'parent_outcome_indeterminate' END,
                     last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
                     lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
                 WHERE operation_id=$1 AND status IN ('pending','running')",
            )
            .bind(id)
            .execute(&mut **tx)
            .await?;
        } else if is_canceled {
            sqlx::query(
                "UPDATE api_operation_targets
                 SET status='canceled',cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
                     worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
                     completed_at=clock_timestamp(),updated_at=clock_timestamp()
                 WHERE operation_id=$1 AND status IN ('pending','running')",
            )
            .bind(id)
            .execute(&mut **tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE api_operation_targets
                 SET status='failed',error_code='operation_deadline_or_attempts_exhausted',
                     last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
                     lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
                 WHERE operation_id=$1 AND status IN ('pending','running')",
            )
            .bind(id)
            .execute(&mut **tx)
            .await?;
        }
        let status = if is_indeterminate {
            "indeterminate"
        } else if is_canceled {
            "canceled"
        } else {
            "failed"
        };
        let error_code = if is_indeterminate {
            Some("worker_lost_after_point_of_no_return")
        } else if is_canceled {
            None
        } else {
            Some("operation_deadline_or_attempts_exhausted")
        };
        let row = sqlx::query(
            "UPDATE api_operation_journal
             SET status=$2,error_code=$3,
                 last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
                 lease_expires_at=NULL,
                 point_of_no_return_at=CASE WHEN $2='indeterminate'
                     THEN COALESCE(point_of_no_return_at,$4,clock_timestamp())
                     ELSE point_of_no_return_at END,
                 completed_at=clock_timestamp(),updated_at=clock_timestamp()
             WHERE id=$1 AND status IN ('pending','running') RETURNING *",
        )
        .bind(id)
        .bind(status)
        .bind(error_code)
        .bind(target_pnr)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(row) = row {
            let operation = operation_from_row(&row)?;
            audit_operation_transition(
                tx,
                &operation,
                status,
                json!({"error_code":error_code,"maintenance":true}),
            )
            .await?;
            expired += 1;
        }
    }
    Ok(expired)
}

pub(super) async fn authorize_manual_reconciler(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    auth_generation: i64,
) -> Result<bool> {
    anyhow::ensure!(
        !actor_id.is_nil() && auth_generation >= 0,
        "invalid reconciler"
    );
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users
         WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE)",
    )
    .bind(actor_id)
    .bind(auth_generation)
    .fetch_one(&mut **tx)
    .await?)
}

/// Resolve one indeterminate target after an operator has checked the actual
/// external system. The evidence note is mandatory and is written only to the
/// audit log; it must never contain a credential.
pub async fn reconcile_indeterminate_target_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    target_id: Uuid,
    input: &ManualReconciliation<'_>,
) -> Result<ManualReconcileOutcome> {
    anyhow::ensure!(
        !input.request_id.is_nil(),
        "reconciliation request id is invalid"
    );
    validate_manual_reconciliation_content(
        input.succeeded,
        input.result,
        input.error_code,
        input.evidence_note,
    )?;
    if !authorize_manual_reconciler(tx, input.reconciled_by, input.reconciler_auth_generation)
        .await?
    {
        return Ok(ManualReconcileOutcome::NotFound);
    }
    let parent = sqlx::query(
        "SELECT operation.* FROM api_operation_journal AS operation
         JOIN api_operation_targets AS target ON target.operation_id=operation.id
         WHERE target.id=$1 FOR UPDATE OF operation",
    )
    .bind(target_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(parent) = parent else {
        return Ok(ManualReconcileOutcome::NotFound);
    };
    let parent = operation_from_row(&parent)?;
    let status = if input.succeeded {
        "succeeded"
    } else {
        "failed"
    };
    let row = sqlx::query(
        "UPDATE api_operation_targets
         SET status=$2,result=$3,error_code=$4,last_error_at=CASE WHEN $2='failed'
                 THEN clock_timestamp() ELSE last_error_at END,
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='indeterminate' RETURNING id",
    )
    .bind(target_id)
    .bind(status)
    .bind(input.result)
    .bind(if input.succeeded {
        None
    } else {
        input.error_code
    })
    .fetch_optional(&mut **tx)
    .await?;
    if row.is_none() {
        return Ok(ManualReconcileOutcome::NotIndeterminate);
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id,operation_id)
         VALUES($1,'api.operation.target_reconciled',$2,$3,$4,$5)",
    )
    .bind(input.reconciled_by)
    .bind(target_id.to_string())
    .bind(json!({
        "status":status,
        "evidence_note":input.evidence_note,
        "original_operation_request_id":parent.request_id,
    }))
    .bind(input.request_id)
    .bind(parent.id)
    .execute(&mut **tx)
    .await?;
    Ok(if input.succeeded {
        ManualReconcileOutcome::Succeeded
    } else {
        ManualReconcileOutcome::Failed
    })
}

/// Resolve the parent only after every indeterminate target was separately
/// reconciled. A success is accepted only when every fan-out target succeeded.
pub async fn reconcile_indeterminate_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    input: &ManualReconciliation<'_>,
) -> Result<ManualReconcileOutcome> {
    anyhow::ensure!(
        !input.request_id.is_nil(),
        "reconciliation request id is invalid"
    );
    validate_manual_reconciliation_content(
        input.succeeded,
        input.result,
        input.error_code,
        input.evidence_note,
    )?;
    if !authorize_manual_reconciler(tx, input.reconciled_by, input.reconciler_auth_generation)
        .await?
    {
        return Ok(ManualReconcileOutcome::NotFound);
    }
    let operation = sqlx::query("SELECT * FROM api_operation_journal WHERE id=$1 FOR UPDATE")
        .bind(operation_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(operation) = operation else {
        return Ok(ManualReconcileOutcome::NotFound);
    };
    let operation = operation_from_row(&operation)?;
    if operation.status != OperationStatus::Indeterminate {
        return Ok(ManualReconcileOutcome::NotIndeterminate);
    }
    let counts = sqlx::query(
        "SELECT COUNT(*) FILTER (WHERE status='indeterminate') AS indeterminate,
                COUNT(*) FILTER (WHERE status<>'succeeded') AS not_succeeded
         FROM api_operation_targets WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_one(&mut **tx)
    .await?;
    if counts.get::<i64, _>("indeterminate") != 0 {
        return Ok(ManualReconcileOutcome::IndeterminateTargetsRemain);
    }
    if input.succeeded && counts.get::<i64, _>("not_succeeded") != 0 {
        return Ok(ManualReconcileOutcome::TargetsPreventSuccess);
    }
    let status = if input.succeeded {
        "succeeded"
    } else {
        "failed"
    };
    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status=$2,result=$3,error_code=$4,
             last_error_at=CASE WHEN $2='failed' THEN clock_timestamp() ELSE last_error_at END,
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='indeterminate' RETURNING *",
    )
    .bind(operation_id)
    .bind(status)
    .bind(input.result)
    .bind(if input.succeeded {
        None
    } else {
        input.error_code
    })
    .fetch_one(&mut **tx)
    .await?;
    let reconciled = operation_from_row(&row)?;
    audit_operation_transition_for_request(
        tx,
        &reconciled,
        "manually_reconciled",
        json!({
            "by":input.reconciled_by,
            "status":status,
            "evidence_note":input.evidence_note,
            "original_operation_request_id":operation.request_id,
        }),
        input.request_id,
        Some(input.reconciled_by),
    )
    .await?;
    Ok(if input.succeeded {
        ManualReconcileOutcome::Succeeded
    } else {
        ManualReconcileOutcome::Failed
    })
}
