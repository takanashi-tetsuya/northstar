//! API operation target enqueue, claims, leases, completion and cancellation acknowledgement.

use super::*;

pub async fn enqueue_operation_target_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    input: &EnqueueOperationTarget<'_>,
) -> Result<OperationTargetRecord> {
    anyhow::ensure!(
        !input.target_key.is_empty() && input.target_key.len() <= MAX_TARGET_BYTES,
        "operation target key is invalid"
    );
    anyhow::ensure!(input.ordinal >= 0, "operation target ordinal is invalid");
    anyhow::ensure!(
        (1..=1000).contains(&input.max_attempts),
        "invalid target attempt budget"
    );
    anyhow::ensure!(
        (1..=604_800).contains(&input.deadline_seconds),
        "invalid target deadline"
    );
    validate_json(
        input.payload,
        MAX_TARGET_PAYLOAD_BYTES,
        "operation target payload",
    )?;
    anyhow::ensure!(
        !contains_secret_key(input.payload),
        "operation target payload must not contain credentials or private keys"
    );
    let parent = sqlx::query(
        "SELECT operation.*,kind.supports_targets,
                operation.deadline_at > clock_timestamp() AS within_deadline
         FROM api_operation_journal AS operation
         JOIN api_operation_kinds AS kind ON kind.kind=operation.kind
         WHERE operation.id=$1 FOR UPDATE OF operation",
    )
    .bind(input.operation_id)
    .fetch_optional(&mut **tx)
    .await?
    .context("operation does not exist")?;
    let operation = operation_from_row(&parent)?;
    anyhow::ensure!(
        matches!(
            operation.status,
            OperationStatus::Pending | OperationStatus::Running
        ) && operation.cancel_requested_at.is_none()
            && operation.point_of_no_return_at.is_none()
            && parent.get::<bool, _>("within_deadline")
            && parent.get::<bool, _>("supports_targets"),
        "operation cannot accept targets"
    );
    let row = sqlx::query(
        "INSERT INTO api_operation_targets
         (id,operation_id,target_key,ordinal,payload,max_attempts,deadline_at)
         VALUES($1,$2,$3,$4,$5,$6,
                LEAST($7,clock_timestamp()+($8*INTERVAL '1 second')))
         ON CONFLICT(operation_id,target_key) DO UPDATE
           SET target_key=EXCLUDED.target_key
           WHERE api_operation_targets.ordinal=EXCLUDED.ordinal
             AND api_operation_targets.payload=EXCLUDED.payload
             AND api_operation_targets.max_attempts=EXCLUDED.max_attempts
         RETURNING api_operation_targets.*",
    )
    .bind(Uuid::new_v4())
    .bind(input.operation_id)
    .bind(input.target_key)
    .bind(input.ordinal)
    .bind(input.payload)
    .bind(input.max_attempts)
    .bind(operation.deadline_at)
    .bind(input.deadline_seconds)
    .fetch_optional(&mut **tx)
    .await?
    .context("operation cannot accept targets")?;
    target_from_row(&row)
}

pub async fn claim_operation_target_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    worker_id: Uuid,
    lease_seconds: i64,
) -> Result<Option<OperationTargetLease>> {
    anyhow::ensure!(!worker_id.is_nil(), "worker id must not be nil");
    anyhow::ensure!((5..=300).contains(&lease_seconds), "invalid target lease");
    expire_exhausted_operations_in_tx(tx, 64).await?;
    let parent = sqlx::query(
        "SELECT operation.*,
                (operation.authorization_policy='committed_consequence'
                 OR operation.point_of_no_return_at IS NOT NULL OR EXISTS (
                    SELECT 1 FROM users AS actor
                    WHERE actor.id=operation.actor_subject_id
                      AND actor.auth_generation=operation.actor_auth_generation
                      AND actor.is_admin AND NOT actor.is_disabled
                )) AS effect_authorized
         FROM api_operation_journal AS operation
         WHERE operation.id=$1 AND operation.status='running'
           AND operation.cancel_requested_at IS NULL
           AND operation.lease_expires_at > clock_timestamp()
           AND operation.deadline_at > clock_timestamp()
         FOR UPDATE OF operation",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(parent) = parent else {
        return Ok(None);
    };
    if !parent.get::<bool, _>("effect_authorized") {
        return Ok(None);
    }
    let lease_token = Uuid::new_v4();
    let row = sqlx::query(
        "WITH candidate AS (
             SELECT target.id
             FROM api_operation_targets AS target
             WHERE target.operation_id=$1
               AND target.cancel_requested_at IS NULL
               AND target.point_of_no_return_at IS NULL
               AND target.attempts < target.max_attempts
               AND target.deadline_at > clock_timestamp()
               AND (
                    (target.status='pending' AND target.next_attempt_at <= clock_timestamp())
                 OR (target.status='running' AND target.lease_expires_at <= clock_timestamp())
               )
             ORDER BY target.next_attempt_at,target.ordinal,target.id
             FOR UPDATE OF target SKIP LOCKED LIMIT 1
         )
         UPDATE api_operation_targets AS target
         SET status='running',worker_id=$2,lease_token=$3,
             lease_expires_at=LEAST(target.deadline_at,
                 clock_timestamp()+($4*INTERVAL '1 second')),
             attempts=attempts+1,updated_at=clock_timestamp()
         FROM candidate WHERE target.id=candidate.id
         RETURNING target.*",
    )
    .bind(operation_id)
    .bind(worker_id)
    .bind(lease_token)
    .bind(lease_seconds)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(OperationTargetLease {
        target: target_from_row(&row)?,
        worker_id,
        lease_token,
    }))
}

pub async fn renew_operation_target_lease_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
    lease_seconds: i64,
) -> Result<bool> {
    anyhow::ensure!((5..=300).contains(&lease_seconds), "invalid target lease");
    if lock_parent_and_current_target_lease(tx, lease)
        .await?
        .is_none()
    {
        return Ok(false);
    }
    Ok(sqlx::query(
        "UPDATE api_operation_targets
         SET lease_expires_at=LEAST(deadline_at,
                 clock_timestamp()+($4*INTERVAL '1 second')),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()",
    )
    .bind(lease.target.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(lease_seconds)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

pub async fn mark_operation_target_point_of_no_return_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
) -> Result<bool> {
    let Some((parent, target)) = lock_parent_and_current_target_lease(tx, lease).await? else {
        return Ok(false);
    };
    if parent.cancel_requested_at.is_some()
        || target.cancel_requested_at.is_some()
        || target.point_of_no_return_at.is_some()
        || !parent_effect_is_authorized(tx, &parent).await?
    {
        return Ok(false);
    }
    Ok(sqlx::query(
        "UPDATE api_operation_targets
         SET point_of_no_return_at=COALESCE(point_of_no_return_at,clock_timestamp()),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND cancel_requested_at IS NULL
           AND point_of_no_return_at IS NULL",
    )
    .bind(lease.target.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

pub async fn succeed_operation_target_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
    result: &Value,
) -> Result<bool> {
    validate_json(result, MAX_RESULT_BYTES, "operation target result")?;
    let Some((parent, target)) = lock_parent_and_current_target_lease(tx, lease).await? else {
        return Ok(false);
    };
    if target.point_of_no_return_at.is_none() || !parent_effect_is_authorized(tx, &parent).await? {
        return Ok(false);
    }
    Ok(sqlx::query(
        "UPDATE api_operation_targets
         SET status='succeeded',result=$4,error_code=NULL,worker_id=NULL,
             lease_token=NULL,lease_expires_at=NULL,completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND point_of_no_return_at IS NOT NULL
           AND (cancel_requested_at IS NULL OR point_of_no_return_at IS NOT NULL)",
    )
    .bind(lease.target.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(result)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

/// Record an effect whose outcome cannot be proved after the target crossed
/// its point of no return.  This is deliberately different from an ordinary
/// failure: the effect may have happened partially (or completely) before the
/// executor returned an error, so retrying or claiming that it failed would
/// both be unsafe.  The parent and the affected target remain terminally
/// `indeterminate` until an administrator records evidence through the
/// reconciliation API.
pub async fn mark_operation_target_indeterminate_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    parent_lease: &OperationLease,
    target_lease: &OperationTargetLease,
    error_code: &str,
    result: Option<&Value>,
) -> Result<bool> {
    validate_error_code(error_code)?;
    if let Some(result) = result {
        validate_json(result, MAX_RESULT_BYTES, "operation target result")?;
    }
    let Some(current_parent) = lock_current_operation_lease(tx, parent_lease).await? else {
        return Ok(false);
    };
    let Some((parent, target)) = lock_parent_and_current_target_lease(tx, target_lease).await?
    else {
        return Ok(false);
    };
    // A target lease has its own fencing token. Never reuse it as the
    // parent's token when terminalizing the journal row: the two leases are
    // intentionally claimed independently. Requiring both current leases
    // also prevents a stale target worker from making the parent terminal.
    if parent.id != current_parent.id {
        return Ok(false);
    }
    let Some(target_point_of_no_return) = target.point_of_no_return_at else {
        return Ok(false);
    };

    // The production worker executes one target at a time for a parent. Keep
    // that invariant explicit here so a future concurrent caller cannot
    // terminalize the parent while another fenced effect is still running.
    let another_target_is_running = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
             SELECT 1 FROM api_operation_targets
             WHERE operation_id=$1 AND id<>$2 AND status='running'
         )",
    )
    .bind(parent.id)
    .bind(target.id)
    .fetch_one(&mut **tx)
    .await?;
    if another_target_is_running {
        return Ok(false);
    }

    let target_changed = sqlx::query(
        "UPDATE api_operation_targets
         SET status='indeterminate',result=$4,error_code=$5,
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND point_of_no_return_at IS NOT NULL",
    )
    .bind(target.id)
    .bind(target_lease.worker_id)
    .bind(target_lease.lease_token)
    .bind(result)
    .bind(error_code)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    if !target_changed {
        return Ok(false);
    }

    sqlx::query(
        "UPDATE api_operation_targets
         SET status='failed',error_code='parent_outcome_indeterminate',
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status='pending'",
    )
    .bind(parent.id)
    .execute(&mut **tx)
    .await?;

    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status='indeterminate',result=$4,error_code=$5,
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,
             point_of_no_return_at=COALESCE(point_of_no_return_at,$6),
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
         RETURNING *",
    )
    .bind(parent.id)
    .bind(parent_lease.worker_id)
    .bind(parent_lease.lease_token)
    .bind(result)
    .bind(error_code)
    .bind(target_point_of_no_return)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("parent operation lease changed while recording indeterminate effect");
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(
        tx,
        &operation,
        "indeterminate",
        json!({"error_code":error_code,"effect_returned_error":true}),
    )
    .await?;
    Ok(true)
}

pub async fn acknowledge_operation_target_cancel_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
) -> Result<bool> {
    let Some((parent, _)) = lock_parent_and_current_target_lease(tx, lease).await? else {
        return Ok(false);
    };
    let changed = sqlx::query(
        "UPDATE api_operation_targets
         SET status='canceled',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND cancel_requested_at IS NOT NULL AND point_of_no_return_at IS NULL",
    )
    .bind(lease.target.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    if changed {
        finalize_parent_cancel_if_targets_acked(tx, &parent).await?;
    }
    Ok(changed)
}
