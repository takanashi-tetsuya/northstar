//! API operation claims, leases, completion, failure, retry and cancellation.

use super::*;

/// Avoid an empty claim transaction without caching the absence of work.
/// Every pending/running row must reach the original claim path: even a future
/// retry or a live lease can need authorization, cancellation or expiry work.
/// The same statement checks the empty claim's schema/ACL dependencies and
/// writable transaction state; losing authority must never look like idleness.
pub async fn operation_work_pending<'e, E>(
    executor: E,
    worker_id: Uuid,
    lease_seconds: i64,
) -> Result<bool>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    validate_operation_claim(worker_id, lease_seconds)?;
    let row = sqlx::query(
        "WITH required(name,read_columns,write_columns,select_all) AS (VALUES
             ('api_operation_journal',
              ARRAY['id','authorization_policy','status','point_of_no_return_at',
                    'lease_expires_at','actor_subject_id','actor_auth_generation',
                    'created_at','cancel_requested_at','attempts','max_attempts',
                    'deadline_at','next_attempt_at'],
              ARRAY['status','worker_id','lease_token','lease_expires_at',
                    'attempts','updated_at'], TRUE),
             ('users', ARRAY['id','auth_generation','is_admin','is_disabled'],
              ARRAY[]::TEXT[], FALSE),
             ('api_operation_targets',
              ARRAY['operation_id','status','lease_expires_at',
                    'point_of_no_return_at','deadline_at'],
              ARRAY[]::TEXT[], FALSE)
         ), relations AS (
             SELECT required.*,pg_catalog.to_regclass(name) AS relation_id
             FROM required
         )
         SELECT EXISTS(SELECT 1 FROM api_operation_journal
                       WHERE status IN ('pending','running')) AS has_work,
                pg_catalog.current_setting('transaction_read_only')='off' AS writable,
                (SELECT bool_and(COALESCE(
                    relation.relation_id IS NOT NULL
                    AND pg_catalog.has_schema_privilege(
                        current_user,table_info.relnamespace,'USAGE')
                    AND NOT EXISTS (
                        SELECT 1 FROM pg_catalog.unnest(
                            relation.read_columns || relation.write_columns
                        ) AS expected(name)
                        WHERE NOT EXISTS (
                            SELECT 1 FROM pg_catalog.pg_attribute AS column_info
                            WHERE column_info.attrelid=relation.relation_id
                              AND column_info.attnum>0 AND NOT column_info.attisdropped
                              AND column_info.attname=expected.name
                        )
                    )
                    AND CASE WHEN pg_catalog.has_table_privilege(
                        current_user,relation.relation_id,'SELECT') THEN TRUE
                    ELSE COALESCE((
                        SELECT bool_and(pg_catalog.has_column_privilege(
                            current_user,relation.relation_id,column_info.attnum,'SELECT'))
                        FROM pg_catalog.pg_attribute AS column_info
                        WHERE column_info.attrelid=relation.relation_id
                          AND column_info.attnum>0 AND NOT column_info.attisdropped
                          AND (relation.select_all
                               OR column_info.attname=ANY(relation.read_columns))
                    ),FALSE) END
                    AND CASE WHEN pg_catalog.cardinality(relation.write_columns)=0 THEN TRUE
                    WHEN pg_catalog.has_table_privilege(
                        current_user,relation.relation_id,'UPDATE') THEN TRUE
                    ELSE COALESCE((
                        SELECT bool_and(pg_catalog.has_column_privilege(
                            current_user,relation.relation_id,column_info.attnum,'UPDATE'))
                        FROM pg_catalog.pg_attribute AS column_info
                        WHERE column_info.attrelid=relation.relation_id
                          AND column_info.attnum>0 AND NOT column_info.attisdropped
                          AND column_info.attname=ANY(relation.write_columns)
                    ),FALSE) END,
                    FALSE))
                 FROM relations AS relation
                 LEFT JOIN pg_catalog.pg_class AS table_info
                   ON table_info.oid=relation.relation_id) AS authority_valid",
    )
    .fetch_one(executor)
    .await
    .context("could not inspect durable operation work")?;
    anyhow::ensure!(
        row.try_get::<bool, _>("writable")?,
        "durable operation database is read-only"
    );
    anyhow::ensure!(
        row.try_get::<bool, _>("authority_valid")?,
        "durable operation claim permissions or schema are unavailable"
    );
    Ok(row.try_get("has_work")?)
}

pub async fn claim_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    worker_id: Uuid,
    lease_seconds: i64,
) -> Result<Option<OperationLease>> {
    validate_operation_claim(worker_id, lease_seconds)?;
    expire_exhausted_operations_in_tx(tx, 64).await?;
    reject_revoked_operations_in_tx(tx, 64).await?;
    let lease_token = Uuid::new_v4();
    let row = sqlx::query(
        "WITH candidate AS (
             SELECT id FROM api_operation_journal
             WHERE cancel_requested_at IS NULL
               AND point_of_no_return_at IS NULL
               AND attempts < max_attempts
               AND deadline_at > clock_timestamp()
               AND (authorization_policy='committed_consequence' OR EXISTS (
                   SELECT 1 FROM users AS actor
                   WHERE actor.id=api_operation_journal.actor_subject_id
                     AND actor.auth_generation=api_operation_journal.actor_auth_generation
                     AND actor.is_admin AND NOT actor.is_disabled
               ))
               AND (
                    (status='pending' AND next_attempt_at <= clock_timestamp())
                 OR (status='running' AND lease_expires_at <= clock_timestamp())
               )
             ORDER BY next_attempt_at,created_at,id
             FOR UPDATE SKIP LOCKED LIMIT 1
         )
         UPDATE api_operation_journal AS operation
         SET status='running',worker_id=$1,lease_token=$2,
             lease_expires_at=LEAST(operation.deadline_at,
                 clock_timestamp()+($3*INTERVAL '1 second')),
             attempts=attempts+1,updated_at=clock_timestamp()
         FROM candidate WHERE operation.id=candidate.id
         RETURNING operation.*",
    )
    .bind(worker_id)
    .bind(lease_token)
    .bind(lease_seconds)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(
        tx,
        &operation,
        "claimed",
        json!({"worker_id":worker_id,"attempt":operation.attempts}),
    )
    .await?;
    Ok(Some(OperationLease {
        operation,
        worker_id,
        lease_token,
    }))
}

pub async fn renew_operation_lease_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
    lease_seconds: i64,
) -> Result<bool> {
    anyhow::ensure!(
        (5..=300).contains(&lease_seconds),
        "invalid operation lease"
    );
    Ok(sqlx::query(
        "UPDATE api_operation_journal
         SET lease_expires_at=LEAST(deadline_at,
                 clock_timestamp()+($4*INTERVAL '1 second')),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(lease_seconds)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

#[cfg(test)]
pub async fn mark_operation_point_of_no_return_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE api_operation_journal
         SET point_of_no_return_at=COALESCE(point_of_no_return_at,clock_timestamp()),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND cancel_requested_at IS NULL
           AND point_of_no_return_at IS NULL
           AND (authorization_policy='committed_consequence' OR EXISTS (
               SELECT 1 FROM users AS actor
               WHERE actor.id=api_operation_journal.actor_subject_id
                 AND actor.auth_generation=api_operation_journal.actor_auth_generation
                 AND actor.is_admin AND NOT actor.is_disabled
           ))",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

pub async fn succeed_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
    result: &Value,
) -> Result<bool> {
    validate_json(result, MAX_RESULT_BYTES, "operation result")?;
    let row = sqlx::query(
        "UPDATE api_operation_journal AS operation
         SET status='succeeded',result=$4,error_code=NULL,worker_id=NULL,
             lease_token=NULL,lease_expires_at=NULL,completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND (point_of_no_return_at IS NOT NULL OR EXISTS (
               SELECT 1 FROM api_operation_targets AS any_target
               WHERE any_target.operation_id=operation.id
           ))
           AND (cancel_requested_at IS NULL OR point_of_no_return_at IS NOT NULL)
           AND NOT EXISTS (
               SELECT 1 FROM api_operation_targets AS target
               WHERE target.operation_id=operation.id AND target.status <> 'succeeded'
           )
         RETURNING operation.*",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(result)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(tx, &operation, "succeeded", json!({})).await?;
    Ok(true)
}

pub(super) async fn no_live_targets(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
) -> Result<bool> {
    Ok(!sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
             SELECT 1 FROM api_operation_targets
             WHERE operation_id=$1 AND status='running'
         )",
    )
    .bind(operation_id)
    .fetch_one(&mut **tx)
    .await?)
}

pub(super) async fn lock_current_operation_lease(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
) -> Result<Option<OperationRecord>> {
    let row = sqlx::query(
        "SELECT * FROM api_operation_journal
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
         FOR UPDATE",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .fetch_optional(&mut **tx)
    .await?;
    row.as_ref().map(operation_from_row).transpose()
}

/// Lock order for every fan-out mutation is parent operation first, target
/// second. This is the same order used by parent cancellation/terminalization
/// and prevents a target completion racing a parent terminal transition.
pub(super) async fn lock_parent_and_current_target_lease(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
) -> Result<Option<(OperationRecord, OperationTargetRecord)>> {
    let parent = sqlx::query(
        "SELECT operation.*
         FROM api_operation_journal AS operation
         JOIN api_operation_targets AS target ON target.operation_id=operation.id
         WHERE target.id=$1 AND operation.status='running'
           AND operation.lease_expires_at > clock_timestamp()
           AND operation.deadline_at > clock_timestamp()
         FOR UPDATE OF operation",
    )
    .bind(lease.target.id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(parent) = parent else {
        return Ok(None);
    };
    let parent = operation_from_row(&parent)?;
    let target = sqlx::query(
        "SELECT * FROM api_operation_targets
         WHERE id=$1 AND operation_id=$2 AND status='running'
           AND worker_id=$3 AND lease_token=$4
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
         FOR UPDATE",
    )
    .bind(lease.target.id)
    .bind(parent.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(target) = target else {
        return Ok(None);
    };
    Ok(Some((parent, target_from_row(&target)?)))
}

pub(super) async fn parent_effect_is_authorized(
    tx: &mut Transaction<'_, Postgres>,
    parent: &OperationRecord,
) -> Result<bool> {
    if parent.authorization_policy == AuthorizationPolicy::CommittedConsequence
        || parent.point_of_no_return_at.is_some()
    {
        return Ok(true);
    }
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users
         WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE)",
    )
    .bind(parent.actor_subject_id)
    .bind(parent.actor_auth_generation)
    .fetch_one(&mut **tx)
    .await?)
}

pub(super) async fn finalize_parent_cancel_if_targets_acked(
    tx: &mut Transaction<'_, Postgres>,
    parent: &OperationRecord,
) -> Result<()> {
    let row = sqlx::query(
        "UPDATE api_operation_journal AS operation
         SET status='canceled',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE operation.id=$1 AND operation.status='running'
           AND operation.cancel_requested_at IS NOT NULL
           AND operation.point_of_no_return_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM api_operation_targets AS target
               WHERE target.operation_id=operation.id
                 AND target.status IN ('pending','running')
           )
         RETURNING operation.*",
    )
    .bind(parent.id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = row {
        let operation = operation_from_row(&row)?;
        audit_operation_transition(
            tx,
            &operation,
            "canceled",
            json!({"targets_acknowledged":true}),
        )
        .await?;
    }
    Ok(())
}

pub async fn fail_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
    error_code: &str,
    result: Option<&Value>,
) -> Result<bool> {
    validate_error_code(error_code)?;
    if let Some(result) = result {
        validate_json(result, MAX_RESULT_BYTES, "operation result")?;
    }
    if lock_current_operation_lease(tx, lease).await?.is_none() {
        return Ok(false);
    }
    if !no_live_targets(tx, lease.operation.id).await? {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE api_operation_targets SET status='failed',error_code=$2,
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status='pending'",
    )
    .bind(lease.operation.id)
    .bind(error_code)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status='failed',result=$4,error_code=$5,last_error_at=clock_timestamp(),
             worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
         RETURNING *",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(result)
    .bind(error_code)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(tx, &operation, "failed", json!({"error_code":error_code})).await?;
    Ok(true)
}

#[cfg(test)]
pub(super) fn retry_backoff_seconds(id: Uuid, attempts: i32) -> i64 {
    let exponent = u32::try_from(attempts.saturating_sub(1))
        .unwrap_or_default()
        .min(8);
    let base = 1_i64.checked_shl(exponent).unwrap_or(256).min(240);
    let jitter_window = (base / 4).max(1);
    let jitter = i64::from(id.as_bytes()[15]) % (jitter_window + 1);
    (base + jitter).min(300)
}

#[cfg(test)]
pub async fn retry_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
    error_code: &str,
) -> Result<RetryOutcome> {
    validate_error_code(error_code)?;
    let Some(operation) = lock_current_operation_lease(tx, lease).await? else {
        return Ok(RetryOutcome::LostLease);
    };
    let has_nonterminal_targets = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM api_operation_targets
         WHERE operation_id=$1 AND status IN ('pending','running'))",
    )
    .bind(operation.id)
    .fetch_one(&mut **tx)
    .await?;
    if has_nonterminal_targets {
        return Ok(RetryOutcome::LostLease);
    }
    if operation.cancel_requested_at.is_some() && operation.point_of_no_return_at.is_none() {
        return if acknowledge_operation_cancel_in_tx(tx, lease).await? {
            Ok(RetryOutcome::Canceled)
        } else {
            Ok(RetryOutcome::LostLease)
        };
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let retry_after_seconds = retry_backoff_seconds(operation.id, operation.attempts);
    let retry_at = now + chrono::Duration::seconds(retry_after_seconds);
    if operation.attempts >= operation.max_attempts || retry_at >= operation.deadline_at {
        return if fail_operation_in_tx(tx, lease, error_code, None).await? {
            Ok(RetryOutcome::Failed)
        } else {
            Ok(RetryOutcome::LostLease)
        };
    }
    let changed = sqlx::query(
        "UPDATE api_operation_journal
         SET status='pending',error_code=$4,last_error_at=clock_timestamp(),
             next_attempt_at=$5,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()",
    )
    .bind(operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(error_code)
    .bind(retry_at)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Ok(RetryOutcome::LostLease);
    }
    let mut pending = operation;
    pending.status = OperationStatus::Pending;
    audit_operation_transition(
        tx,
        &pending,
        "retry_scheduled",
        json!({"error_code":error_code,"retry_after_seconds":retry_after_seconds}),
    )
    .await?;
    Ok(RetryOutcome::Pending {
        retry_after_seconds,
    })
}

pub async fn request_operation_cancel_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    canceled_by: Uuid,
    request_id: Uuid,
) -> Result<CancelOutcome> {
    anyhow::ensure!(!canceled_by.is_nil(), "cancel actor must not be nil");
    anyhow::ensure!(!request_id.is_nil(), "cancel request id must not be nil");
    let row = sqlx::query(
        "SELECT operation.*,kind.supports_cancel,
                EXISTS(SELECT 1 FROM api_operation_targets AS target
                       WHERE target.operation_id=operation.id
                         AND target.point_of_no_return_at IS NOT NULL)
                    AS target_point_of_no_return
         FROM api_operation_journal AS operation
         JOIN api_operation_kinds AS kind ON kind.kind=operation.kind
         WHERE operation.id=$1 FOR UPDATE OF operation",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(CancelOutcome::NotFound);
    };
    let operation = operation_from_row(&row)?;
    if operation.status.is_terminal() {
        return Ok(CancelOutcome::AlreadyTerminal);
    }
    if !row.get::<bool, _>("supports_cancel") {
        return Ok(CancelOutcome::NotCancelable);
    }
    if operation.point_of_no_return_at.is_some() || row.get::<bool, _>("target_point_of_no_return")
    {
        return Ok(CancelOutcome::PastPointOfNoReturn);
    }
    if operation.status == OperationStatus::Pending {
        sqlx::query(
            "UPDATE api_operation_targets
             SET status='canceled',cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
                 worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
                 completed_at=clock_timestamp(),updated_at=clock_timestamp()
             WHERE operation_id=$1 AND status='pending'",
        )
        .bind(operation_id)
        .execute(&mut **tx)
        .await?;
        let row = sqlx::query(
            "UPDATE api_operation_journal
             SET status='canceled',cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
                 cancel_requested_by=$2,completed_at=clock_timestamp(),updated_at=clock_timestamp()
             WHERE id=$1 AND status='pending' RETURNING *",
        )
        .bind(operation_id)
        .bind(canceled_by)
        .fetch_one(&mut **tx)
        .await?;
        let canceled = operation_from_row(&row)?;
        audit_operation_transition_for_request(
            tx,
            &canceled,
            "canceled",
            json!({
                "by":canceled_by,
                "original_operation_request_id":operation.request_id,
            }),
            request_id,
            Some(canceled_by),
        )
        .await?;
        return Ok(CancelOutcome::Canceled);
    }
    sqlx::query(
        "UPDATE api_operation_journal
         SET cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
             cancel_requested_by=COALESCE(cancel_requested_by,$2),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND point_of_no_return_at IS NULL",
    )
    .bind(operation_id)
    .bind(canceled_by)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE api_operation_targets
         SET status=CASE WHEN status='pending' THEN 'canceled' ELSE status END,
             cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
             completed_at=CASE WHEN status='pending' THEN clock_timestamp() ELSE completed_at END,
             updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status IN ('pending','running')
           AND point_of_no_return_at IS NULL",
    )
    .bind(operation_id)
    .execute(&mut **tx)
    .await?;
    audit_operation_transition_for_request(
        tx,
        &operation,
        "cancel_requested",
        json!({
            "by":canceled_by,
            "original_operation_request_id":operation.request_id,
        }),
        request_id,
        Some(canceled_by),
    )
    .await?;
    Ok(CancelOutcome::Requested)
}

pub async fn acknowledge_operation_cancel_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
) -> Result<bool> {
    let Some(operation) = lock_current_operation_lease(tx, lease).await? else {
        return Ok(false);
    };
    if operation.cancel_requested_at.is_none() || operation.point_of_no_return_at.is_some() {
        return Ok(false);
    }
    if !no_live_targets(tx, lease.operation.id).await? {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE api_operation_targets
         SET status='canceled',cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status='pending'",
    )
    .bind(lease.operation.id)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status='canceled',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND cancel_requested_at IS NOT NULL AND point_of_no_return_at IS NULL
         RETURNING *",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(tx, &operation, "canceled", json!({})).await?;
    Ok(true)
}
