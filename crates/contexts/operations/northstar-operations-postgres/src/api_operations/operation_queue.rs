//! API operation enqueue, lookup, listing, revocation and effect authorization.

use super::*;

pub async fn enqueue_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    input: &EnqueueOperation<'_>,
) -> Result<OperationRecord> {
    anyhow::ensure!(!input.request_id.is_nil(), "request id must not be nil");
    anyhow::ensure!(
        !input.idempotency_id.is_nil(),
        "idempotency id must not be nil"
    );
    anyhow::ensure!(
        !input.idempotency_lease_token.is_nil(),
        "idempotency lease token must not be nil"
    );
    anyhow::ensure!(!input.actor_id.is_nil(), "operation actor must not be nil");
    anyhow::ensure!(input.actor_auth_generation >= 0, "invalid actor generation");
    anyhow::ensure!(
        (1..=32767).contains(&input.payload_version),
        "invalid payload version"
    );
    anyhow::ensure!(
        (1..=1000).contains(&input.max_attempts),
        "invalid attempt budget"
    );
    anyhow::ensure!(
        (1..=604_800).contains(&input.deadline_seconds),
        "invalid operation deadline"
    );
    anyhow::ensure!(
        input
            .target
            .is_none_or(|target| !target.is_empty() && target.len() <= MAX_TARGET_BYTES),
        "operation target is invalid"
    );
    validate_json(
        input.payload,
        MAX_OPERATION_PAYLOAD_BYTES,
        "operation payload",
    )?;
    validate_operation_payload(input.kind, input.payload_version, input.payload)?;
    validate_operation_identity_keys(input.kind, input.target, input.payload)?;
    anyhow::ensure!(
        input.authorization_policy == required_authorization_policy(input.kind)?,
        "operation kind requires a different authorization policy"
    );

    let id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO api_operation_journal
         (id,request_id,idempotency_id,actor_id,actor_subject_id,actor_auth_generation,
          authorization_policy,kind,target,payload_version,payload,max_attempts,deadline_at)
         SELECT $1,reservation.request_id,reservation.id,$4,$4,$5,kind.authorization_policy,
                kind.kind,$8,$9,$10,$11,
                clock_timestamp()+($12*INTERVAL '1 second')
         FROM api_idempotency_records AS reservation
         JOIN api_operation_kinds AS kind
           ON kind.kind=$7 AND kind.authorization_policy=$6
         WHERE reservation.id=$2 AND reservation.request_id=$3
           AND reservation.request_actor_id=$4
           AND reservation.state='started'
           AND reservation.lease_token=$13
           AND reservation.lease_expires_at > clock_timestamp()
           AND reservation.expires_at > clock_timestamp()
         RETURNING api_operation_journal.*",
    )
    .bind(id)
    .bind(input.idempotency_id)
    .bind(input.request_id)
    .bind(input.actor_id)
    .bind(input.actor_auth_generation)
    .bind(input.authorization_policy.as_str())
    .bind(input.kind)
    .bind(input.target)
    .bind(input.payload_version)
    .bind(input.payload)
    .bind(input.max_attempts)
    .bind(input.deadline_seconds)
    .bind(input.idempotency_lease_token)
    .fetch_optional(&mut **tx)
    .await?
    .context("idempotency reservation is absent, stale, or belongs to another actor")?;
    let operation = operation_from_row(&row)?;
    audit_operation_transition(tx, &operation, "requested", json!({})).await?;
    Ok(operation)
}

pub async fn operation_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<OperationRecord>> {
    let row = sqlx::query("SELECT * FROM api_operation_journal WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(operation_from_row).transpose()
}

pub async fn operation_target_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<OperationTargetRecord>> {
    let row = sqlx::query("SELECT * FROM api_operation_targets WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(target_from_row).transpose()
}

/// Lists operations using a stable descending `(created_at,id)` keyset. The
/// returned records intentionally exclude worker and lease credentials.
pub async fn list_operations(
    tx: &mut Transaction<'_, Postgres>,
    status: Option<&str>,
    kind: Option<&str>,
    boundary: Option<OperationPageBoundary>,
    limit: i64,
) -> Result<OperationPage> {
    anyhow::ensure!((1..=100).contains(&limit), "invalid operation page size");
    if let Some(status) = status {
        OperationStatus::parse(status)?;
    }
    if let Some(kind) = kind {
        required_authorization_policy(kind)?;
    }
    let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let (after_created_at, after_id) = boundary
        .map(|value| (Some(value.created_at), Some(value.id)))
        .unwrap_or((None, None));
    let rows = sqlx::query(
        "SELECT * FROM api_operation_journal
         WHERE ($1::text IS NULL OR status=$1)
           AND ($2::text IS NULL OR kind=$2)
           AND ($3::timestamptz IS NULL OR (created_at,id) < ($3,$4))
         ORDER BY created_at DESC,id DESC LIMIT $5",
    )
    .bind(status)
    .bind(kind)
    .bind(after_created_at)
    .bind(after_id)
    .bind(limit + 1)
    .fetch_all(&mut **tx)
    .await?;
    let mut items = rows
        .iter()
        .map(operation_from_row)
        .collect::<Result<Vec<_>>>()?;
    let next = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|item| OperationPageBoundary {
            created_at: item.created_at,
            id: item.id,
        })
    } else {
        None
    };
    Ok(OperationPage {
        items,
        next,
        database_now,
    })
}

/// Lists a single operation's fan-out targets without exposing lease fencing
/// tokens or worker identity.
pub async fn list_operation_targets(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    status: Option<&str>,
    boundary: Option<OperationPageBoundary>,
    limit: i64,
) -> Result<OperationTargetPage> {
    anyhow::ensure!(!operation_id.is_nil(), "operation id must not be nil");
    anyhow::ensure!((1..=100).contains(&limit), "invalid target page size");
    if let Some(status) = status {
        OperationStatus::parse(status)?;
    }
    let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let (after_created_at, after_id) = boundary
        .map(|value| (Some(value.created_at), Some(value.id)))
        .unwrap_or((None, None));
    let rows = sqlx::query(
        "SELECT * FROM api_operation_targets
         WHERE operation_id=$1
           AND ($2::text IS NULL OR status=$2)
           AND ($3::timestamptz IS NULL OR (created_at,id) < ($3,$4))
         ORDER BY created_at DESC,id DESC LIMIT $5",
    )
    .bind(operation_id)
    .bind(status)
    .bind(after_created_at)
    .bind(after_id)
    .bind(limit + 1)
    .fetch_all(&mut **tx)
    .await?;
    let mut items = rows
        .iter()
        .map(target_from_row)
        .collect::<Result<Vec<_>>>()?;
    let next = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|item| OperationPageBoundary {
            created_at: item.created_at,
            id: item.id,
        })
    } else {
        None
    };
    Ok(OperationTargetPage {
        items,
        next,
        database_now,
    })
}

pub(super) async fn terminalize_authorization_revoked(
    tx: &mut Transaction<'_, Postgres>,
    operation: &OperationRecord,
) -> Result<bool> {
    if !no_live_targets(tx, operation.id).await? {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE api_operation_targets
         SET status='failed',error_code='authorization_revoked',
             last_error_at=clock_timestamp(),completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status='pending'",
    )
    .bind(operation.id)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status='failed',error_code='authorization_revoked',
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status IN ('pending','running')
           AND point_of_no_return_at IS NULL
         RETURNING *",
    )
    .bind(operation.id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let failed = operation_from_row(&row)?;
    audit_operation_transition(
        tx,
        &failed,
        "authorization_revoked",
        json!({"actor_subject_id": failed.actor_subject_id}),
    )
    .await?;
    Ok(true)
}

pub async fn reject_revoked_operations_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    limit: i64,
) -> Result<u64> {
    anyhow::ensure!((1..=1000).contains(&limit), "invalid rejection batch size");
    let rows = sqlx::query(
        "SELECT operation.* FROM api_operation_journal AS operation
         WHERE operation.authorization_policy='reauthorize_until_effect'
           AND operation.status IN ('pending','running')
           AND operation.point_of_no_return_at IS NULL
           AND (operation.status='pending' OR operation.lease_expires_at <= clock_timestamp())
           AND NOT EXISTS (
               SELECT 1 FROM users AS actor
               WHERE actor.id=operation.actor_subject_id
                 AND actor.auth_generation=operation.actor_auth_generation
                 AND actor.is_admin AND NOT actor.is_disabled
           )
           AND NOT EXISTS (
               SELECT 1 FROM api_operation_targets AS target
               WHERE target.operation_id=operation.id AND target.status='running'
                 AND target.lease_expires_at > clock_timestamp()
           )
         ORDER BY operation.created_at,operation.id
         FOR UPDATE OF operation SKIP LOCKED LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&mut **tx)
    .await?;
    let mut rejected = 0;
    for row in rows {
        let operation = operation_from_row(&row)?;
        if terminalize_authorization_revoked(tx, &operation).await? {
            rejected += 1;
        }
    }
    Ok(rejected)
}

pub async fn authorize_operation_effect_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
) -> Result<EffectAuthorizationOutcome> {
    let Some(operation) = lock_current_operation_lease(tx, lease).await? else {
        return Ok(EffectAuthorizationOutcome::LostLease);
    };
    if operation.deadline_at
        <= sqlx::query_scalar::<_, DateTime<Utc>>("SELECT clock_timestamp()")
            .fetch_one(&mut **tx)
            .await?
    {
        return Ok(EffectAuthorizationOutcome::LostLease);
    }
    if operation.authorization_policy == AuthorizationPolicy::CommittedConsequence
        || operation.point_of_no_return_at.is_some()
    {
        return Ok(EffectAuthorizationOutcome::Authorized);
    }
    let authorized = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users
         WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE)",
    )
    .bind(operation.actor_subject_id)
    .bind(operation.actor_auth_generation)
    .fetch_one(&mut **tx)
    .await?;
    if authorized {
        return Ok(EffectAuthorizationOutcome::Authorized);
    }
    if terminalize_authorization_revoked(tx, &operation).await? {
        Ok(EffectAuthorizationOutcome::AuthorizationRevoked)
    } else {
        Ok(EffectAuthorizationOutcome::LostLease)
    }
}

pub(super) fn validate_operation_claim(worker_id: Uuid, lease_seconds: i64) -> Result<()> {
    anyhow::ensure!(!worker_id.is_nil(), "worker id must not be nil");
    anyhow::ensure!(
        (5..=300).contains(&lease_seconds),
        "invalid operation lease"
    );
    Ok(())
}
