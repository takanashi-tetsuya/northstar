//! Cluster MUC outbox claim, settlement, dead-letter and housekeeping persistence.

use super::capacity::CapacityPlan;
use super::*;
use northstar_room_application::cluster_muc_delivery_item::ItemAdmission;
use std::collections::BTreeMap;

/// Claim a bounded ordered batch for this exact node.  A later event for a
/// room cannot pass an earlier pending event, while equal-sequence audience
/// rows may be processed concurrently.
pub async fn claim_cluster_muc_outbox(
    pool: &PgPool,
    node_id: &str,
    limit: i64,
    lease: Duration,
) -> Result<Vec<ClusterMucOutboxDelivery>> {
    validate_node_id(node_id)?;
    let lease_seconds = i64::try_from(lease.as_secs()).context("outbox lease too large")?;
    anyhow::ensure!(
        (5..=300).contains(&lease_seconds),
        "invalid MUC outbox lease"
    );
    let claim_token = Uuid::new_v4();
    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT current.delivery_id
               FROM cluster_muc_event_outbox current
              WHERE current.target_node_id=$1
                AND current.next_attempt_at<=clock_timestamp()
                AND current.expires_at>clock_timestamp()
                AND current.attempt_count<16
                AND (current.claim_token IS NULL OR current.lease_until<=clock_timestamp())
                AND NOT EXISTS (
                    SELECT 1 FROM cluster_muc_event_outbox earlier
                     WHERE earlier.room_id=current.room_id
                       AND ((current.audience_kind='occupant'
                             AND earlier.audience_kind='occupant'
                             AND earlier.recipient_occupant_incarnation=current.recipient_occupant_incarnation)
                            OR (current.audience_kind='node_pull'
                                AND earlier.audience_kind='node_pull'
                                AND earlier.target_node_id=current.target_node_id))
                       AND earlier.event_sequence<current.event_sequence)
              ORDER BY current.room_id,current.event_sequence,current.delivery_id
              FOR UPDATE SKIP LOCKED LIMIT $2
         ), claimed AS (
         UPDATE cluster_muc_event_outbox current SET
             claim_token=$3,
             lease_until=clock_timestamp()+make_interval(secs=>$4),
             attempt_count=current.attempt_count+1
          FROM candidates
         WHERE current.delivery_id=candidates.delivery_id
         RETURNING current.*)
         SELECT claimed.*,
           COALESCE((SELECT MAX(handoff_version) FROM cluster_muc_delivery_handoffs h
                     WHERE h.delivery_id=claimed.delivery_id),0) AS handoff_version
           FROM claimed",
    )
    .bind(node_id)
    .bind(limit.clamp(1, MAX_CLAIM_BATCH))
    .bind(claim_token)
    .bind(lease_seconds as f64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClusterMucOutboxDelivery {
            delivery_id: row.get("delivery_id"),
            operation_id: row.get("operation_id"),
            room_id: row.get("room_id"),
            room_epoch: row.get("room_epoch"),
            event_sequence: row.get("event_sequence"),
            event_id: row.get("event_id"),
            audience_kind: row.get("audience_kind"),
            target_node_id: row.get("target_node_id"),
            recipient_full_jid: row.get("recipient_full_jid"),
            recipient_nick: row.get("recipient_nick"),
            recipient_occupant_incarnation: row.get("recipient_occupant_incarnation"),
            recipient_occupancy_epoch: row.get("recipient_occupancy_epoch"),
            recipient_connection_uuid: row.get("recipient_connection_uuid"),
            recipient_connection_epoch: row.get("recipient_connection_epoch"),
            payload: row.get("payload"),
            payload_digest: row.get("payload_digest"),
            attempt_count: row.get("attempt_count"),
            claim_token,
            handoff_version: row.get("handoff_version"),
        })
        .collect())
}

pub async fn ack_cluster_muc_outbox(
    pool: &PgPool,
    delivery_id: Uuid,
    claim_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "DELETE FROM cluster_muc_event_outbox
          WHERE delivery_id=$1 AND claim_token=$2 AND lease_until>clock_timestamp()",
    )
    .bind(delivery_id)
    .bind(claim_token)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn renew_cluster_muc_outbox_claim(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
    lease: Duration,
) -> Result<bool> {
    let seconds = i64::try_from(lease.as_secs()).context("MUC claim lease is too large")?;
    anyhow::ensure!(
        (5..=300).contains(&seconds),
        "invalid MUC claim renewal lease"
    );
    Ok(sqlx::query(
        "UPDATE cluster_muc_event_outbox SET lease_until=clock_timestamp()+make_interval(secs=>$3)
          WHERE delivery_id=$1 AND claim_token=$2
            AND lease_until>clock_timestamp() AND expires_at>clock_timestamp()
            AND room_id=$4 AND room_epoch=$5 AND target_node_id=$6
            AND recipient_occupant_incarnation IS NOT DISTINCT FROM $7
            AND recipient_connection_uuid IS NOT DISTINCT FROM $8
            AND recipient_connection_epoch IS NOT DISTINCT FROM $9
            AND COALESCE((SELECT MAX(handoff_version) FROM cluster_muc_delivery_handoffs h
                          WHERE h.delivery_id=cluster_muc_event_outbox.delivery_id),0)=$10",
    )
    .bind(delivery.delivery_id)
    .bind(delivery.claim_token)
    .bind(seconds as f64)
    .bind(delivery.room_id)
    .bind(delivery.room_epoch)
    .bind(&delivery.target_node_id)
    .bind(delivery.recipient_occupant_incarnation)
    .bind(delivery.recipient_connection_uuid)
    .bind(delivery.recipient_connection_epoch)
    .bind(delivery.handoff_version)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

fn validate_item_identity(ordinal: i32, stable_id: &str) -> Result<()> {
    anyhow::ensure!((0..64).contains(&ordinal), "invalid MUC delivery ordinal");
    anyhow::ensure!(
        !stable_id.is_empty() && stable_id.len() <= 128,
        "invalid MUC delivery item id"
    );
    Ok(())
}

pub async fn cluster_muc_delivery_item_completed(
    pool: &PgPool,
    delivery_id: Uuid,
    ordinal: i32,
    stable_id: &str,
) -> Result<bool> {
    validate_item_identity(ordinal, stable_id)?;
    let row: Option<(String, bool)> = sqlx::query_as(
        "SELECT stable_id,completed_at IS NOT NULL FROM cluster_muc_event_delivery_items
          WHERE delivery_id=$1 AND ordinal=$2",
    )
    .bind(delivery_id)
    .bind(ordinal)
    .fetch_optional(pool)
    .await?;
    item_completed(row, stable_id)
}

fn item_completed(row: Option<(String, bool)>, stable_id: &str) -> Result<bool> {
    let Some((stored_id, completed)) = row else {
        return Ok(false);
    };
    anyhow::ensure!(
        stored_id == stable_id,
        "MUC delivery ordinal identity conflict"
    );
    Ok(completed)
}

pub async fn reserve_cluster_muc_delivery_item(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
    ordinal: i32,
    stable_id: &str,
) -> Result<ItemAdmission> {
    validate_item_identity(ordinal, stable_id)?;
    let mut tx = pool.begin().await?;
    if !lock_exact_item_claim(&mut tx, delivery).await? {
        tx.rollback().await?;
        return Ok(ItemAdmission::Stale);
    }
    let row: (String, bool) = sqlx::query_as(
        "INSERT INTO cluster_muc_event_delivery_items(delivery_id,ordinal,stable_id)
         VALUES($1,$2,$3) ON CONFLICT(delivery_id,ordinal) DO UPDATE
           SET stable_id=cluster_muc_event_delivery_items.stable_id
         RETURNING stable_id,completed_at IS NOT NULL",
    )
    .bind(delivery.delivery_id)
    .bind(ordinal)
    .bind(stable_id)
    .fetch_one(&mut *tx)
    .await?;
    let completed = item_completed(Some(row), stable_id)?;
    tx.commit().await?;
    Ok(if completed {
        ItemAdmission::Completed
    } else {
        ItemAdmission::Ready
    })
}

async fn lock_exact_item_claim(
    tx: &mut Transaction<'_, Postgres>,
    delivery: &ClusterMucOutboxDelivery,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "WITH locked_claim AS MATERIALIZED (
             SELECT delivery_id,claim_token,lease_until,expires_at,room_id,room_epoch,target_node_id,
                    recipient_occupant_incarnation,recipient_connection_uuid,recipient_connection_epoch
               FROM cluster_muc_event_outbox WHERE delivery_id=$1 FOR UPDATE
         )
         SELECT parent.delivery_id FROM locked_claim parent
          WHERE parent.claim_token=$2
            AND parent.lease_until>clock_timestamp() AND parent.expires_at>clock_timestamp()
            AND parent.room_id=$3 AND parent.room_epoch=$4 AND parent.target_node_id=$5
            AND parent.recipient_occupant_incarnation IS NOT DISTINCT FROM $6
            AND parent.recipient_connection_uuid IS NOT DISTINCT FROM $7
            AND parent.recipient_connection_epoch IS NOT DISTINCT FROM $8
            AND COALESCE((SELECT MAX(handoff_version) FROM cluster_muc_delivery_handoffs h
                          WHERE h.delivery_id=parent.delivery_id),0)=$9",
    )
    .bind(delivery.delivery_id)
    .bind(delivery.claim_token)
    .bind(delivery.room_id)
    .bind(delivery.room_epoch)
    .bind(&delivery.target_node_id)
    .bind(delivery.recipient_occupant_incarnation)
    .bind(delivery.recipient_connection_uuid)
    .bind(delivery.recipient_connection_epoch)
    .bind(delivery.handoff_version)
    .fetch_optional(&mut **tx)
    .await?
    .is_some())
}

pub async fn complete_cluster_muc_delivery_item(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
    ordinal: i32,
    stable_id: &str,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    if !lock_exact_item_claim(&mut tx, delivery).await? {
        tx.rollback().await?;
        return Ok(false);
    }
    let completed = sqlx::query(
        "UPDATE cluster_muc_event_delivery_items item
            SET completed_at=COALESCE(item.completed_at,clock_timestamp())
          WHERE item.delivery_id=$1 AND item.ordinal=$2 AND item.stable_id=$3",
    )
    .bind(delivery.delivery_id)
    .bind(ordinal)
    .bind(stable_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    tx.commit().await?;
    Ok(completed)
}

pub async fn retry_cluster_muc_outbox(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
    error: &str,
) -> Result<bool> {
    let error = bounded_error(error);
    if delivery.attempt_count >= 16 {
        return dead_letter_cluster_muc_outbox(pool, delivery, &error).await;
    }
    let delay_seconds = 2_i64.saturating_pow(delivery.attempt_count.clamp(1, 10) as u32);
    let retried = sqlx::query(
        "UPDATE cluster_muc_event_outbox SET
             claim_token=NULL,lease_until=NULL,last_error=$3,
             next_attempt_at=clock_timestamp()+make_interval(secs=>$4)
          WHERE delivery_id=$1 AND claim_token=$2
            AND expires_at>clock_timestamp()",
    )
    .bind(delivery.delivery_id)
    .bind(delivery.claim_token)
    .bind(&error)
    .bind(delay_seconds as f64)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    if retried {
        Ok(true)
    } else {
        dead_letter_cluster_muc_outbox(pool, delivery, &error).await
    }
}

pub async fn dead_letter_cluster_muc_outbox(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
    reason: &str,
) -> Result<bool> {
    let reason = bounded_error(reason);
    let mut tx = pool.begin().await?;
    let removed = remove_for_dead_letter(
        &mut tx,
        &[delivery.delivery_id],
        Some(delivery.claim_token),
        Some(&reason),
    )
    .await?;
    let moved = !removed.is_empty() && insert_dead_letters(&mut tx, removed).await? == 1;
    tx.commit().await?;
    Ok(moved)
}

pub async fn cleanup_cluster_muc_dead_letters(pool: &PgPool, limit: i64) -> Result<u64> {
    let mut tx = pool.begin().await?;
    let victims: Vec<(Uuid, i16)> = sqlx::query_as(
        "SELECT delivery_id,capacity_shard FROM cluster_muc_event_dead_letters
          WHERE purge_after<=clock_timestamp()
          ORDER BY purge_after,delivery_id FOR UPDATE LIMIT $1",
    )
    .bind(limit.clamp(1, 1000))
    .fetch_all(&mut *tx)
    .await?;
    if victims.is_empty() {
        tx.commit().await?;
        return Ok(0);
    }
    CapacityPlan::new(victims.iter().map(|(_, shard)| *shard))
        .lock_dead_letters_if_multiple(&mut tx)
        .await?;
    let removed =
        sqlx::query("DELETE FROM cluster_muc_event_dead_letters WHERE delivery_id=ANY($1)")
            .bind(victims.into_iter().map(|(id, _)| id).collect::<Vec<_>>())
            .execute(&mut *tx)
            .await?
            .rows_affected();
    tx.commit().await?;
    Ok(removed)
}

/// Remove MUC operation history and destroyed room incarnations after the
/// bounded online-recovery horizon. PostgreSQL rejects cleanup of live legal
/// holds and any operation which still has an outbox/dead-letter projection.
pub async fn cleanup_cluster_muc_history(
    pool: &PgPool,
    retention_days: i64,
    limit: i64,
) -> Result<(u64, u64)> {
    // The SQL function intentionally accepts INTEGER so callers cannot submit
    // unbounded retention or batch values.  Bind that exact PostgreSQL type;
    // binding Rust i64 values resolves the overload as (BIGINT, BIGINT) and
    // PostgreSQL will not implicitly narrow them to INTEGER.
    let retention_days = i32::try_from(retention_days.clamp(30, 36_500))
        .context("cluster MUC history retention exceeds i32")?;
    let limit = i32::try_from(limit.clamp(1, 1_000))
        .context("cluster MUC history cleanup limit exceeds i32")?;
    let (operations, rooms): (i64, i64) = sqlx::query_as(
        "SELECT operations_removed,rooms_removed
           FROM northstar_purge_cluster_muc_history($1,$2)",
    )
    .bind(retention_days)
    .bind(limit)
    .fetch_one(pool)
    .await?;
    Ok((operations.max(0) as u64, rooms.max(0) as u64))
}

pub async fn dead_letter_expired_cluster_muc_outbox(pool: &PgPool, limit: i64) -> Result<u64> {
    let mut tx = pool.begin().await?;
    let victims: Vec<(Uuid, Uuid, i16)> = sqlx::query_as(
        "SELECT delivery_id,room_id,capacity_shard::smallint FROM cluster_muc_event_outbox
          WHERE expires_at<=clock_timestamp() OR attempt_count>=16
          ORDER BY expires_at,delivery_id FOR UPDATE SKIP LOCKED LIMIT $1",
    )
    .bind(limit.clamp(1, 1000))
    .fetch_all(&mut *tx)
    .await?;
    if victims.is_empty() {
        tx.commit().await?;
        return Ok(0);
    }
    let plan = CapacityPlan::new(victims.iter().map(|(_, _, shard)| *shard));
    plan.lock_outbox_if_multiple(&mut tx).await?;
    let mut rooms = BTreeMap::<Uuid, Vec<Uuid>>::new();
    for (delivery_id, room_id, _) in victims {
        rooms.entry(room_id).or_default().push(delivery_id);
    }
    let mut removed = Vec::<Value>::new();
    for delivery_ids in rooms.into_values() {
        removed.extend(remove_for_dead_letter(&mut tx, &delivery_ids, None, None).await?);
    }
    plan.lock_dead_letters_if_multiple(&mut tx).await?;
    let moved = insert_dead_letters(&mut tx, removed).await?;
    tx.commit().await?;
    Ok(moved)
}

async fn remove_for_dead_letter(
    tx: &mut Transaction<'_, Postgres>,
    delivery_ids: &[Uuid],
    claim_token: Option<Uuid>,
    reason: Option<&str>,
) -> Result<Vec<Value>> {
    Ok(sqlx::query_scalar(
        "WITH removed AS (
             DELETE FROM cluster_muc_event_outbox
              WHERE delivery_id=ANY($1) AND ($2::uuid IS NULL OR claim_token=$2)
             RETURNING delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,
                       target_node_id,recipient_occupant_incarnation,payload_digest,
                       capacity_shard,attempt_count,
                       COALESCE($3::text,CASE WHEN expires_at<=clock_timestamp() THEN 'expired'
                            ELSE 'attempt_limit' END) AS terminal_reason,created_at
         ) SELECT to_jsonb(removed) FROM removed",
    )
    .bind(delivery_ids)
    .bind(claim_token)
    .bind(reason)
    .fetch_all(&mut **tx)
    .await?)
}

async fn insert_dead_letters(
    tx: &mut Transaction<'_, Postgres>,
    removed: Vec<Value>,
) -> Result<u64> {
    Ok(sqlx::query(
        "INSERT INTO cluster_muc_event_dead_letters(
             delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,
             target_node_id,recipient_occupant_incarnation,payload_digest,
             capacity_shard,attempt_count,terminal_reason,created_at)
         SELECT delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,
                target_node_id,recipient_occupant_incarnation,payload_digest,
                capacity_shard,attempt_count,terminal_reason,created_at
           FROM jsonb_populate_recordset(NULL::cluster_muc_event_dead_letters,$1)
         ON CONFLICT(delivery_id) DO NOTHING",
    )
    .bind(Value::Array(removed))
    .execute(&mut **tx)
    .await?
    .rows_affected())
}

pub async fn cluster_muc_outbox_snapshot(pool: &PgPool) -> Result<ClusterMucOutboxSnapshot> {
    let row = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS queued_rows,
                COUNT(*) FILTER (WHERE expires_at<=clock_timestamp())::BIGINT AS expired_rows,
                COUNT(*) FILTER (WHERE claim_token IS NOT NULL
                                  AND lease_until>clock_timestamp())::BIGINT AS claimed_rows,
                COALESCE(EXTRACT(EPOCH FROM clock_timestamp()-MIN(created_at)),0)::BIGINT
                    AS oldest_age_seconds,
                (SELECT COUNT(*)::BIGINT FROM cluster_muc_event_dead_letters)
                    AS dead_letter_rows
           FROM cluster_muc_event_outbox",
    )
    .fetch_one(pool)
    .await?;
    Ok(ClusterMucOutboxSnapshot {
        queued_rows: row.get("queued_rows"),
        expired_rows: row.get("expired_rows"),
        claimed_rows: row.get("claimed_rows"),
        dead_letter_rows: row.get("dead_letter_rows"),
        oldest_age_seconds: row.get("oldest_age_seconds"),
    })
}
