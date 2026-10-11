//! Cluster MUC occupant moderation: kick and role changes.

use super::*;

/// Apply a moderator kick only after re-reading both actor authorization and
/// the target's exact occupancy tuple under the room lock.
pub async fn kick_cluster_muc_occupancy(
    pool: &PgPool,
    operation_id: Uuid,
    actor: &ClusterMucOccupancyTarget,
    target: &ClusterMucOccupancyTarget,
    reason: Option<&str>,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        actor.room_id == target.room_id,
        "cross-room MUC kick rejected"
    );
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "kick reason is oversized"
    );
    let digest = request_digest(&json!({"actor":actor,"target":target,"reason":reason}))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "kick", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, actor.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    if room.room_epoch != actor.room_epoch || room.room_epoch != target.room_epoch {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    expire_due_in_room(&mut tx, actor.room_id).await?;
    let actor_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3
            AND full_jid=$4 AND nick=$5 AND connection_uuid=$6 AND connection_epoch=$7
            AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(actor.room_id)
    .bind(actor.occupant_incarnation)
    .bind(actor.occupancy_epoch)
    .bind(&actor.full_jid)
    .bind(&actor.nick)
    .bind(actor.connection_uuid)
    .bind(actor.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(actor_row) = actor_row else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    };
    let actor_current = occupancy_from_row(&actor_row);
    let current_affiliation: Option<String> = if let Some(user_id) =
        actor_row.get::<Option<Uuid>, _>("local_user_id")
    {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(actor.room_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
        )
        .bind(actor.room_id)
        .bind(&actor_current.bare_jid)
        .fetch_optional(&mut *tx)
        .await?
    };
    if current_affiliation.as_deref() == Some("outcast")
        || !(matches!(current_affiliation.as_deref(), Some("owner" | "admin"))
            || actor_current.role == "moderator")
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let target_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state IN ('active','suspended') AND lease_until>clock_timestamp()
          FOR UPDATE",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(target_row) = target_row else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    let target_current = occupancy_from_row(&target_row);
    if !exact_target_matches_row(target, &target_current) {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let target_durable_affiliation: Option<String> = if let Some(user_id) =
        target_row.get::<Option<Uuid>, _>("local_user_id")
    {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(target.room_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar(
                "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
            )
            .bind(target.room_id)
            .bind(&target_current.bare_jid)
            .fetch_optional(&mut *tx)
            .await?
    };
    if (current_affiliation.as_deref() == Some("admin")
        && matches!(
            target_durable_affiliation.as_deref(),
            Some("owner" | "admin")
        ))
        || (!matches!(current_affiliation.as_deref(), Some("owner" | "admin"))
            && (target_current.role == "moderator"
                || matches!(
                    target_durable_affiliation.as_deref(),
                    Some("owner" | "admin")
                )))
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let audience = active_audience(&mut tx, actor.room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, actor.room_id, false).await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',ended_at=clock_timestamp(),lease_until=clock_timestamp(),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3
            AND connection_uuid=$4 AND connection_epoch=$5",
    )
    .bind(target.room_id)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .execute(&mut *tx)
    .await?;
    let authorization = json!({
        "actor_incarnation":actor.occupant_incarnation,
        "actor_occupancy_epoch":actor.occupancy_epoch,
        "durable_affiliation":current_affiliation,
        "live_role":actor_current.role,
    });
    let details = json!({"reason":reason,"status":307});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: actor.room_id,
            room_epoch: room.room_epoch,
            kind: "kick",
            digest: &digest,
            actor_bare_jid: Some(&actor_current.bare_jid),
            actor_full_jid: Some(&actor_current.full_jid),
            actor_affiliation: current_affiliation.as_deref(),
            authorization_source: if actor_row.get::<Option<Uuid>, _>("local_user_id").is_some() {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: Some(target),
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucTransitionOutcome::Applied)
}

/// Change a live role under the same exact actor/target fences as a kick.
/// `none` is intentionally excluded; removals must use the kick operation so
/// their status and terminal transition cannot be confused with soft role
/// presence.
pub async fn change_cluster_muc_role(
    pool: &PgPool,
    operation_id: Uuid,
    actor: &ClusterMucOccupancyTarget,
    target: &ClusterMucOccupancyTarget,
    new_role: &str,
    reason: Option<&str>,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        actor.room_id == target.room_id,
        "cross-room MUC role change rejected"
    );
    anyhow::ensure!(
        matches!(new_role, "moderator" | "participant" | "visitor"),
        "terminal role changes must use the kick path"
    );
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "role reason is oversized"
    );
    let digest = request_digest(&json!({
        "actor":actor,"target":target,"new_role":new_role,"reason":reason,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "role", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, actor.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed || room.room_epoch != actor.room_epoch || room.room_epoch != target.room_epoch
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    expire_due_in_room(&mut tx, actor.room_id).await?;
    let actor_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(actor.room_id)
    .bind(actor.room_epoch)
    .bind(actor.occupant_incarnation)
    .bind(actor.occupancy_epoch)
    .bind(&actor.full_jid)
    .bind(&actor.nick)
    .bind(actor.connection_uuid)
    .bind(actor.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(actor_row) = actor_row else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    };
    let actor_current = occupancy_from_row(&actor_row);
    let actor_affiliation: Option<String> = if let Some(user_id) =
        actor_row.get::<Option<Uuid>, _>("local_user_id")
    {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(actor.room_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar(
                "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
            ).bind(actor.room_id).bind(&actor_current.bare_jid).fetch_optional(&mut *tx).await?
    };
    if actor_affiliation.as_deref() == Some("outcast")
        || !(matches!(actor_affiliation.as_deref(), Some("owner" | "admin"))
            || actor_current.role == "moderator")
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let target_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state IN ('active','suspended') AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(target_row) = target_row else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    let target_current = occupancy_from_row(&target_row);
    if !exact_target_matches_row(target, &target_current) {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let target_affiliation: Option<String> = if let Some(user_id) =
        target_row.get::<Option<Uuid>, _>("local_user_id")
    {
        sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
        )
        .bind(target.room_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar(
                "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
            ).bind(target.room_id).bind(&target_current.bare_jid).fetch_optional(&mut *tx).await?
    };
    if (actor_affiliation.as_deref() == Some("admin")
        && matches!(target_affiliation.as_deref(), Some("owner" | "admin")))
        || (!matches!(actor_affiliation.as_deref(), Some("owner" | "admin"))
            && (new_role == "moderator"
                || target_current.role == "moderator"
                || matches!(target_affiliation.as_deref(), Some("owner" | "admin"))))
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let audience = active_audience(&mut tx, actor.room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, actor.room_id, false).await?;
    let changed = sqlx::query(
        "UPDATE cluster_muc_occupancies SET role=$9,updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state IN ('active','suspended')",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(new_role)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    anyhow::ensure!(changed == 1, "exact MUC role target changed concurrently");
    let authorization = json!({
        "actor_incarnation":actor.occupant_incarnation,
        "actor_occupancy_epoch":actor.occupancy_epoch,
        "durable_affiliation":actor_affiliation,"live_role":actor_current.role,
    });
    let details = json!({"old_role":target_current.role,"new_role":new_role,"reason":reason});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: actor.room_id,
            room_epoch: room.room_epoch,
            kind: "role",
            digest: &digest,
            actor_bare_jid: Some(&actor_current.bare_jid),
            actor_full_jid: Some(&actor_current.full_jid),
            actor_affiliation: actor_affiliation.as_deref(),
            authorization_source: if actor_row.get::<Option<Uuid>, _>("local_user_id").is_some() {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: Some(target),
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucTransitionOutcome::Applied)
}
