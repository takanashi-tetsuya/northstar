//! Cluster MUC read-side authority queries: event context, wake descriptors, delivery audiences and occupancy snapshots.

use super::*;

pub async fn cluster_muc_event_context(
    pool: &PgPool,
    operation_id: Uuid,
) -> Result<Option<ClusterMucEventContext>> {
    let row = sqlx::query(
        "SELECT op.operation_kind,op.actor_full_jid,op.actor_affiliation,op.details,
                op.room_epoch,op.target_snapshot,r.localpart,r.non_anonymous,r.occupant_id_secret
           FROM cluster_muc_operations op
           JOIN muc_rooms r ON r.id=op.room_id AND r.room_epoch=op.room_epoch
          WHERE op.operation_id=$1",
    )
    .bind(operation_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let target = match row.get::<Option<Value>, _>("target_snapshot") {
        Some(value) => {
            let target: ClusterMucOccupancy = serde_json::from_value(value)
                .context("cluster MUC immutable target snapshot is malformed")?;
            Some(ClusterMucEventOccupant {
                full_jid: target.full_jid,
                bare_jid: target.bare_jid,
                nick: target.nick,
                affiliation: target.affiliation,
                role: target.role,
                presence_payload: target.presence_payload,
                occupant_incarnation: target.occupant_incarnation,
                occupancy_epoch: target.occupancy_epoch,
                connection_uuid: target.connection_uuid,
                connection_epoch: target.connection_epoch,
            })
        }
        None => None,
    };
    Ok(Some(ClusterMucEventContext {
        operation_kind: row.get("operation_kind"),
        room_localpart: row.get("localpart"),
        room_epoch: row.get("room_epoch"),
        room_non_anonymous: row.get("non_anonymous"),
        occupant_id_secret: row
            .get::<Option<Vec<u8>>, _>("occupant_id_secret")
            .unwrap_or_default(),
        actor_full_jid: row.get("actor_full_jid"),
        actor_affiliation: row.get("actor_affiliation"),
        details: row.get("details"),
        target,
    }))
}

pub async fn cluster_muc_wake_descriptor(
    pool: &PgPool,
    operation_id: Uuid,
) -> Result<Option<ClusterMucWakeDescriptor>> {
    let row = sqlx::query(
        "SELECT room_id,event_id,event_sequence FROM cluster_muc_operations
          WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut target_nodes = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT target_node_id FROM cluster_muc_event_outbox
          WHERE operation_id=$1 ORDER BY target_node_id",
    )
    .bind(operation_id)
    .fetch_all(pool)
    .await?;
    target_nodes.dedup();
    Ok(Some(ClusterMucWakeDescriptor {
        operation_id,
        room_id: row.get("room_id"),
        event_id: row.get("event_id"),
        event_sequence: row.get("event_sequence"),
        target_nodes,
    }))
}

pub async fn cluster_muc_delivery_audience_is_current(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
) -> Result<bool> {
    let Some(incarnation) = delivery.recipient_occupant_incarnation else {
        return Ok(false);
    };
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM cluster_muc_occupancies o
             JOIN muc_rooms r ON r.id=o.room_id AND r.room_epoch=o.room_epoch
              WHERE o.room_id=$1 AND o.room_epoch=$2
                AND o.occupant_incarnation=$3 AND o.occupancy_epoch=$4
                AND o.full_jid=$5 AND o.nick=$6
                AND o.connection_uuid=$7 AND o.connection_epoch=$8
                AND o.owner_node_id=$9 AND o.state IN ('active','suspended')
                AND o.lease_until>clock_timestamp() AND r.destroyed_at IS NULL)",
    )
    .bind(delivery.room_id)
    .bind(delivery.room_epoch)
    .bind(incarnation)
    .bind(delivery.recipient_occupancy_epoch)
    .bind(&delivery.recipient_full_jid)
    .bind(&delivery.recipient_nick)
    .bind(delivery.recipient_connection_uuid)
    .bind(delivery.recipient_connection_epoch)
    .bind(&delivery.target_node_id)
    .fetch_one(pool)
    .await?)
}

/// Read the exact audience incarnation even after it became terminal. This
/// is used only to render the already-committed config/affiliation event; it
/// never restores authorization or extends the lease.
pub async fn cluster_muc_delivery_recipient_snapshot(
    pool: &PgPool,
    delivery: &ClusterMucOutboxDelivery,
) -> Result<Option<ClusterMucAudienceSnapshot>> {
    let Some(incarnation) = delivery.recipient_occupant_incarnation else {
        return Ok(None);
    };
    let handoff = sqlx::query_scalar::<_, Value>(
        "SELECT audience_snapshot FROM cluster_muc_delivery_handoffs
          WHERE delivery_id=$1 ORDER BY handoff_version DESC LIMIT 1",
    )
    .bind(delivery.delivery_id)
    .fetch_optional(pool)
    .await?;
    if let Some(handoff) = handoff {
        let snapshot: ClusterMucAudienceSnapshot = serde_json::from_value(handoff)
            .context("cluster MUC handoff audience snapshot is malformed")?;
        anyhow::ensure!(
            snapshot.room_id == delivery.room_id
                && snapshot.room_epoch == delivery.room_epoch
                && snapshot.occupant_incarnation == incarnation
                && Some(snapshot.occupancy_epoch) == delivery.recipient_occupancy_epoch
                && Some(snapshot.connection_uuid) == delivery.recipient_connection_uuid
                && Some(snapshot.connection_epoch) == delivery.recipient_connection_epoch
                && snapshot.owner_node_id == delivery.target_node_id,
            "cluster MUC handoff audience snapshot is not exactly bound"
        );
        return Ok(Some(snapshot));
    }
    let audience = sqlx::query_scalar::<_, Value>(
        "SELECT audience_snapshot FROM cluster_muc_operations
          WHERE operation_id=$1 AND room_id=$2 AND room_epoch=$3
            AND event_id=$4 AND event_sequence=$5",
    )
    .bind(delivery.operation_id)
    .bind(delivery.room_id)
    .bind(delivery.room_epoch)
    .bind(delivery.event_id)
    .bind(delivery.event_sequence)
    .fetch_optional(pool)
    .await?;
    let Some(audience) = audience else {
        return Ok(None);
    };
    let audience: Vec<ClusterMucAudienceSnapshot> = serde_json::from_value(audience)
        .context("cluster MUC immutable audience snapshot is malformed")?;
    Ok(audience.into_iter().find(|snapshot| {
        snapshot.room_id == delivery.room_id
            && snapshot.room_epoch == delivery.room_epoch
            && snapshot.occupant_incarnation == incarnation
            && Some(snapshot.occupancy_epoch) == delivery.recipient_occupancy_epoch
            && Some(snapshot.full_jid.as_str()) == delivery.recipient_full_jid.as_deref()
            && Some(snapshot.nick.as_str()) == delivery.recipient_nick.as_deref()
            && Some(snapshot.connection_uuid) == delivery.recipient_connection_uuid
            && Some(snapshot.connection_epoch) == delivery.recipient_connection_epoch
            && snapshot.owner_node_id == delivery.target_node_id
    }))
}

pub async fn cluster_muc_exact_occupancy_snapshot(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
) -> Result<Option<ClusterMucOccupancy>> {
    let row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5
            AND connection_uuid=$6 AND connection_epoch=$7",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| occupancy_from_row(&row)))
}

/// PostgreSQL catch-up source used after Redis/listener recovery.  Returned
/// rows are only the exact unexpired occupancies owned by this node.
pub async fn authoritative_cluster_muc_occupancies_for_node(
    pool: &PgPool,
    node_id: &str,
) -> Result<Vec<ClusterMucOccupancy>> {
    validate_node_id(node_id)?;
    let rows = sqlx::query(
        "SELECT o.* FROM cluster_muc_occupancies o
          JOIN muc_rooms r ON r.id=o.room_id AND r.room_epoch=o.room_epoch
         WHERE o.owner_node_id=$1 AND o.state IN ('active','suspended')
           AND o.lease_until>clock_timestamp() AND r.destroyed_at IS NULL
         ORDER BY o.room_id,o.occupancy_epoch",
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(occupancy_from_row).collect())
}

/// Resolve only locally observed actors, avoiding a node-wide occupancy scan
/// on every lease tick. A changed room, connection, nickname or owner node
/// simply omits that candidate from the result.
pub async fn resolve_cluster_muc_occupancies_batch(
    pool: &PgPool,
    candidates: &[ClusterMucOccupancyLookup],
    owner_node_id: &str,
) -> Result<Vec<ClusterMucResolvedOccupancy>> {
    validate_node_id(owner_node_id)?;
    anyhow::ensure!(
        candidates.len() <= MAX_MUC_OCCUPANCY_RENEW_BATCH,
        "MUC occupancy lookup batch exceeds its limit"
    );
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = std::collections::HashSet::with_capacity(candidates.len());
    anyhow::ensure!(
        candidates.iter().all(|candidate| {
            seen.insert((
                candidate.room_localpart.as_str(),
                candidate.occupant_incarnation,
                candidate.connection_uuid,
            ))
        }),
        "MUC occupancy lookup batch contains a duplicate incarnation"
    );
    let input = serde_json::to_value(candidates)?;
    let rows = sqlx::query(
        "SELECT input.room_localpart,o.room_id,o.room_epoch,
                o.occupant_incarnation,o.occupancy_epoch,o.full_jid,o.nick,
                o.connection_uuid,o.connection_epoch
           FROM jsonb_to_recordset($1::jsonb) AS input(
                room_localpart text,full_jid text,nick text,
                occupant_incarnation uuid,connection_uuid uuid)
           JOIN muc_rooms r ON r.localpart=input.room_localpart
                AND r.destroyed_at IS NULL
           JOIN cluster_muc_occupancies o ON o.room_id=r.id
                AND o.room_epoch=r.room_epoch
                AND o.occupant_incarnation=input.occupant_incarnation
                AND o.full_jid=input.full_jid AND o.nick=input.nick
                AND o.connection_uuid=input.connection_uuid
          WHERE o.owner_node_id=$2 AND o.state IN ('active','suspended')
            AND o.lease_until>clock_timestamp()
          ORDER BY input.room_localpart,o.occupant_incarnation",
    )
    .bind(input)
    .bind(owner_node_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClusterMucResolvedOccupancy {
            room_localpart: row.get("room_localpart"),
            target: ClusterMucOccupancyTarget {
                room_id: row.get("room_id"),
                room_epoch: row.get("room_epoch"),
                occupant_incarnation: row.get("occupant_incarnation"),
                occupancy_epoch: row.get("occupancy_epoch"),
                full_jid: row.get("full_jid"),
                nick: row.get("nick"),
                connection_uuid: row.get("connection_uuid"),
                connection_epoch: row.get("connection_epoch"),
            },
        })
        .collect())
}

/// Distinguish a committed room departure from a lost lease or ownership
/// fence. The room's current epoch is deliberately not part of this lookup:
/// the old occupant remains terminal after that room is recreated.
pub async fn committed_terminal_cluster_muc_occupancies_batch(
    pool: &PgPool,
    candidates: &[ClusterMucOccupancyLookup],
    owner_node_id: &str,
) -> Result<Vec<ClusterMucOccupancyLookup>> {
    validate_node_id(owner_node_id)?;
    anyhow::ensure!(
        candidates.len() <= MAX_MUC_OCCUPANCY_RENEW_BATCH,
        "MUC terminal lookup batch exceeds its limit"
    );
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = std::collections::HashSet::with_capacity(candidates.len());
    anyhow::ensure!(
        candidates.iter().all(|candidate| seen.insert((
            candidate.room_localpart.as_str(),
            candidate.full_jid.as_str(),
            candidate.nick.as_str(),
            candidate.occupant_incarnation,
            candidate.connection_uuid,
        ))),
        "MUC terminal lookup batch contains a duplicate identity"
    );
    let input = serde_json::to_value(candidates)?;
    let rows = sqlx::query(
        "SELECT input.room_localpart,input.full_jid,input.nick,
                input.occupant_incarnation,input.connection_uuid
           FROM jsonb_to_recordset($1::jsonb) AS input(
                room_localpart text,full_jid text,nick text,
                occupant_incarnation uuid,connection_uuid uuid)
           JOIN muc_rooms r ON r.localpart=input.room_localpart
           JOIN cluster_muc_occupancies o ON o.room_id=r.id
                AND o.occupant_incarnation=input.occupant_incarnation
                AND o.full_jid=input.full_jid AND o.nick=input.nick
                AND o.connection_uuid=input.connection_uuid
          WHERE o.owner_node_id=$2 AND o.state='revoked'
            AND o.ended_at IS NOT NULL
          ORDER BY input.room_localpart,input.occupant_incarnation",
    )
    .bind(input)
    .bind(owner_node_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClusterMucOccupancyLookup {
            room_localpart: row.get("room_localpart"),
            full_jid: row.get("full_jid"),
            nick: row.get("nick"),
            occupant_incarnation: row.get("occupant_incarnation"),
            connection_uuid: row.get("connection_uuid"),
        })
        .collect())
}

/// Resolve a departing local actor without trusting a nickname or a room
/// address alone. The returned tuple is still rechecked by the leave writer.
#[allow(clippy::too_many_arguments)]
pub async fn cluster_muc_occupancy_target_for_disconnect(
    pool: &PgPool,
    room_localpart: &str,
    full_jid: &str,
    nick: &str,
    occupant_incarnation: Uuid,
    connection_uuid: Uuid,
    owner_node_id: &str,
) -> Result<Option<ClusterMucOccupancyTarget>> {
    validate_node_id(owner_node_id)?;
    let row = sqlx::query(
        "SELECT o.room_id,o.room_epoch,o.occupant_incarnation,
                o.occupancy_epoch,o.full_jid,o.nick,
                o.connection_uuid,o.connection_epoch
           FROM cluster_muc_occupancies o
           JOIN muc_rooms r ON r.id=o.room_id AND r.room_epoch=o.room_epoch
          WHERE r.localpart=$1 AND r.destroyed_at IS NULL
            AND o.full_jid=$2 AND o.nick=$3
            AND o.occupant_incarnation=$4 AND o.connection_uuid=$5
            AND o.owner_node_id=$6 AND o.state='active'
            AND o.lease_until>clock_timestamp()",
    )
    .bind(room_localpart)
    .bind(full_jid)
    .bind(nick)
    .bind(occupant_incarnation)
    .bind(connection_uuid)
    .bind(owner_node_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| ClusterMucOccupancyTarget {
        room_id: row.get("room_id"),
        room_epoch: row.get("room_epoch"),
        occupant_incarnation: row.get("occupant_incarnation"),
        occupancy_epoch: row.get("occupancy_epoch"),
        full_jid: row.get("full_jid"),
        nick: row.get("nick"),
        connection_uuid: row.get("connection_uuid"),
        connection_epoch: row.get("connection_epoch"),
    }))
}

pub async fn cluster_muc_occupancy_target(
    pool: &PgPool,
    room_id: Uuid,
    occupant_incarnation: Uuid,
    connection_uuid: Uuid,
) -> Result<Option<ClusterMucOccupancyTarget>> {
    let row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND occupant_incarnation=$2 AND connection_uuid=$3
            AND state IN ('active','suspended') AND lease_until>clock_timestamp()",
    )
    .bind(room_id)
    .bind(occupant_incarnation)
    .bind(connection_uuid)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        let occupancy = occupancy_from_row(&row);
        ClusterMucOccupancyTarget::from(&occupancy)
    }))
}

pub async fn cluster_muc_occupancy_target_by_nick(
    pool: &PgPool,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    nick: &str,
) -> Result<Option<ClusterMucOccupancyTarget>> {
    validate_nick(nick)?;
    let row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND nick=$3
            AND state IN ('active','suspended') AND lease_until>clock_timestamp()",
    )
    .bind(room_id)
    .bind(expected_room_epoch)
    .bind(nick)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        let occupancy = occupancy_from_row(&row);
        ClusterMucOccupancyTarget::from(&occupancy)
    }))
}

pub async fn cluster_muc_room_is_empty(pool: &PgPool, room_id: Uuid) -> Result<bool> {
    Ok(!sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_occupancies
          WHERE room_id=$1 AND state IN ('active','suspended')
            AND lease_until>clock_timestamp())",
    )
    .bind(room_id)
    .fetch_one(pool)
    .await?)
}
