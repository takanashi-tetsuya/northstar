//! Cluster MUC occupancy claim, renewal, transition and rename authority.

use super::*;

/// Atomically authorizes and claims one nickname/full-JID occupancy.
pub async fn claim_cluster_muc_occupancy(
    pool: &PgPool,
    request: ClusterMucJoin<'_>,
) -> Result<ClusterMucJoinOutcome> {
    request.principal.validate()?;
    validate_node_id(request.owner_node_id)?;
    validate_nick(request.nick)?;
    anyhow::ensure!(
        !request.connection_uuid.is_nil(),
        "MUC connection UUID is nil"
    );
    anyhow::ensure!(
        request.connection_epoch >= 1,
        "MUC connection epoch is invalid"
    );
    anyhow::ensure!(
        !request.occupant_incarnation.is_nil(),
        "MUC occupant incarnation is nil"
    );
    anyhow::ensure!(
        request.presence_payload.len() <= MAX_PAYLOAD_BYTES,
        "MUC presence payload is oversized"
    );
    let full_jid = crate::jid::canonicalize(request.full_jid)?;
    anyhow::ensure!(
        full_jid == request.full_jid,
        "MUC full JID must be canonical"
    );
    anyhow::ensure!(
        muc_principal_owns_address(&full_jid, &request.principal)?,
        "MUC full JID does not belong to the authorized principal"
    );
    let lease_seconds = validate_lease(request.lease)?;
    let digest = request_digest(&json!({
        "room_id": request.room_id,
        "room_epoch": request.expected_room_epoch,
        "config_version": request.expected_config_version,
        "principal": &request.principal,
        "full_jid": request.full_jid,
        "nick": request.nick,
        "node": request.owner_node_id,
        "connection_uuid": request.connection_uuid,
        "connection_epoch": request.connection_epoch,
        "occupant_incarnation": request.occupant_incarnation,
    }))?;

    let mut tx = pool.begin().await?;
    if let Some((room_id, _)) =
        existing_operation(&mut tx, request.operation_id, "join", &digest).await?
    {
        anyhow::ensure!(room_id == request.room_id, "MUC replay changed rooms");
        let row = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupant_incarnation=$2",
        )
        .bind(request.room_id)
        .bind(request.occupant_incarnation)
        .fetch_one(&mut *tx)
        .await?;
        let occupancy = occupancy_from_row(&row);
        tx.commit().await?;
        return Ok(ClusterMucJoinOutcome::Replay(occupancy));
    }
    let Some(room) = lock_room(&mut tx, request.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::RoomMissing);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::RoomDestroyed);
    }
    if room.room_epoch != request.expected_room_epoch
        || room.config_version != request.expected_config_version
    {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::StaleRoom);
    }
    expire_due_in_room(&mut tx, request.room_id).await?;
    let affiliation = affiliation_in_tx(&mut tx, request.room_id, &request.principal).await?;
    if affiliation.as_deref() == Some("outcast") {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::Outcast);
    }
    if room.members_only && affiliation.is_none() {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::MembershipRequired);
    }
    if room.configuration_state != "active"
        && !(room.configuration_state == "locked"
            && !room.configuration_expired
            && room.configuration_owner_jid.as_deref() == Some(request.full_jid)
            && affiliation.as_deref() == Some("owner"))
    {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::RoomLocked);
    }
    let reserved_for_other: bool = match &request.principal {
        ClusterMucPrincipal::Local { user_id, .. } => {
            sqlx::query_scalar(
                "SELECT EXISTS(
                 SELECT 1 FROM muc_affiliations
                  WHERE room_id=$1 AND reserved_nick=$2 AND user_id<>$3
                 UNION ALL
                 SELECT 1 FROM muc_external_affiliations
                  WHERE room_id=$1 AND reserved_nick=$2)",
            )
            .bind(request.room_id)
            .bind(request.nick)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?
        }
        ClusterMucPrincipal::Federated { bare_jid, .. } => {
            sqlx::query_scalar(
                "SELECT EXISTS(
                 SELECT 1 FROM muc_affiliations
                  WHERE room_id=$1 AND reserved_nick=$2
                 UNION ALL
                 SELECT 1 FROM muc_external_affiliations
                  WHERE room_id=$1 AND reserved_nick=$2 AND jid<>$3)",
            )
            .bind(request.room_id)
            .bind(request.nick)
            .bind(bare_jid)
            .fetch_one(&mut *tx)
            .await?
        }
    };
    if reserved_for_other {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::ReservedNickname);
    }
    let nick_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_occupancies
          WHERE room_id=$1 AND nick=$2 AND state IN ('active','suspended'))",
    )
    .bind(request.room_id)
    .bind(request.nick)
    .fetch_one(&mut *tx)
    .await?;
    if nick_exists {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::NicknameConflict);
    }
    let full_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_occupancies
          WHERE room_id=$1 AND full_jid=$2 AND state IN ('active','suspended'))",
    )
    .bind(request.room_id)
    .bind(request.full_jid)
    .fetch_one(&mut *tx)
    .await?;
    if full_exists {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::FullJidConflict);
    }
    let privileged = matches!(affiliation.as_deref(), Some("owner" | "admin"));
    let capacity = i64::from(room.max_occupants) + if privileged { 10 } else { 0 };
    let occupants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM cluster_muc_occupancies
          WHERE room_id=$1 AND state IN ('active','suspended')",
    )
    .bind(request.room_id)
    .fetch_one(&mut *tx)
    .await?;
    if occupants >= capacity {
        tx.rollback().await?;
        return Ok(ClusterMucJoinOutcome::Full);
    }

    let (occupancy_epoch, event_sequence) =
        allocate_room_epochs(&mut tx, request.room_id, true).await?;
    let occupancy_epoch = occupancy_epoch.context("MUC occupancy epoch was not allocated")?;
    let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
    let role = if matches!(affiliation.as_str(), "owner" | "admin") {
        "moderator"
    } else if room.moderated && affiliation == "none" {
        "visitor"
    } else {
        "participant"
    };
    let (identity_kind, local_user_id, authenticated_domain) = match &request.principal {
        ClusterMucPrincipal::Local { user_id, .. } => ("local", Some(*user_id), None),
        ClusterMucPrincipal::Federated {
            authenticated_domain,
            ..
        } => ("federated", None, Some(authenticated_domain.as_str())),
    };
    let row = sqlx::query(
        "INSERT INTO cluster_muc_occupancies(
             room_id,room_epoch,occupant_incarnation,occupancy_epoch,config_version,
             identity_kind,local_user_id,bare_jid,full_jid,nick,authenticated_domain,
             owner_node_id,connection_uuid,connection_epoch,sm_session_id,state,role,
             affiliation,presence_payload,lease_until)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                'active',$16,$17,$18,clock_timestamp()+make_interval(secs=>$19))
         RETURNING *",
    )
    .bind(request.room_id)
    .bind(room.room_epoch)
    .bind(request.occupant_incarnation)
    .bind(occupancy_epoch)
    .bind(room.config_version)
    .bind(identity_kind)
    .bind(local_user_id)
    .bind(request.principal.bare_jid())
    .bind(request.full_jid)
    .bind(request.nick)
    .bind(authenticated_domain)
    .bind(request.owner_node_id)
    .bind(request.connection_uuid)
    .bind(request.connection_epoch)
    .bind(request.sm_session_id)
    .bind(role)
    .bind(&affiliation)
    .bind(request.presence_payload)
    .bind(lease_seconds as f64)
    .fetch_one(&mut *tx)
    .await?;
    let occupancy = occupancy_from_row(&row);
    let target = ClusterMucOccupancyTarget::from(&occupancy);
    let audience = active_audience(&mut tx, request.room_id).await?;
    let authorization = json!({
        "source": if matches!(&request.principal, ClusterMucPrincipal::Local { .. }) {
            "local_database"
        } else {
            "federated_verified"
        },
        "principal": &request.principal,
        "affiliation": affiliation,
        "room_epoch": room.room_epoch,
        "config_version": room.config_version,
    });
    let details = json!({"role": role, "created_occupancy": true});
    // The operation UUID is also the server-authoritative XEP-0359 event ID.
    // Synchronous protocol responses and any at-least-once outbox retry can
    // therefore share one identifier without another post-commit lookup.
    let event_id = request.operation_id;
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id: request.operation_id,
            room_id: request.room_id,
            room_epoch: room.room_epoch,
            kind: "join",
            digest: &digest,
            actor_bare_jid: Some(request.principal.bare_jid()),
            actor_full_jid: Some(request.full_jid),
            actor_affiliation: Some(&affiliation),
            authorization_source: if matches!(&request.principal, ClusterMucPrincipal::Local { .. })
            {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: Some(&target),
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucJoinOutcome::Joined(occupancy))
}

/// Extend an exact live occupancy lease.  A stale node, reused nickname or
/// older connection epoch changes zero rows and therefore loses authority.
pub async fn renew_cluster_muc_occupancy(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
    lease: Duration,
) -> Result<bool> {
    validate_node_id(owner_node_id)?;
    let seconds = validate_lease(lease)?;
    Ok(sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET lease_until=clock_timestamp()+make_interval(secs=>$10),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND owner_node_id=$9 AND state IN ('active','suspended')
            AND lease_until > clock_timestamp()",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(seconds as f64)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Refresh a bounded set of exact leases in one database round trip. Only
/// rows returned by PostgreSQL still belong to this node; callers must fence
/// every omitted local actor before using its room authority again.
pub async fn renew_cluster_muc_occupancies_batch(
    pool: &PgPool,
    targets: &[ClusterMucOccupancyTarget],
    owner_node_id: &str,
    lease: Duration,
) -> Result<Vec<ClusterMucOccupancyTarget>> {
    validate_node_id(owner_node_id)?;
    let seconds = validate_lease(lease)?;
    anyhow::ensure!(
        targets.len() <= MAX_MUC_OCCUPANCY_RENEW_BATCH,
        "MUC occupancy renewal batch exceeds its limit"
    );
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = std::collections::HashSet::with_capacity(targets.len());
    anyhow::ensure!(
        targets
            .iter()
            .all(|target| seen.insert((target.room_id, target.occupant_incarnation))),
        "MUC occupancy renewal batch contains a duplicate incarnation"
    );
    let input = serde_json::to_value(targets)?;
    let rows = sqlx::query(
        "WITH input AS MATERIALIZED (
             SELECT * FROM jsonb_to_recordset($1::jsonb) AS item(
                 room_id uuid,room_epoch uuid,occupant_incarnation uuid,
                 occupancy_epoch bigint,full_jid text,nick text,
                 connection_uuid uuid,connection_epoch bigint)
         ), locked AS MATERIALIZED (
             SELECT o.room_id,o.occupant_incarnation
               FROM cluster_muc_occupancies o
               JOIN input ON o.room_id=input.room_id
                    AND o.room_epoch=input.room_epoch
                    AND o.occupant_incarnation=input.occupant_incarnation
                    AND o.occupancy_epoch=input.occupancy_epoch
                    AND o.full_jid=input.full_jid AND o.nick=input.nick
                    AND o.connection_uuid=input.connection_uuid
                    AND o.connection_epoch=input.connection_epoch
              WHERE o.owner_node_id=$2 AND o.state IN ('active','suspended')
                AND o.lease_until>clock_timestamp()
              ORDER BY o.room_id,o.occupant_incarnation
              FOR UPDATE OF o
         )
         UPDATE cluster_muc_occupancies AS o
            SET lease_until=clock_timestamp()+make_interval(secs=>$3),
                updated_at=clock_timestamp()
           FROM locked
          WHERE o.room_id=locked.room_id
            AND o.occupant_incarnation=locked.occupant_incarnation
      RETURNING o.room_id,o.room_epoch,o.occupant_incarnation,
                o.occupancy_epoch,o.full_jid,o.nick,
                o.connection_uuid,o.connection_epoch",
    )
    .bind(input)
    .bind(owner_node_id)
    .bind(seconds as f64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ClusterMucOccupancyTarget {
            room_id: row.get("room_id"),
            room_epoch: row.get("room_epoch"),
            occupant_incarnation: row.get("occupant_incarnation"),
            occupancy_epoch: row.get("occupancy_epoch"),
            full_jid: row.get("full_jid"),
            nick: row.get("nick"),
            connection_uuid: row.get("connection_uuid"),
            connection_epoch: row.get("connection_epoch"),
        })
        .collect())
}

/// Refresh bounded ordinary presence soft-state while extending the exact PG
/// lease. This is not an authorization mutation and therefore does not
/// allocate an operation/event sequence.
pub async fn refresh_cluster_muc_presence(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
    presence_payload: &str,
    lease: Duration,
) -> Result<bool> {
    validate_node_id(owner_node_id)?;
    anyhow::ensure!(
        presence_payload.len() <= MAX_PAYLOAD_BYTES,
        "MUC presence payload is oversized"
    );
    let seconds = validate_lease(lease)?;
    Ok(sqlx::query(
        "UPDATE cluster_muc_occupancies SET presence_payload=$10,
             lease_until=clock_timestamp()+make_interval(secs=>$11),updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8 AND owner_node_id=$9
            AND state='active' AND lease_until>clock_timestamp()",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(presence_payload)
    .bind(seconds as f64)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn associate_cluster_muc_sm_session(
    pool: &PgPool,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
    sm_session_id: Uuid,
) -> Result<bool> {
    validate_node_id(owner_node_id)?;
    Ok(sqlx::query(
        "UPDATE cluster_muc_occupancies SET sm_session_id=$10,updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8 AND owner_node_id=$9
            AND state='active' AND lease_until>clock_timestamp()",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(sm_session_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn suspended_cluster_muc_occupancy(
    pool: &PgPool,
    room_id: Uuid,
    room_epoch: Uuid,
    sm_session_id: Uuid,
    full_jid: &str,
    nick: &str,
) -> Result<Option<ClusterMucOccupancy>> {
    let full_jid = crate::jid::canonicalize(full_jid)?;
    validate_nick(nick)?;
    let row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND sm_session_id=$3
            AND full_jid=$4 AND nick=$5 AND state='suspended'
            AND lease_until>clock_timestamp()",
    )
    .bind(room_id)
    .bind(room_epoch)
    .bind(sm_session_id)
    .bind(full_jid)
    .bind(nick)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| occupancy_from_row(&row)))
}

#[derive(Serialize)]
struct SelfTransitionDigest<'a> {
    room_id: Uuid,
    room_epoch: Uuid,
    occupant_incarnation: Uuid,
    occupancy_epoch: i64,
    full_jid: &'a str,
    nick: &'a str,
    connection_uuid: Uuid,
    connection_epoch: i64,
    transition: &'a str,
    new_connection_uuid: Option<Uuid>,
    new_connection_epoch: Option<i64>,
    sm_session_id: Option<Uuid>,
}

/// Suspend, resume or leave one exact occupant.  Resume preserves the stable
/// occupant incarnation while advancing the connection epoch.
#[allow(clippy::too_many_arguments)]
pub async fn transition_cluster_muc_occupancy(
    pool: &PgPool,
    operation_id: Uuid,
    target: &ClusterMucOccupancyTarget,
    transition: &str,
    owner_node_id: &str,
    new_connection_uuid: Option<Uuid>,
    new_connection_epoch: Option<i64>,
    sm_session_id: Option<Uuid>,
    lease: Duration,
) -> Result<ClusterMucTransitionOutcome> {
    transition_cluster_muc_occupancy_with_status(
        pool,
        operation_id,
        target,
        transition,
        owner_node_id,
        new_connection_uuid,
        new_connection_epoch,
        sm_session_id,
        lease,
        None,
        None,
    )
    .await
}

/// Transfer one active federated actor to a new authenticated S2S connection.
/// The old connection and any late disconnect remain fenced by its exact UUID
/// and epoch. A different actor or authenticated domain cannot claim the row.
pub async fn rebind_federated_cluster_muc_occupancy(
    pool: &PgPool,
    operation_id: Uuid,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
    authenticated_domain: &str,
    new_connection_uuid: Uuid,
    lease: Duration,
) -> Result<ClusterMucTransitionOutcome> {
    let authenticated_domain = crate::jid::prepare_domainpart(authenticated_domain)?;
    let actor = crate::jid::CanonicalJid::parse(&target.full_jid)?;
    anyhow::ensure!(
        actor.domainpart() == authenticated_domain,
        "federated MUC rebind requires the authenticated actor domain"
    );
    transition_cluster_muc_occupancy_with_status(
        pool,
        operation_id,
        target,
        "rebind",
        owner_node_id,
        Some(new_connection_uuid),
        target.connection_epoch.checked_add(1),
        None,
        lease,
        None,
        Some(&authenticated_domain),
    )
    .await
}

pub async fn disconnect_cluster_muc_occupancy(
    pool: &PgPool,
    operation_id: Uuid,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
) -> Result<ClusterMucTransitionOutcome> {
    transition_cluster_muc_occupancy_with_status(
        pool,
        operation_id,
        target,
        "leave",
        owner_node_id,
        None,
        None,
        None,
        Duration::from_secs(90),
        Some(333),
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn transition_cluster_muc_occupancy_with_status(
    pool: &PgPool,
    operation_id: Uuid,
    target: &ClusterMucOccupancyTarget,
    transition: &str,
    owner_node_id: &str,
    new_connection_uuid: Option<Uuid>,
    new_connection_epoch: Option<i64>,
    sm_session_id: Option<Uuid>,
    lease: Duration,
    removal_status: Option<u16>,
    rebind_authenticated_domain: Option<&str>,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        matches!(transition, "suspend" | "resume" | "rebind" | "leave"),
        "unsupported MUC self transition"
    );
    anyhow::ensure!(
        (transition == "rebind") == rebind_authenticated_domain.is_some(),
        "federated MUC rebind requires an authenticated domain"
    );
    anyhow::ensure!(
        removal_status.is_none() || (transition == "leave" && removal_status == Some(333)),
        "MUC transport failure status is only valid on a leave"
    );
    validate_node_id(owner_node_id)?;
    let lease_seconds = validate_lease(lease)?;
    if transition == "resume" {
        anyhow::ensure!(
            new_connection_uuid.is_some_and(|value| !value.is_nil())
                && new_connection_epoch.is_some_and(|value| value > target.connection_epoch)
                && sm_session_id.is_some(),
            "MUC resume requires a newer exact connection and SM session"
        );
    }
    if transition == "rebind" {
        anyhow::ensure!(
            new_connection_uuid
                .is_some_and(|value| !value.is_nil() && value != target.connection_uuid)
                && new_connection_epoch.is_some_and(|value| value > target.connection_epoch)
                && sm_session_id.is_none(),
            "federated MUC rebind requires a newer exact S2S connection"
        );
    }
    let transition_digest = SelfTransitionDigest {
        room_id: target.room_id,
        room_epoch: target.room_epoch,
        occupant_incarnation: target.occupant_incarnation,
        occupancy_epoch: target.occupancy_epoch,
        full_jid: &target.full_jid,
        nick: &target.nick,
        connection_uuid: target.connection_uuid,
        connection_epoch: target.connection_epoch,
        transition,
        new_connection_uuid,
        new_connection_epoch,
        sm_session_id,
    };
    let digest = match removal_status {
        Some(status) => request_digest(&json!({
            "transition": transition_digest,
            "removal_status": status,
        }))?,
        None => request_digest(&transition_digest)?,
    };
    // Existing readers already understand the resume presence event. Rebind
    // keeps that wire kind during rolling upgrades while its digest and
    // details retain the distinct transaction semantics.
    let operation_kind = if transition == "rebind" {
        "resume"
    } else {
        transition
    };
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, operation_kind, &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, target.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    if room.room_epoch != target.room_epoch {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let current = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND (owner_node_id=$9 OR $10='resume') AND state IN ('active','suspended')
            AND ($10<>'rebind' OR lease_until>clock_timestamp())
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
    .bind(owner_node_id)
    .bind(transition)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current) = current else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    let authorization_source = if current.get::<Option<Uuid>, _>("local_user_id").is_some() {
        "local_database"
    } else {
        "federated_verified"
    };
    let current = occupancy_from_row(&current);
    if let Some(authenticated_domain) = rebind_authenticated_domain {
        if current.identity_kind != "federated"
            || current.authenticated_domain.as_deref() != Some(authenticated_domain)
        {
            tx.rollback().await?;
            return Ok(ClusterMucTransitionOutcome::Unauthorized);
        }
        let affiliation: Option<String> = sqlx::query_scalar(
            "SELECT affiliation FROM muc_external_affiliations
              WHERE room_id=$1 AND jid=$2 FOR SHARE",
        )
        .bind(target.room_id)
        .bind(&current.bare_jid)
        .fetch_optional(&mut *tx)
        .await?;
        if affiliation.as_deref() == Some("outcast") || (room.members_only && affiliation.is_none())
        {
            tx.rollback().await?;
            return Ok(ClusterMucTransitionOutcome::Unauthorized);
        }
    }
    let expected_state = if transition == "resume" {
        "suspended"
    } else {
        "active"
    };
    if current.state != expected_state {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, target.room_id, false).await?;
    let new_state = match transition {
        "suspend" => "suspended",
        "resume" => "active",
        "rebind" => "active",
        "leave" => "left",
        _ => unreachable!(),
    };
    sqlx::query(
        "UPDATE cluster_muc_occupancies SET
             state=$10,
             owner_node_id=CASE WHEN $15 THEN $9 ELSE owner_node_id END,
             connection_uuid=COALESCE($11,connection_uuid),
             connection_epoch=COALESCE($12,connection_epoch),
             sm_session_id=$13,
             lease_until=CASE WHEN $10='left' THEN clock_timestamp()
                              ELSE clock_timestamp()+make_interval(secs=>$14) END,
             ended_at=CASE WHEN $10='left' THEN clock_timestamp() ELSE NULL END,
             updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND (owner_node_id=$9 OR $10='resume')",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(new_state)
    .bind(new_connection_uuid)
    .bind(new_connection_epoch)
    .bind(sm_session_id)
    .bind(lease_seconds as f64)
    .bind(transition == "resume")
    .execute(&mut *tx)
    .await?;
    if matches!(transition, "resume" | "rebind") {
        sqlx::query("SELECT northstar_transfer_cluster_muc_outbox($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(target.room_id)
            .bind(target.room_epoch)
            .bind(target.occupant_incarnation)
            .bind(target.connection_uuid)
            .bind(target.connection_epoch)
            .bind(new_connection_uuid.expect("connection UUID validated"))
            .bind(new_connection_epoch.expect("connection epoch validated"))
            .bind(owner_node_id)
            .execute(&mut *tx)
            .await?;
    }
    let audience = active_audience(&mut tx, target.room_id).await?;
    let authorization = json!({
        "source": "exact_occupancy",
        "owner_node_id": owner_node_id,
        "occupant_incarnation": target.occupant_incarnation,
        "occupancy_epoch": target.occupancy_epoch,
        "connection_uuid": target.connection_uuid,
        "connection_epoch": target.connection_epoch,
    });
    let mut details = json!({
        "state": new_state,
        "new_connection_uuid": new_connection_uuid,
        "new_connection_epoch": new_connection_epoch,
        "sm_session_id": sm_session_id,
        "connection_rebind": transition == "rebind",
    });
    if let Some(status) = removal_status {
        details["status"] = json!(status);
    }
    let actor_bare_jid = muc_address_bare_jid(&target.full_jid)?;
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: target.room_id,
            room_epoch: target.room_epoch,
            kind: operation_kind,
            digest: &digest,
            actor_bare_jid: Some(&actor_bare_jid),
            actor_full_jid: Some(&target.full_jid),
            actor_affiliation: Some(&current.affiliation),
            authorization_source,
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

/// Rename only the exact current incarnation. A delayed mutation that names a
/// reused nickname cannot match the replacement occupancy UUID/epoch tuple.
pub async fn rename_cluster_muc_occupancy(
    pool: &PgPool,
    operation_id: Uuid,
    target: &ClusterMucOccupancyTarget,
    owner_node_id: &str,
    new_nick: &str,
) -> Result<ClusterMucTransitionOutcome> {
    validate_node_id(owner_node_id)?;
    validate_nick(new_nick)?;
    let digest = request_digest(&json!({
        "target": target,
        "owner_node_id": owner_node_id,
        "new_nick": new_nick,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "rename", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, target.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    expire_due_in_room(&mut tx, target.room_id).await?;
    let current = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8 AND owner_node_id=$9
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
    .bind(owner_node_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current) = current else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    let local_user_id: Option<Uuid> = current.get("local_user_id");
    let current = occupancy_from_row(&current);
    let conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_occupancies
          WHERE room_id=$1 AND nick=$2 AND occupant_incarnation<>$3
            AND state IN ('active','suspended'))",
    )
    .bind(target.room_id)
    .bind(new_nick)
    .bind(target.occupant_incarnation)
    .fetch_one(&mut *tx)
    .await?;
    if conflict {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Conflict);
    }
    let reserved: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM muc_affiliations a
              WHERE a.room_id=$1 AND a.reserved_nick=$2
                AND ($3::uuid IS NULL OR a.user_id<>$3)
             UNION ALL
             SELECT 1 FROM muc_external_affiliations e
              WHERE e.room_id=$1 AND e.reserved_nick=$2 AND e.jid<>$4)",
    )
    .bind(target.room_id)
    .bind(new_nick)
    .bind(local_user_id)
    .bind(&current.bare_jid)
    .fetch_one(&mut *tx)
    .await?;
    if reserved {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Conflict);
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, target.room_id, false).await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies SET nick=$10,updated_at=clock_timestamp()
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8 AND owner_node_id=$9",
    )
    .bind(target.room_id)
    .bind(target.room_epoch)
    .bind(target.occupant_incarnation)
    .bind(target.occupancy_epoch)
    .bind(&target.full_jid)
    .bind(&target.nick)
    .bind(target.connection_uuid)
    .bind(target.connection_epoch)
    .bind(owner_node_id)
    .bind(new_nick)
    .execute(&mut *tx)
    .await?;
    let audience = active_audience(&mut tx, target.room_id).await?;
    let authorization = json!({"source":"exact_occupancy","owner_node_id":owner_node_id});
    let details = json!({"old_nick":target.nick,"new_nick":new_nick});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: target.room_id,
            room_epoch: target.room_epoch,
            kind: "rename",
            digest: &digest,
            actor_bare_jid: Some(&current.bare_jid),
            actor_full_jid: Some(&current.full_jid),
            actor_affiliation: Some(&current.affiliation),
            authorization_source: if local_user_id.is_some() {
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
