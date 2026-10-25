//! Cluster MUC room configuration, subject and lifecycle (destroy, tombstone, account revocation).

use super::*;

/// Apply an authorization-relevant room configuration exactly once. The
/// durable owner affiliation, locked-room owner and expected room/config
/// epochs are all checked while holding the room row lock. No password hash
/// or room secret is copied into the immutable operation details.
#[allow(clippy::too_many_arguments)]
pub async fn update_cluster_muc_config(
    pool: &PgPool,
    operation_id: Uuid,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    expected_config_version: i64,
    actor_target: &ClusterMucOccupancyTarget,
    principal: &ClusterMucPrincipal,
    actor_full_jid: &str,
    config: super::super::muc::MucConfigUpdate<'_>,
) -> Result<ClusterMucConfigurationOutcome> {
    principal.validate()?;
    let actor_full_jid = northstar_xmpp_types::jid::canonicalize(actor_full_jid)?;
    anyhow::ensure!(
        muc_principal_owns_address(&actor_full_jid, principal)?,
        "MUC configuration actor does not belong to the authorized principal"
    );
    let digest = request_digest(&json!({
        "room_id":room_id,
        "room_epoch":expected_room_epoch,
        "config_version":expected_config_version,
        "actor_target":actor_target,
        "principal":principal,
        "actor_full_jid":actor_full_jid,
        "title":config.title,
        "description":config.description,
        "persistent":config.persistent,
        "members_only":config.members_only,
        "public":config.public,
        "moderated":config.moderated,
        "non_anonymous":config.non_anonymous,
        "max_occupants":config.max_occupants,
        "password_protected":config.password_hash.is_some(),
        "password_verifier_digest":config.password_hash.map(payload_digest),
        "allow_subject_change":config.allow_subject_change,
        "allow_invites":config.allow_invites,
        "allow_private_messages":config.allow_private_messages,
        "logging_enabled":config.logging_enabled,
        "allow_registration":config.allow_registration,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "config", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucConfigurationOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Missing);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch || room.config_version != expected_config_version {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Stale);
    }
    if actor_target.room_id != room_id || actor_target.room_epoch != room.room_epoch {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Stale);
    }
    let actor_row = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
            AND connection_uuid=$7 AND connection_epoch=$8
            AND state='active' AND lease_until>clock_timestamp() FOR UPDATE",
    )
    .bind(actor_target.room_id)
    .bind(actor_target.room_epoch)
    .bind(actor_target.occupant_incarnation)
    .bind(actor_target.occupancy_epoch)
    .bind(&actor_target.full_jid)
    .bind(&actor_target.nick)
    .bind(actor_target.connection_uuid)
    .bind(actor_target.connection_epoch)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(actor_row) = actor_row else {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Unauthorized);
    };
    let actor_snapshot = occupancy_from_row(&actor_row);
    if !exact_target_matches_row(actor_target, &actor_snapshot)
        || actor_snapshot.full_jid != actor_full_jid
        || !principal_matches_occupancy(principal, &actor_snapshot)
    {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Unauthorized);
    }
    if affiliation_in_tx(&mut tx, room_id, principal)
        .await?
        .as_deref()
        != Some("owner")
    {
        tx.rollback().await?;
        return Ok(ClusterMucConfigurationOutcome::Unauthorized);
    }
    let configuration = sqlx::query(
        "SELECT configuration_state,configuration_owner_jid,
                configuration_expires_at<=clock_timestamp() AS expired
           FROM muc_rooms WHERE id=$1",
    )
    .bind(room_id)
    .fetch_one(&mut *tx)
    .await?;
    if configuration.get::<String, _>("configuration_state") == "locked" {
        if configuration.get::<bool, _>("expired") {
            tx.rollback().await?;
            return Ok(ClusterMucConfigurationOutcome::Expired);
        }
        if configuration
            .get::<Option<String>, _>("configuration_owner_jid")
            .as_deref()
            != Some(actor_full_jid.as_str())
        {
            tx.rollback().await?;
            return Ok(ClusterMucConfigurationOutcome::LockedByAnother);
        }
    }
    let audience = active_audience(&mut tx, room_id).await?;
    let updated_version: i64 = sqlx::query_scalar(
        "UPDATE muc_rooms SET
             title=$2,persistent=$3,members_only=$4,public=$5,moderated=$6,
             non_anonymous=$7,max_occupants=$8,password_hash=$9,description=$10,
             allow_subject_change=$11,allow_invites=$12,allow_private_messages=$13,
             logging_enabled=$14,allow_registration=$15,configuration_state='active',
             configuration_owner_jid=NULL,configuration_expires_at=NULL
          WHERE id=$1 AND room_epoch=$16 AND config_version=$17 AND destroyed_at IS NULL
          RETURNING config_version",
    )
    .bind(room_id)
    .bind(config.title)
    .bind(config.persistent)
    .bind(config.members_only)
    .bind(config.public)
    .bind(config.moderated)
    .bind(config.non_anonymous)
    .bind(config.max_occupants.clamp(2, 1000))
    .bind(config.password_hash)
    .bind(config.description)
    .bind(config.allow_subject_change)
    .bind(config.allow_invites)
    .bind(config.allow_private_messages)
    .bind(config.logging_enabled)
    .bind(config.allow_registration)
    .bind(expected_room_epoch)
    .bind(expected_config_version)
    .fetch_one(&mut *tx)
    .await?;
    anyhow::ensure!(
        updated_version == expected_config_version + 1,
        "MUC config version did not advance exactly once"
    );

    // Refresh role/affiliation snapshots from durable rows. Guests made
    // invalid by members-only are fenced immediately; the exact audience
    // snapshot still lets the committed operation notify their old routes.
    sqlx::query(
        "UPDATE cluster_muc_occupancies o SET
             config_version=$2,
             affiliation=COALESCE(a.affiliation,'none'),
             role=CASE WHEN COALESCE(a.affiliation,'none') IN ('owner','admin') THEN 'moderator'
                       WHEN $3 AND COALESCE(a.affiliation,'none')='none' THEN 'visitor'
                       ELSE 'participant' END,
             state=CASE WHEN $4 AND a.affiliation IS NULL THEN 'revoked' ELSE o.state END,
             lease_until=CASE WHEN $4 AND a.affiliation IS NULL THEN clock_timestamp()
                              ELSE o.lease_until END,
             ended_at=CASE WHEN $4 AND a.affiliation IS NULL THEN clock_timestamp()
                           ELSE o.ended_at END,
             updated_at=clock_timestamp()
          FROM (SELECT u.occupant_incarnation,m.affiliation
                  FROM cluster_muc_occupancies u
                  LEFT JOIN muc_affiliations m
                    ON m.room_id=u.room_id AND m.user_id=u.local_user_id
                 WHERE u.room_id=$1 AND u.identity_kind='local'
                   AND u.state IN ('active','suspended')) a
         WHERE o.room_id=$1 AND o.occupant_incarnation=a.occupant_incarnation",
    )
    .bind(room_id)
    .bind(updated_version)
    .bind(config.moderated)
    .bind(config.members_only)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies o SET
             config_version=$2,
             affiliation=COALESCE(a.affiliation,'none'),
             role=CASE WHEN COALESCE(a.affiliation,'none') IN ('owner','admin') THEN 'moderator'
                       WHEN $3 AND COALESCE(a.affiliation,'none')='none' THEN 'visitor'
                       ELSE 'participant' END,
             state=CASE WHEN $4 AND a.affiliation IS NULL THEN 'revoked' ELSE o.state END,
             lease_until=CASE WHEN $4 AND a.affiliation IS NULL THEN clock_timestamp()
                              ELSE o.lease_until END,
             ended_at=CASE WHEN $4 AND a.affiliation IS NULL THEN clock_timestamp()
                           ELSE o.ended_at END,
             updated_at=clock_timestamp()
          FROM (SELECT u.occupant_incarnation,m.affiliation
                  FROM cluster_muc_occupancies u
                  LEFT JOIN muc_external_affiliations m
                    ON m.room_id=u.room_id AND m.jid=u.bare_jid
                 WHERE u.room_id=$1 AND u.identity_kind='federated'
                   AND u.state IN ('active','suspended')) a
         WHERE o.room_id=$1 AND o.occupant_incarnation=a.occupant_incarnation",
    )
    .bind(room_id)
    .bind(updated_version)
    .bind(config.moderated)
    .bind(config.members_only)
    .execute(&mut *tx)
    .await?;
    let mut affected = Vec::with_capacity(audience.len());
    for identity in &audience {
        let row = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3
                AND full_jid=$4 AND connection_uuid=$5 AND connection_epoch=$6",
        )
        .bind(room_id)
        .bind(identity.occupant_incarnation)
        .bind(identity.occupancy_epoch)
        .bind(&identity.full_jid)
        .bind(identity.connection_uuid)
        .bind(identity.connection_epoch)
        .fetch_one(&mut *tx)
        .await?;
        let snapshot = occupancy_from_row(&row);
        let target = ClusterMucOccupancyTarget::from(&snapshot);
        affected
            .push(json!({"target":target,"snapshot":ClusterMucPolicySnapshot::from(&snapshot)}));
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, room_id, false).await?;
    let authorization = json!({
        "principal":principal,
        "actor_target":actor_target,
        "durable_affiliation":"owner",
        "expected_room_epoch":expected_room_epoch,
        "expected_config_version":expected_config_version,
    });
    let details = json!({
        "members_only":config.members_only,"moderated":config.moderated,
        "non_anonymous":config.non_anonymous,"max_occupants":config.max_occupants,
        "persistent":config.persistent,"public":config.public,
        "affected":affected,
    });
    anyhow::ensure!(
        serde_json::to_vec(&details)?.len() <= MAX_PAYLOAD_BYTES,
        "MUC configuration audience snapshot is oversized"
    );
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "config",
            digest: &digest,
            actor_bare_jid: Some(principal.bare_jid()),
            actor_full_jid: Some(&actor_full_jid),
            actor_affiliation: Some("owner"),
            authorization_source: if matches!(principal, ClusterMucPrincipal::Local { .. }) {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: None,
            config_version_before: room.config_version,
            config_version_after: updated_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ClusterMucConfigurationOutcome::Applied)
}

/// Commit a room subject under the same PostgreSQL room/occupancy fence as
/// other clustered control operations. Subject state, optional MAM row,
/// immutable audience and notification outbox are one transaction.
pub async fn set_cluster_muc_subject(
    pool: &PgPool,
    operation_id: Uuid,
    expected_room_epoch: Uuid,
    expected_config_version: i64,
    actor: &ClusterMucOccupancyTarget,
    mutation: super::super::muc::MucSubjectMutation<'_>,
    archive: bool,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        mutation.room_id == actor.room_id,
        "cross-room subject mutation rejected"
    );
    anyhow::ensure!(
        mutation.subject.len() <= MAX_PAYLOAD_BYTES && mutation.stanza.len() <= MAX_PAYLOAD_BYTES,
        "MUC subject is oversized"
    );
    let actor_scope = northstar_xmpp_types::jid::canonicalize_bare(mutation.actor_scope)?;
    let sender_jid = northstar_xmpp_types::jid::canonicalize(mutation.sender_jid)?;
    let digest = request_digest(&json!({
        "actor":actor,"room_epoch":expected_room_epoch,
        "config_version":expected_config_version,"subject":mutation.subject,
        "stanza":mutation.stanza,"archive":archive,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "subject", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, mutation.room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch || room.config_version != expected_config_version {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    expire_due_in_room(&mut tx, mutation.room_id).await?;
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
    if !exact_target_matches_row(actor, &actor_current)
        || actor_current.bare_jid != actor_scope
        || actor_current.full_jid != sender_jid
        || !(actor_current.role == "moderator"
            || (room.allow_subject_change && actor_current.role == "participant"))
    {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let audience = active_audience(&mut tx, mutation.room_id).await?;
    sqlx::query(
        "UPDATE muc_rooms SET subject=$2,subject_set_by=$3,subject_stanza_id=$4,
             subject_changed_at=clock_timestamp() WHERE id=$1 AND room_epoch=$5
             AND config_version=$6 AND destroyed_at IS NULL",
    )
    .bind(mutation.room_id)
    .bind(mutation.subject)
    .bind(&actor_scope)
    .bind(mutation.stanza_id)
    .bind(expected_room_epoch)
    .bind(expected_config_version)
    .execute(&mut *tx)
    .await?;
    if archive {
        sqlx::query(
            "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted,message_kind,actor_scope)
             VALUES($1,$2,$3,$4,$5,$6,'subject',$7)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(mutation.stanza_id).bind(mutation.room_id).bind(&sender_jid)
        .bind(mutation.nick).bind(mutation.stanza).bind(mutation.encrypted).bind(&actor_scope)
        .execute(&mut *tx).await?;
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, mutation.room_id, false).await?;
    let authorization = json!({
        "actor":actor,"role":actor_current.role,"room_epoch":room.room_epoch,
        "config_version":room.config_version,"allow_subject_change":room.allow_subject_change,
    });
    let details = json!({"subject":mutation.subject,"stanza":mutation.stanza,"archived":archive});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id: mutation.room_id,
            room_epoch: room.room_epoch,
            kind: "subject",
            digest: &digest,
            actor_bare_jid: Some(&actor_current.bare_jid),
            actor_full_jid: Some(&actor_current.full_jid),
            actor_affiliation: Some(&actor_current.affiliation),
            authorization_source: if actor_row.get::<Option<Uuid>, _>("local_user_id").is_some() {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: Some(actor),
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

/// Permanently fence this room incarnation and revoke every exact occupancy in
/// the same transaction. Redis caches can never clear the PostgreSQL fence;
/// a later same-localpart room is an unrelated UUID/room_epoch incarnation.
#[allow(clippy::too_many_arguments)]
pub async fn destroy_cluster_muc_room(
    pool: &PgPool,
    operation_id: Uuid,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    actor: Option<&ClusterMucOccupancyTarget>,
    authorization_source: &str,
    actor_jid: Option<&str>,
    alternate_jid: Option<&str>,
    reason: Option<&str>,
) -> Result<ClusterMucTransitionOutcome> {
    anyhow::ensure!(
        matches!(
            authorization_source,
            "system" | "admin_control" | "local_database" | "federated_verified"
        ),
        "invalid MUC destroy authorization source"
    );
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "destroy reason is oversized"
    );
    let digest = request_digest(&json!({
        "room_id":room_id,"room_epoch":expected_room_epoch,"actor":actor,
        "authorization_source":authorization_source,"actor_jid":actor_jid,
        "alternate_jid":alternate_jid,"reason":reason,
    }))?;
    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "destroy", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(ClusterMucTransitionOutcome::Replay);
    }
    let Some(room) = lock_room(&mut tx, room_id).await? else {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Stale);
    }
    let mut actor_snapshot = json!({"source":authorization_source});
    let mut actor_affiliation = None;
    let mut canonical_actor_bare = None;
    let mut canonical_actor_full = None;
    if let Some(actor) = actor {
        let row = sqlx::query(
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
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(ClusterMucTransitionOutcome::Unauthorized);
        };
        let current = occupancy_from_row(&row);
        let claimed_actor = actor_jid
            .map(northstar_xmpp_types::jid::canonicalize)
            .transpose()?;
        if claimed_actor.as_deref() != Some(current.full_jid.as_str())
            || (current.identity_kind == "local" && authorization_source != "local_database")
            || (current.identity_kind == "federated"
                && authorization_source != "federated_verified")
        {
            tx.rollback().await?;
            return Ok(ClusterMucTransitionOutcome::Unauthorized);
        }
        let durable_affiliation: Option<String> = if let Some(user_id) =
            row.get::<Option<Uuid>, _>("local_user_id")
        {
            sqlx::query_scalar(
                "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 FOR SHARE",
            )
            .bind(room_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT affiliation FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 FOR SHARE",
            )
            .bind(room_id)
            .bind(&current.bare_jid)
            .fetch_optional(&mut *tx)
            .await?
        };
        if !matches!(durable_affiliation.as_deref(), Some("owner")) {
            tx.rollback().await?;
            return Ok(ClusterMucTransitionOutcome::Unauthorized);
        }
        actor_affiliation = durable_affiliation;
        canonical_actor_bare = Some(current.bare_jid);
        canonical_actor_full = Some(current.full_jid);
        actor_snapshot = json!({
            "source":authorization_source,
            "actor_incarnation":actor.occupant_incarnation,
            "actor_occupancy_epoch":actor.occupancy_epoch,
            "durable_affiliation":"owner",
        });
    } else if !matches!(authorization_source, "system" | "admin_control") {
        tx.rollback().await?;
        return Ok(ClusterMucTransitionOutcome::Unauthorized);
    }
    let audience = active_audience(&mut tx, room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, room_id, false).await?;
    let event_id = operation_id;
    let details = json!({"alternate_jid":alternate_jid,"reason":reason});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "destroy",
            digest: &digest,
            actor_bare_jid: canonical_actor_bare.as_deref().or(actor_jid),
            actor_full_jid: canonical_actor_full.as_deref(),
            actor_affiliation: actor_affiliation.as_deref(),
            authorization_source,
            authorization_snapshot: &actor_snapshot,
            target: actor,
            config_version_before: room.config_version,
            config_version_after: room.config_version + 1,
            event_sequence,
            event_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',ended_at=clock_timestamp(),lease_until=clock_timestamp(),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND state IN ('active','suspended')",
    )
    .bind(room_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE muc_rooms SET destroyed_at=clock_timestamp(),destroyed_operation_id=$2,
                destroyed_by=$3,destroy_reason=$4,destroy_alternate_jid=$5
          WHERE id=$1 AND room_epoch=$6 AND destroyed_at IS NULL",
    )
    .bind(room_id)
    .bind(operation_id)
    .bind(actor_jid.or(canonical_actor_full.as_deref()))
    .bind(reason)
    .bind(alternate_jid)
    .bind(expected_room_epoch)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ClusterMucTransitionOutcome::Applied)
}

/// Control-plane variant used inside the API operation journal transaction.
/// Keeping the intent check, tombstone, immutable MUC operation and audit
/// consequence in one caller-owned transaction prevents a crash gap.
pub async fn admin_destroy_cluster_muc_room_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    room_id: Uuid,
    actor_id: Uuid,
    actor_label: &str,
    alternate_jid: Option<&str>,
    reason: Option<&str>,
) -> Result<Option<Vec<ClusterMucAudienceSnapshot>>> {
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "destroy reason is oversized"
    );
    let digest = request_digest(&json!({
        "room_id":room_id,"actor_id":actor_id,"actor_label":actor_label,
        "alternate_jid":alternate_jid,"reason":reason,
    }))?;
    if existing_operation(tx, operation_id, "destroy", &digest)
        .await?
        .is_some()
    {
        return Ok(None);
    }
    let Some(room) = lock_room(tx, room_id).await? else {
        return Ok(None);
    };
    if room.destroyed {
        return Ok(None);
    }
    let audience = active_audience(tx, room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(tx, room_id, false).await?;
    let authorization = json!({
        "source":"admin_control",
        "actor_id":actor_id,
        "actor_label":actor_label,
        "room_epoch":room.room_epoch,
        "config_version":room.config_version,
    });
    let details = json!({"alternate_jid":alternate_jid,"reason":reason});
    insert_operation_and_outbox(
        tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "destroy",
            digest: &digest,
            actor_bare_jid: Some(actor_label),
            actor_full_jid: None,
            actor_affiliation: None,
            authorization_source: "admin_control",
            authorization_snapshot: &authorization,
            target: None,
            config_version_before: room.config_version,
            config_version_after: room.config_version + 1,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',ended_at=clock_timestamp(),lease_until=clock_timestamp(),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND state IN ('active','suspended')",
    )
    .bind(room_id)
    .execute(&mut **tx)
    .await?;
    let updated = sqlx::query(
        "UPDATE muc_rooms SET destroyed_at=clock_timestamp(),destroyed_operation_id=$2,
                destroyed_by=$3,destroy_reason=$4,destroy_alternate_jid=$5
          WHERE id=$1 AND room_epoch=$6 AND destroyed_at IS NULL",
    )
    .bind(room_id)
    .bind(operation_id)
    .bind(actor_label)
    .bind(reason)
    .bind(alternate_jid)
    .bind(room.room_epoch)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    anyhow::ensure!(updated, "MUC room tombstone fence changed concurrently");
    Ok(Some(audience))
}

/// Internal lifecycle tombstone used for temporary-room cleanup and locked
/// room expiry.  The caller must first lock and verify its exact lifecycle
/// predicate in this same transaction.
pub async fn system_tombstone_cluster_muc_room_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    room_id: Uuid,
    operation_kind: &str,
    authorization_snapshot: &Value,
    reason: &str,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(operation_kind, "destroy" | "locked_expiry"),
        "invalid system MUC tombstone operation kind"
    );
    anyhow::ensure!(
        authorization_snapshot.is_object(),
        "system MUC authorization snapshot must be an object"
    );
    anyhow::ensure!(reason.len() <= 4096, "destroy reason is oversized");
    let digest = request_digest(&json!({
        "room_id":room_id,"kind":operation_kind,
        "authorization":authorization_snapshot,"reason":reason,
    }))?;
    if existing_operation(tx, operation_id, operation_kind, &digest)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let Some(room) = lock_room(tx, room_id).await? else {
        return Ok(false);
    };
    if room.destroyed {
        return Ok(false);
    }
    let audience = active_audience(tx, room_id).await?;
    let (_unused, event_sequence) = allocate_room_epochs(tx, room_id, false).await?;
    let details = json!({"reason":reason});
    insert_operation_and_outbox(
        tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: operation_kind,
            digest: &digest,
            actor_bare_jid: None,
            actor_full_jid: None,
            actor_affiliation: None,
            authorization_source: "system",
            authorization_snapshot,
            target: None,
            config_version_before: room.config_version,
            config_version_after: room.config_version + 1,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',ended_at=clock_timestamp(),lease_until=clock_timestamp(),
                updated_at=clock_timestamp()
          WHERE room_id=$1 AND state IN ('active','suspended')",
    )
    .bind(room_id)
    .execute(&mut **tx)
    .await?;
    let changed = sqlx::query(
        "UPDATE muc_rooms SET destroyed_at=clock_timestamp(),destroyed_operation_id=$2,
                destroyed_by='system',destroy_reason=$3
          WHERE id=$1 AND room_epoch=$4 AND destroyed_at IS NULL",
    )
    .bind(room_id)
    .bind(operation_id)
    .bind(reason)
    .bind(room.room_epoch)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    anyhow::ensure!(changed, "MUC tombstone fence changed concurrently");
    Ok(true)
}

/// Fence every live room incarnation owned by an account before its user row
/// is erased. The deletion transaction cannot commit while a stale node
/// remains authorized to speak as that account.
pub async fn revoke_cluster_muc_account_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    account_bare_jid: &str,
) -> Result<u64> {
    let account_bare_jid = northstar_xmpp_types::jid::canonicalize_bare(account_bare_jid)?;
    let room_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT room_id FROM cluster_muc_occupancies
          WHERE local_user_id=$1 AND state IN ('active','suspended') ORDER BY room_id",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut revoked = 0_u64;
    for room_id in room_ids {
        let Some(room) = lock_room(tx, room_id).await? else {
            continue;
        };
        if room.destroyed {
            continue;
        }
        let rows = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND local_user_id=$2
                AND state IN ('active','suspended') FOR UPDATE",
        )
        .bind(room_id)
        .bind(user_id)
        .fetch_all(&mut **tx)
        .await?;
        for row in rows {
            let occupancy = occupancy_from_row(&row);
            let target = ClusterMucOccupancyTarget::from(&occupancy);
            let audience = active_audience(tx, room_id).await?;
            let operation_id = Uuid::new_v4();
            let digest = request_digest(&json!({
                "user_id":user_id,"account":account_bare_jid,
                "target":&target,"transition":"account_delete",
            }))?;
            let (_unused, event_sequence) = allocate_room_epochs(tx, room_id, false).await?;
            let changed = sqlx::query(
                "UPDATE cluster_muc_occupancies SET state='revoked',role='none',
                     lease_until=clock_timestamp(),ended_at=clock_timestamp(),updated_at=clock_timestamp()
                  WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3
                    AND connection_uuid=$4 AND connection_epoch=$5
                    AND state IN ('active','suspended')",
            )
            .bind(room_id)
            .bind(occupancy.occupant_incarnation)
            .bind(occupancy.occupancy_epoch)
            .bind(occupancy.connection_uuid)
            .bind(occupancy.connection_epoch)
            .execute(&mut **tx)
            .await?
            .rows_affected();
            anyhow::ensure!(
                changed == 1,
                "account deletion lost an exact MUC occupancy fence"
            );
            let authorization = json!({
                "source":"account_delete_transaction","user_id":user_id,
                "account":account_bare_jid,
            });
            let details = json!({"state":"revoked","status":332});
            insert_operation_and_outbox(
                tx,
                OperationRecord {
                    operation_id,
                    room_id,
                    room_epoch: room.room_epoch,
                    kind: "account_delete",
                    digest: &digest,
                    actor_bare_jid: Some(&account_bare_jid),
                    actor_full_jid: None,
                    actor_affiliation: Some(&occupancy.affiliation),
                    authorization_source: "system",
                    authorization_snapshot: &authorization,
                    target: Some(&target),
                    config_version_before: room.config_version,
                    config_version_after: room.config_version,
                    event_sequence,
                    event_id: operation_id,
                    audience: &audience,
                    details: &details,
                },
            )
            .await?;
            revoked += 1;
        }
    }
    Ok(revoked)
}
