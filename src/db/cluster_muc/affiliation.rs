//! Cluster MUC affiliation and registration authority.

use super::*;

async fn subject_affiliation_for_update(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    subject: &ClusterMucAffiliationSubject,
) -> Result<Option<String>> {
    match subject {
        ClusterMucAffiliationSubject::Local { user_id, .. } => sqlx::query_scalar(
            "SELECT affiliation FROM muc_affiliations
              WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
        )
        .bind(room_id)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(Into::into),
        ClusterMucAffiliationSubject::Federated { bare_jid } => sqlx::query_scalar(
            "SELECT affiliation FROM muc_external_affiliations
              WHERE room_id=$1 AND jid=$2 FOR UPDATE",
        )
        .bind(room_id)
        .bind(bare_jid)
        .fetch_optional(&mut **tx)
        .await
        .map_err(Into::into),
    }
}

async fn subject_occupancies_for_update(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    subject: &ClusterMucAffiliationSubject,
) -> Result<Vec<ClusterMucOccupancy>> {
    let rows = match subject {
        ClusterMucAffiliationSubject::Local { user_id, .. } => {
            sqlx::query(
                "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND local_user_id=$2
                AND state IN ('active','suspended')
                AND lease_until>clock_timestamp() FOR UPDATE",
            )
            .bind(room_id)
            .bind(user_id)
            .fetch_all(&mut **tx)
            .await?
        }
        ClusterMucAffiliationSubject::Federated { bare_jid } => {
            sqlx::query(
                "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND identity_kind='federated' AND bare_jid=$2
                AND state IN ('active','suspended')
                AND lease_until>clock_timestamp() FOR UPDATE",
            )
            .bind(room_id)
            .bind(bare_jid)
            .fetch_all(&mut **tx)
            .await?
        }
    };
    Ok(rows.iter().map(occupancy_from_row).collect())
}

async fn update_subject_occupancies(
    tx: &mut Transaction<'_, Postgres>,
    room: &RoomAuthority,
    room_id: Uuid,
    subject: &ClusterMucAffiliationSubject,
    affiliation: &str,
) -> Result<()> {
    match subject {
        ClusterMucAffiliationSubject::Local { user_id, .. } => {
            sqlx::query(
                "UPDATE cluster_muc_occupancies SET affiliation=$3,
                 role=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'none'
                           WHEN $3 IN ('owner','admin') THEN 'moderator'
                           WHEN $4 AND $3='none' THEN 'visitor' ELSE 'participant' END,
                 state=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                            THEN 'revoked' ELSE state END,
                 lease_until=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                                  THEN clock_timestamp() ELSE lease_until END,
                 ended_at=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                               THEN clock_timestamp() ELSE ended_at END,
                 updated_at=clock_timestamp()
                 WHERE room_id=$1 AND local_user_id=$2
                   AND state IN ('active','suspended')
                   AND lease_until>clock_timestamp()",
            )
            .bind(room_id)
            .bind(user_id)
            .bind(affiliation)
            .bind(room.moderated)
            .bind(room.members_only)
            .execute(&mut **tx)
            .await?;
        }
        ClusterMucAffiliationSubject::Federated { bare_jid } => {
            sqlx::query(
                "UPDATE cluster_muc_occupancies SET affiliation=$3,
                 role=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'none'
                           WHEN $3 IN ('owner','admin') THEN 'moderator'
                           WHEN $4 AND $3='none' THEN 'visitor' ELSE 'participant' END,
                 state=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                            THEN 'revoked' ELSE state END,
                 lease_until=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                                  THEN clock_timestamp() ELSE lease_until END,
                 ended_at=CASE WHEN $3='outcast' OR ($5 AND $3='none')
                               THEN clock_timestamp() ELSE ended_at END,
                 updated_at=clock_timestamp()
                 WHERE room_id=$1 AND identity_kind='federated' AND bare_jid=$2
                   AND state IN ('active','suspended')
                   AND lease_until>clock_timestamp()",
            )
            .bind(room_id)
            .bind(bare_jid)
            .bind(affiliation)
            .bind(room.moderated)
            .bind(room.members_only)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn mutate_cluster_muc_affiliation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    expected_config_version: i64,
    actor: &ClusterMucPrincipal,
    actor_full_jid: &str,
    actor_target: Option<&ClusterMucOccupancyTarget>,
    subject: &ClusterMucAffiliationSubject,
    mutation: ClusterMucAffiliationMutation<'_>,
    reason: Option<&str>,
) -> Result<ClusterMucAffiliationMutationOutcome> {
    actor.validate()?;
    subject.validate()?;
    anyhow::ensure!(
        reason.is_none_or(|value| value.len() <= 4096),
        "invite reason is oversized"
    );
    let actor_full_jid = northstar_xmpp_types::jid::canonicalize(actor_full_jid)?;
    anyhow::ensure!(
        muc_principal_owns_address(&actor_full_jid, actor)?,
        "MUC affiliation actor does not own the authenticated full JID"
    );
    let (action, reserved_nick) = match mutation {
        ClusterMucAffiliationMutation::SelfRegister { reserved_nick } => {
            validate_nick(reserved_nick)?;
            ("self_register", Some(reserved_nick))
        }
        ClusterMucAffiliationMutation::SelfUnregister => ("self_unregister", None),
        ClusterMucAffiliationMutation::Invitation => ("invitation", None),
    };
    let digest = request_digest(&json!({
        "room_id":room_id,"room_epoch":expected_room_epoch,
        "config_version":expected_config_version,"action":action,
        "actor":actor,"actor_full_jid":actor_full_jid,"actor_target":actor_target,
        "subject":subject,"reserved_nick":reserved_nick,"reason":reason,
    }))?;
    if existing_operation(tx, operation_id, "affiliation", &digest)
        .await?
        .is_some()
    {
        let changed = sqlx::query_scalar::<_, bool>(
            "SELECT COALESCE((details->>'affiliation_changed')::BOOLEAN,FALSE)
               FROM cluster_muc_operations WHERE operation_id=$1",
        )
        .bind(operation_id)
        .fetch_one(&mut **tx)
        .await?;
        return Ok(ClusterMucAffiliationMutationOutcome::Replay {
            affiliation_changed: changed,
        });
    }
    let Some(room) = lock_room(tx, room_id).await? else {
        return Ok(ClusterMucAffiliationMutationOutcome::Stale);
    };
    if room.destroyed {
        return Ok(ClusterMucAffiliationMutationOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch || room.config_version != expected_config_version {
        return Ok(ClusterMucAffiliationMutationOutcome::Stale);
    }
    expire_due_in_room(tx, room_id).await?;

    let self_service = !matches!(mutation, ClusterMucAffiliationMutation::Invitation);
    let actor_affiliation;
    let actor_role;
    if self_service {
        if !room.allow_registration || actor_target.is_some() || !subject.matches_principal(actor) {
            return Ok(ClusterMucAffiliationMutationOutcome::NotAllowed);
        }
        actor_affiliation = affiliation_in_tx(tx, room_id, actor)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        actor_role = None;
    } else {
        actor_affiliation = affiliation_in_tx(tx, room_id, actor)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if let Some(actor_target) = actor_target {
            if actor_target.room_id != room_id || actor_target.room_epoch != room.room_epoch {
                return Ok(ClusterMucAffiliationMutationOutcome::Stale);
            }
            let row = sqlx::query(
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
            .fetch_optional(&mut **tx)
            .await?;
            let Some(row) = row else {
                return Ok(ClusterMucAffiliationMutationOutcome::Unauthorized);
            };
            let snapshot = occupancy_from_row(&row);
            if !exact_target_matches_row(actor_target, &snapshot)
                || snapshot.full_jid != actor_full_jid
                || !principal_matches_occupancy(actor, &snapshot)
            {
                return Ok(ClusterMucAffiliationMutationOutcome::Unauthorized);
            }
            actor_role = Some(snapshot.role);
        } else {
            // Only a locally authenticated account may authorize a direct
            // invitation without an in-room occupancy. Remote ownership must
            // remain tied to an authenticated S2S occupancy incarnation.
            if !matches!(actor, ClusterMucPrincipal::Local { .. }) {
                return Ok(ClusterMucAffiliationMutationOutcome::Unauthorized);
            }
            actor_role = None;
        }
        let privileged = matches!(actor_affiliation.as_str(), "owner" | "admin");
        let permitted_member = room.allow_invites
            && actor_role.as_deref().map_or_else(
                || matches!(actor_affiliation.as_str(), "member" | "owner" | "admin"),
                |role| role != "visitor",
            );
        if !privileged && !permitted_member {
            return Ok(ClusterMucAffiliationMutationOutcome::Unauthorized);
        }
    }

    let previous = subject_affiliation_for_update(tx, room_id, subject).await?;
    if matches!(
        mutation,
        ClusterMucAffiliationMutation::SelfRegister { .. }
            | ClusterMucAffiliationMutation::Invitation
    ) && previous.as_deref() == Some("outcast")
    {
        return Ok(ClusterMucAffiliationMutationOutcome::Outcast);
    }
    if let Some(nick) = reserved_nick {
        let conflict = match subject {
            ClusterMucAffiliationSubject::Local { user_id, .. } => {
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(
                    SELECT 1 FROM muc_affiliations
                     WHERE room_id=$1 AND reserved_nick=$2 AND user_id<>$3
                    UNION ALL
                    SELECT 1 FROM muc_external_affiliations
                     WHERE room_id=$1 AND reserved_nick=$2
                    UNION ALL
                    SELECT 1 FROM cluster_muc_occupancies
                     WHERE room_id=$1 AND nick=$2 AND bare_jid<>$4
                       AND state IN ('active','suspended')
                       AND lease_until>clock_timestamp())",
                )
                .bind(room_id)
                .bind(nick)
                .bind(user_id)
                .bind(subject.bare_jid())
                .fetch_one(&mut **tx)
                .await?
            }
            ClusterMucAffiliationSubject::Federated { bare_jid } => {
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(
                    SELECT 1 FROM muc_affiliations WHERE room_id=$1 AND reserved_nick=$2
                    UNION ALL
                    SELECT 1 FROM muc_external_affiliations
                     WHERE room_id=$1 AND reserved_nick=$2 AND jid<>$3
                    UNION ALL
                    SELECT 1 FROM cluster_muc_occupancies
                     WHERE room_id=$1 AND nick=$2 AND bare_jid<>$3
                       AND state IN ('active','suspended')
                       AND lease_until>clock_timestamp())",
                )
                .bind(room_id)
                .bind(nick)
                .bind(bare_jid)
                .fetch_one(&mut **tx)
                .await?
            }
        };
        if conflict {
            return Ok(ClusterMucAffiliationMutationOutcome::Conflict);
        }
    }

    let previous_affiliation = previous.as_deref().unwrap_or("none");
    let resulting_affiliation = match mutation {
        ClusterMucAffiliationMutation::SelfRegister { .. } => {
            if matches!(previous_affiliation, "owner" | "admin") {
                previous_affiliation
            } else {
                "member"
            }
        }
        ClusterMucAffiliationMutation::SelfUnregister => {
            if matches!(previous_affiliation, "owner" | "admin" | "outcast") {
                previous_affiliation
            } else {
                "none"
            }
        }
        ClusterMucAffiliationMutation::Invitation => {
            if previous.is_none() {
                "member"
            } else {
                previous_affiliation
            }
        }
    };
    let affiliation_changed = previous_affiliation != resulting_affiliation;
    let audience = active_audience(tx, room_id).await?;
    let targets = if affiliation_changed {
        subject_occupancies_for_update(tx, room_id, subject).await?
    } else {
        Vec::new()
    };
    match (subject, &mutation) {
        (
            ClusterMucAffiliationSubject::Local { user_id, .. },
            ClusterMucAffiliationMutation::SelfRegister { reserved_nick },
        ) => {
            sqlx::query(
                "INSERT INTO muc_affiliations(room_id,user_id,affiliation,reserved_nick,updated_at)
                 VALUES($1,$2,'member',$3,clock_timestamp())
                 ON CONFLICT(room_id,user_id) DO UPDATE SET
                   affiliation=CASE WHEN muc_affiliations.affiliation IN ('owner','admin')
                                    THEN muc_affiliations.affiliation ELSE 'member' END,
                   reserved_nick=EXCLUDED.reserved_nick,updated_at=clock_timestamp()",
            )
            .bind(room_id)
            .bind(user_id)
            .bind(reserved_nick)
            .execute(&mut **tx)
            .await?;
        }
        (
            ClusterMucAffiliationSubject::Federated { bare_jid },
            ClusterMucAffiliationMutation::SelfRegister { reserved_nick },
        ) => {
            sqlx::query(
                "INSERT INTO muc_external_affiliations(room_id,jid,affiliation,reserved_nick,updated_at)
                 VALUES($1,$2,'member',$3,clock_timestamp())
                 ON CONFLICT(room_id,jid) DO UPDATE SET
                   affiliation=CASE WHEN muc_external_affiliations.affiliation IN ('owner','admin')
                                    THEN muc_external_affiliations.affiliation ELSE 'member' END,
                   reserved_nick=EXCLUDED.reserved_nick,updated_at=clock_timestamp()",
            ).bind(room_id).bind(bare_jid).bind(reserved_nick).execute(&mut **tx).await?;
        }
        (
            ClusterMucAffiliationSubject::Local { user_id, .. },
            ClusterMucAffiliationMutation::SelfUnregister,
        ) => {
            if matches!(previous_affiliation, "owner" | "admin" | "outcast") {
                sqlx::query("UPDATE muc_affiliations SET reserved_nick=NULL,updated_at=clock_timestamp() WHERE room_id=$1 AND user_id=$2")
                    .bind(room_id).bind(user_id).execute(&mut **tx).await?;
            } else {
                sqlx::query("DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2")
                    .bind(room_id)
                    .bind(user_id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        (
            ClusterMucAffiliationSubject::Federated { bare_jid },
            ClusterMucAffiliationMutation::SelfUnregister,
        ) => {
            if matches!(previous_affiliation, "owner" | "admin" | "outcast") {
                sqlx::query("UPDATE muc_external_affiliations SET reserved_nick=NULL,updated_at=clock_timestamp() WHERE room_id=$1 AND jid=$2")
                    .bind(room_id).bind(bare_jid).execute(&mut **tx).await?;
            } else {
                sqlx::query("DELETE FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2")
                    .bind(room_id)
                    .bind(bare_jid)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        (
            ClusterMucAffiliationSubject::Local { user_id, .. },
            ClusterMucAffiliationMutation::Invitation,
        ) => {
            sqlx::query("INSERT INTO muc_affiliations(room_id,user_id,affiliation,updated_at) VALUES($1,$2,'member',clock_timestamp()) ON CONFLICT(room_id,user_id) DO NOTHING")
                .bind(room_id).bind(user_id).execute(&mut **tx).await?;
        }
        (
            ClusterMucAffiliationSubject::Federated { bare_jid },
            ClusterMucAffiliationMutation::Invitation,
        ) => {
            sqlx::query("INSERT INTO muc_external_affiliations(room_id,jid,affiliation,updated_at) VALUES($1,$2,'member',clock_timestamp()) ON CONFLICT(room_id,jid) DO NOTHING")
                .bind(room_id).bind(bare_jid).execute(&mut **tx).await?;
        }
    }
    if affiliation_changed {
        update_subject_occupancies(tx, &room, room_id, subject, resulting_affiliation).await?;
    }
    let mut changes = Vec::with_capacity(targets.len());
    for target in targets {
        let target_identity = ClusterMucOccupancyTarget::from(&target);
        let row = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3",
        )
        .bind(room_id)
        .bind(target.occupant_incarnation)
        .bind(target.occupancy_epoch)
        .fetch_one(&mut **tx)
        .await?;
        changes.push(json!({
            "target":target_identity,"previous_affiliation":previous_affiliation,
            "affiliation":resulting_affiliation,"status":321,
            "snapshot":ClusterMucPolicySnapshot::from(&occupancy_from_row(&row)),
        }));
    }
    let offline_affiliation = (affiliation_changed && room.non_anonymous && changes.is_empty())
        .then(|| {
            json!({
                "bare_jid":subject.bare_jid(),"affiliation":resulting_affiliation,
                "nick":reserved_nick,"reason":reason,
            })
        });
    let (_unused, event_sequence) = allocate_room_epochs(tx, room_id, false).await?;
    let authorization = json!({
        "action":action,"actor":actor,"actor_full_jid":actor_full_jid,
        "actor_target":actor_target,"durable_actor_affiliation":actor_affiliation,
        "actor_role":actor_role,"subject":subject,
        "room_epoch":room.room_epoch,"config_version":room.config_version,
        "allow_registration":room.allow_registration,"allow_invites":room.allow_invites,
    });
    let details = json!({
        "changes":changes,"offline_affiliation":offline_affiliation,
        "affiliation_changed":affiliation_changed,"action":action,
    });
    insert_operation_and_outbox(
        tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "affiliation",
            digest: &digest,
            actor_bare_jid: Some(actor.bare_jid()),
            actor_full_jid: Some(&actor_full_jid),
            actor_affiliation: Some(&actor_affiliation),
            authorization_source: match actor {
                ClusterMucPrincipal::Local { .. } => "local_database",
                ClusterMucPrincipal::Federated { .. } => "federated_verified",
            },
            authorization_snapshot: &authorization,
            target: None,
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    Ok(ClusterMucAffiliationMutationOutcome::Applied {
        affiliation_changed,
    })
}

/// XEP-0045 self registration/unregistration is a PostgreSQL-authoritative
/// affiliation operation in cluster mode. Nick reservation, membership,
/// exact live occupancy updates and the immutable notification audience are
/// committed together.
#[allow(clippy::too_many_arguments)]
pub async fn mutate_cluster_muc_registration(
    pool: &PgPool,
    operation_id: Uuid,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    expected_config_version: i64,
    principal: &ClusterMucPrincipal,
    actor_full_jid: &str,
    reserved_nick: Option<&str>,
) -> Result<ClusterMucRegistrationOutcome> {
    let subject = match principal {
        ClusterMucPrincipal::Local { user_id, bare_jid } => ClusterMucAffiliationSubject::Local {
            user_id: *user_id,
            bare_jid: bare_jid.clone(),
        },
        ClusterMucPrincipal::Federated { bare_jid, .. } => {
            ClusterMucAffiliationSubject::Federated {
                bare_jid: bare_jid.clone(),
            }
        }
    };
    let mutation = reserved_nick.map_or(
        ClusterMucAffiliationMutation::SelfUnregister,
        |reserved_nick| ClusterMucAffiliationMutation::SelfRegister { reserved_nick },
    );
    let mut tx = pool.begin().await?;
    let outcome = mutate_cluster_muc_affiliation_in_tx(
        &mut tx,
        operation_id,
        room_id,
        expected_room_epoch,
        expected_config_version,
        principal,
        actor_full_jid,
        None,
        &subject,
        mutation,
        None,
    )
    .await?;
    match outcome {
        ClusterMucAffiliationMutationOutcome::Applied {
            affiliation_changed,
        } => {
            tx.commit().await?;
            Ok(ClusterMucRegistrationOutcome::Applied {
                affiliation_changed,
            })
        }
        ClusterMucAffiliationMutationOutcome::Replay {
            affiliation_changed,
        } => {
            tx.commit().await?;
            Ok(ClusterMucRegistrationOutcome::Replay {
                affiliation_changed,
            })
        }
        other => {
            tx.rollback().await?;
            Ok(match other {
                ClusterMucAffiliationMutationOutcome::Conflict => {
                    ClusterMucRegistrationOutcome::Conflict
                }
                ClusterMucAffiliationMutationOutcome::Outcast => {
                    ClusterMucRegistrationOutcome::Outcast
                }
                ClusterMucAffiliationMutationOutcome::NotAllowed
                | ClusterMucAffiliationMutationOutcome::Unauthorized => {
                    ClusterMucRegistrationOutcome::NotAllowed
                }
                ClusterMucAffiliationMutationOutcome::Stale => ClusterMucRegistrationOutcome::Stale,
                ClusterMucAffiliationMutationOutcome::Destroyed => {
                    ClusterMucRegistrationOutcome::Destroyed
                }
                ClusterMucAffiliationMutationOutcome::Applied { .. }
                | ClusterMucAffiliationMutationOutcome::Replay { .. } => unreachable!(),
            })
        }
    }
}

/// Called by the existing durable invitation admissions while their
/// PostgreSQL transaction is still open. A later quota/outbox failure rolls
/// back the affiliation operation and every notification projection too.
pub(in crate::db) async fn grant_cluster_muc_invitation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    authority: &ClusterMucInviteAuthority,
) -> Result<ClusterMucAffiliationMutationOutcome> {
    mutate_cluster_muc_affiliation_in_tx(
        tx,
        authority.operation_id,
        room_id,
        authority.expected_room_epoch,
        authority.expected_config_version,
        &authority.actor,
        &authority.actor_full_jid,
        authority.actor_target.as_ref(),
        &authority.subject,
        ClusterMucAffiliationMutation::Invitation,
        authority.reason.as_deref(),
    )
    .await
}
