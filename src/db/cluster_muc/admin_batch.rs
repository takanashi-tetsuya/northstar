//! Cluster MUC ordered affiliation and admin batches.

use super::*;

/// Apply one XEP-0045 admin affiliation IQ as a single PostgreSQL operation.
/// All targets are resolved and authorized before the first durable change;
/// live target incarnations are copied into immutable details so a delayed
/// ban/removal can never match a later occupant that reused the JID or nick.
pub struct ClusterMucAffiliationBatch<'a> {
    pub operation_id: Uuid,
    pub room_id: Uuid,
    pub expected_room_epoch: Uuid,
    pub expected_config_version: i64,
    pub actor_target: &'a ClusterMucOccupancyTarget,
    pub actor: &'a ClusterMucPrincipal,
    pub actor_full_jid: &'a str,
    pub changes: &'a [super::super::muc::MucAffiliationChange],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ClusterMucAdminChange {
    Affiliation {
        target: super::super::muc::MucAffiliationTarget,
        affiliation: String,
        reason: Option<String>,
    },
    Role {
        target_nick: String,
        role: String,
        reason: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClusterMucAdminBatchOutcome {
    Applied,
    Replay,
    DuplicateTarget,
    LastOwner,
    MissingTarget,
    Unauthorized,
    Stale,
    Destroyed,
    Conflict,
    TooManyProjections,
}

#[derive(Clone, Copy)]
pub struct ClusterMucAdminBatch<'a> {
    pub operation_id: Uuid,
    pub room_id: Uuid,
    pub expected_room_epoch: Uuid,
    pub expected_config_version: i64,
    pub actor_target: Option<&'a ClusterMucOccupancyTarget>,
    pub actor: &'a ClusterMucPrincipal,
    pub actor_full_jid: &'a str,
    pub local_domain: &'a str,
    pub changes: &'a [ClusterMucAdminChange],
}

pub async fn apply_cluster_muc_affiliations_batch(
    pool: &PgPool,
    batch: ClusterMucAffiliationBatch<'_>,
) -> Result<super::super::muc::MucAffiliationBatchOutcome> {
    let ClusterMucAffiliationBatch {
        operation_id,
        room_id,
        expected_room_epoch,
        expected_config_version,
        actor_target,
        actor,
        actor_full_jid,
        changes,
    } = batch;
    actor.validate()?;
    let actor_full_jid = crate::jid::canonicalize(actor_full_jid)?;
    anyhow::ensure!(
        muc_principal_owns_address(&actor_full_jid, actor)?,
        "MUC affiliation actor does not own the authenticated full JID"
    );
    if changes.is_empty() {
        return Ok(super::super::muc::MucAffiliationBatchOutcome::Applied);
    }

    #[derive(Serialize)]
    struct DigestChange<'a> {
        target_kind: &'a str,
        target: &'a str,
        affiliation: &'a str,
    }
    let digest_changes = changes
        .iter()
        .map(|change| match &change.target {
            super::super::muc::MucAffiliationTarget::LocalUsername(username) => DigestChange {
                target_kind: "local",
                target: username,
                affiliation: &change.affiliation,
            },
            super::super::muc::MucAffiliationTarget::FederatedBareJid(jid) => DigestChange {
                target_kind: "federated",
                target: jid,
                affiliation: &change.affiliation,
            },
        })
        .collect::<Vec<_>>();
    let digest = request_digest(&json!({
        "room_id":room_id,"room_epoch":expected_room_epoch,
        "config_version":expected_config_version,"actor_target":actor_target,"actor":actor,
        "actor_full_jid":actor_full_jid,"changes":digest_changes,
    }))?;

    enum ResolvedTarget {
        Local { user_id: Uuid },
        Federated { bare_jid: String },
    }
    struct ResolvedChange {
        target: ResolvedTarget,
        affiliation: String,
        previous: Option<String>,
    }

    let mut tx = pool.begin().await?;
    if existing_operation(&mut tx, operation_id, "affiliation", &digest)
        .await?
        .is_some()
    {
        tx.commit().await?;
        return Ok(super::super::muc::MucAffiliationBatchOutcome::Applied);
    }
    let Some(room) = lock_room(&mut tx, room_id).await? else {
        tx.rollback().await?;
        return Ok(super::super::muc::MucAffiliationBatchOutcome::MissingTarget);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(super::super::muc::MucAffiliationBatchOutcome::Destroyed);
    }
    if room.room_epoch != expected_room_epoch || room.config_version != expected_config_version {
        tx.rollback().await?;
        return Ok(super::super::muc::MucAffiliationBatchOutcome::Stale);
    }
    if actor_target.room_id != room_id || actor_target.room_epoch != room.room_epoch {
        tx.rollback().await?;
        return Ok(super::super::muc::MucAffiliationBatchOutcome::Stale);
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
        return Ok(super::super::muc::MucAffiliationBatchOutcome::Unauthorized);
    };
    let actor_snapshot = occupancy_from_row(&actor_row);
    if !exact_target_matches_row(actor_target, &actor_snapshot)
        || actor_snapshot.full_jid != actor_full_jid
        || !principal_matches_occupancy(actor, &actor_snapshot)
    {
        tx.rollback().await?;
        return Ok(super::super::muc::MucAffiliationBatchOutcome::Unauthorized);
    }
    let actor_affiliation = affiliation_in_tx(&mut tx, room_id, actor)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if !matches!(actor_affiliation.as_str(), "owner" | "admin") {
        tx.rollback().await?;
        return Ok(super::super::muc::MucAffiliationBatchOutcome::MissingTarget);
    }
    let mut seen = std::collections::HashSet::with_capacity(changes.len());
    let mut resolved = Vec::with_capacity(changes.len());
    let mut owner_delta = 0_i64;
    for change in changes {
        anyhow::ensure!(
            matches!(
                change.affiliation.as_str(),
                "owner" | "admin" | "member" | "outcast" | "none"
            ),
            "invalid clustered MUC affiliation"
        );
        let (key, target, previous) = match &change.target {
            super::super::muc::MucAffiliationTarget::LocalUsername(username) => {
                let Some(user_id) =
                    sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE username=$1")
                        .bind(username)
                        .fetch_optional(&mut *tx)
                        .await?
                else {
                    tx.rollback().await?;
                    return Ok(super::super::muc::MucAffiliationBatchOutcome::MissingTarget);
                };
                let previous = sqlx::query_scalar::<_, String>(
                    "SELECT affiliation FROM muc_affiliations
                      WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
                )
                .bind(room_id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
                (
                    format!("local:{user_id}"),
                    ResolvedTarget::Local { user_id },
                    previous,
                )
            }
            super::super::muc::MucAffiliationTarget::FederatedBareJid(jid) => {
                let jid = crate::jid::CanonicalJid::parse_bare(jid)?;
                anyhow::ensure!(
                    jid.localpart().is_some(),
                    "federated MUC target must be a user JID"
                );
                let jid = jid.to_string();
                let previous = sqlx::query_scalar::<_, String>(
                    "SELECT affiliation FROM muc_external_affiliations
                      WHERE room_id=$1 AND jid=$2 FOR UPDATE",
                )
                .bind(room_id)
                .bind(&jid)
                .fetch_optional(&mut *tx)
                .await?;
                (
                    format!("federated:{jid}"),
                    ResolvedTarget::Federated { bare_jid: jid },
                    previous,
                )
            }
        };
        if !seen.insert(key) {
            tx.rollback().await?;
            return Ok(super::super::muc::MucAffiliationBatchOutcome::DuplicateTarget);
        }
        if actor_affiliation == "admin"
            && (matches!(previous.as_deref(), Some("owner" | "admin"))
                || matches!(change.affiliation.as_str(), "owner" | "admin"))
        {
            tx.rollback().await?;
            return Ok(super::super::muc::MucAffiliationBatchOutcome::MissingTarget);
        }
        if previous.as_deref() == Some("owner") && change.affiliation != "owner" {
            owner_delta -= 1;
        } else if previous.as_deref() != Some("owner") && change.affiliation == "owner" {
            owner_delta += 1;
        }
        resolved.push(ResolvedChange {
            target,
            affiliation: change.affiliation.clone(),
            previous,
        });
    }
    let existing_owners: i64 = sqlx::query_scalar(
        "SELECT
             (SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND affiliation='owner') +
             (SELECT COUNT(*) FROM muc_external_affiliations WHERE room_id=$1 AND affiliation='owner')",
    )
    .bind(room_id)
    .fetch_one(&mut *tx)
    .await?;
    if existing_owners + owner_delta < 1 {
        tx.rollback().await?;
        return Ok(super::super::muc::MucAffiliationBatchOutcome::LastOwner);
    }

    let audience = active_audience(&mut tx, room_id).await?;
    let mut affected = Vec::new();
    for change in &resolved {
        let rows = match &change.target {
            ResolvedTarget::Local { user_id, .. } => {
                sqlx::query(
                    "SELECT * FROM cluster_muc_occupancies
                  WHERE room_id=$1 AND local_user_id=$2
                    AND state IN ('active','suspended') FOR UPDATE",
                )
                .bind(room_id)
                .bind(user_id)
                .fetch_all(&mut *tx)
                .await?
            }
            ResolvedTarget::Federated { bare_jid } => {
                sqlx::query(
                    "SELECT * FROM cluster_muc_occupancies
                  WHERE room_id=$1 AND bare_jid=$2
                    AND state IN ('active','suspended') FOR UPDATE",
                )
                .bind(room_id)
                .bind(bare_jid)
                .fetch_all(&mut *tx)
                .await?
            }
        };
        for row in rows {
            let occupancy = occupancy_from_row(&row);
            affected.push(json!({
                "target":ClusterMucOccupancyTarget::from(&occupancy),
                "previous_affiliation":change.previous,
                "affiliation":change.affiliation,
                "status":if change.affiliation == "outcast" { 301 } else { 321 },
            }));
        }
        match &change.target {
            ResolvedTarget::Local { user_id, .. } => {
                if change.affiliation == "none" {
                    sqlx::query("DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2")
                        .bind(room_id)
                        .bind(user_id)
                        .execute(&mut *tx)
                        .await?;
                } else {
                    sqlx::query(
                        "INSERT INTO muc_affiliations(room_id,user_id,affiliation)
                         VALUES($1,$2,$3) ON CONFLICT(room_id,user_id) DO UPDATE
                         SET affiliation=EXCLUDED.affiliation",
                    )
                    .bind(room_id)
                    .bind(user_id)
                    .bind(&change.affiliation)
                    .execute(&mut *tx)
                    .await?;
                }
                sqlx::query(
                    "UPDATE cluster_muc_occupancies SET affiliation=$3,
             role=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'none'
                       WHEN $3 IN ('owner','admin') THEN 'moderator'
                                   WHEN $4 AND $3='none' THEN 'visitor' ELSE 'participant' END,
                         state=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'revoked' ELSE state END,
                         lease_until=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN clock_timestamp() ELSE lease_until END,
                         ended_at=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN clock_timestamp() ELSE ended_at END,
                         updated_at=clock_timestamp()
                      WHERE room_id=$1 AND local_user_id=$2 AND state IN ('active','suspended')",
                )
                .bind(room_id).bind(user_id).bind(&change.affiliation)
                .bind(room.moderated).bind(room.members_only)
                .execute(&mut *tx).await?;
            }
            ResolvedTarget::Federated { bare_jid } => {
                if change.affiliation == "none" {
                    sqlx::query(
                        "DELETE FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2",
                    )
                    .bind(room_id)
                    .bind(bare_jid)
                    .execute(&mut *tx)
                    .await?;
                } else {
                    sqlx::query(
                        "INSERT INTO muc_external_affiliations(room_id,jid,affiliation)
                         VALUES($1,$2,$3) ON CONFLICT(room_id,jid) DO UPDATE
                         SET affiliation=EXCLUDED.affiliation",
                    )
                    .bind(room_id)
                    .bind(bare_jid)
                    .bind(&change.affiliation)
                    .execute(&mut *tx)
                    .await?;
                }
                sqlx::query(
                    "UPDATE cluster_muc_occupancies SET affiliation=$3,
             role=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'none'
                       WHEN $3 IN ('owner','admin') THEN 'moderator'
                                   WHEN $4 AND $3='none' THEN 'visitor' ELSE 'participant' END,
                         state=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN 'revoked' ELSE state END,
                         lease_until=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN clock_timestamp() ELSE lease_until END,
                         ended_at=CASE WHEN $3='outcast' OR ($5 AND $3='none') THEN clock_timestamp() ELSE ended_at END,
                         updated_at=clock_timestamp()
                      WHERE room_id=$1 AND bare_jid=$2 AND identity_kind='federated'
                        AND state IN ('active','suspended')",
                )
                .bind(room_id).bind(bare_jid).bind(&change.affiliation)
                .bind(room.moderated).bind(room.members_only)
                .execute(&mut *tx).await?;
            }
        }
    }
    for entry in &mut affected {
        let target: ClusterMucOccupancyTarget = serde_json::from_value(entry["target"].clone())?;
        let snapshot = sqlx::query(
            "SELECT * FROM cluster_muc_occupancies
              WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3",
        )
        .bind(target.room_id)
        .bind(target.occupant_incarnation)
        .bind(target.occupancy_epoch)
        .fetch_one(&mut *tx)
        .await?;
        entry
            .as_object_mut()
            .context("MUC affiliation detail must be an object")?
            .insert(
                "snapshot".to_owned(),
                serde_json::to_value(ClusterMucPolicySnapshot::from(&occupancy_from_row(
                    &snapshot,
                )))?,
            );
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, room_id, false).await?;
    let authorization = json!({
        "actor":actor,"actor_full_jid":actor_full_jid,
        "actor_target":actor_target,
        "durable_affiliation":actor_affiliation,
        "room_epoch":room.room_epoch,"config_version":room.config_version,
    });
    let details = json!({"changes":affected});
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id,
            room_id,
            room_epoch: room.room_epoch,
            kind: "affiliation",
            digest: &digest,
            actor_bare_jid: Some(actor.bare_jid()),
            actor_full_jid: Some(&actor_full_jid),
            actor_affiliation: Some(&actor_affiliation),
            authorization_source: if matches!(actor, ClusterMucPrincipal::Local { .. }) {
                "local_database"
            } else {
                "federated_verified"
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
    tx.commit().await?;
    Ok(super::super::muc::MucAffiliationBatchOutcome::Applied)
}

/// Apply the complete ordered administrative IQ while the room is locked.
/// Every read used for authorization, every target fence, the final-owner
/// check, all writes, and the immutable delivery record share one transaction.
pub async fn apply_cluster_muc_admin_batch(
    pool: &PgPool,
    batch: ClusterMucAdminBatch<'_>,
) -> Result<ClusterMucAdminBatchOutcome> {
    for attempt in 0..3 {
        match apply_cluster_muc_admin_batch_once(pool, batch).await {
            Err(error) if attempt < 2 && is_cluster_muc_serialization_failure(&error) => {
                continue;
            }
            outcome => return outcome,
        }
    }
    unreachable!("the bounded MUC transaction retry always returns")
}

fn is_cluster_muc_serialization_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .and_then(|database| database.code())
            .is_some_and(|code| matches!(code.as_ref(), "40001" | "40P01"))
    })
}

async fn apply_cluster_muc_admin_batch_once(
    pool: &PgPool,
    batch: ClusterMucAdminBatch<'_>,
) -> Result<ClusterMucAdminBatchOutcome> {
    use std::collections::{BTreeMap, HashSet};
    use ClusterMucAdminBatchOutcome as Outcome;

    enum Subject {
        Local(Uuid),
        Federated(String),
    }
    enum Prepared {
        Affiliation {
            key: String,
            subject: Subject,
            bare_jid: String,
            affiliation: String,
            previous: Option<String>,
            reason: Option<String>,
            affected: Vec<ClusterMucOccupancyTarget>,
        },
        Role {
            target: ClusterMucOccupancyTarget,
            role: String,
            reason: Option<String>,
        },
    }

    anyhow::ensure!(
        !batch.changes.is_empty() && batch.changes.len() <= 63,
        "MUC admin batch must contain 1 to 63 items"
    );
    batch.actor.validate()?;
    let actor_full_jid = crate::jid::canonicalize(batch.actor_full_jid)?;
    anyhow::ensure!(
        actor_full_jid == batch.actor_full_jid
            && muc_principal_owns_address(&actor_full_jid, batch.actor)?,
        "MUC admin actor does not own the canonical authenticated full JID"
    );
    let local_domain = crate::jid::prepare_domainpart(batch.local_domain)?;
    anyhow::ensure!(
        local_domain == batch.local_domain,
        "noncanonical local domain"
    );
    for change in batch.changes {
        let reason = match change {
            ClusterMucAdminChange::Affiliation { reason, .. }
            | ClusterMucAdminChange::Role { reason, .. } => reason,
        };
        anyhow::ensure!(
            reason.as_ref().is_none_or(|value| value.len() <= 4096),
            "MUC admin reason is oversized"
        );
    }
    let digest = request_digest(&json!({
        "actor":batch.actor,"actor_full_jid":actor_full_jid,
        "changes":batch.changes,
    }))?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    // Replay is checked before resolving any nick: a successful kick leaves
    // no live nick to resolve. The IQ identity is independent of its payload.
    let prior = sqlx::query(
        "SELECT room_id,operation_kind,request_digest
           FROM cluster_muc_operations WHERE operation_id=$1",
    )
    .bind(batch.operation_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(prior) = prior {
        let identical = prior.get::<Uuid, _>("room_id") == batch.room_id
            && prior.get::<String, _>("operation_kind") == "admin_batch"
            && prior.get::<Vec<u8>, _>("request_digest") == digest;
        tx.rollback().await?;
        return Ok(if identical {
            Outcome::Replay
        } else {
            Outcome::Conflict
        });
    }
    let Some(actor_target) = batch.actor_target else {
        tx.rollback().await?;
        return Ok(Outcome::Unauthorized);
    };
    let Some(room) = lock_room(&mut tx, batch.room_id).await? else {
        tx.rollback().await?;
        return Ok(Outcome::MissingTarget);
    };
    if room.destroyed {
        tx.rollback().await?;
        return Ok(Outcome::Destroyed);
    }
    if room.room_epoch != batch.expected_room_epoch
        || room.config_version != batch.expected_config_version
        || actor_target.room_id != batch.room_id
        || actor_target.room_epoch != room.room_epoch
    {
        tx.rollback().await?;
        return Ok(Outcome::Stale);
    }
    // The room lock serializes all conforming room mutations. Lock the exact
    // occupancies in a stable order before reading affiliation rows, so a
    // mixed request cannot reverse the lock order of its individual items.
    let rows = sqlx::query(
        "SELECT * FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2
            AND state IN ('active','suspended') AND lease_until>clock_timestamp()
          ORDER BY occupant_incarnation LIMIT $3 FOR UPDATE",
    )
    .bind(batch.room_id)
    .bind(room.room_epoch)
    .bind(i64::try_from(MAX_OPERATION_AUDIENCE + 1).unwrap_or(10_001))
    .fetch_all(&mut *tx)
    .await?;
    anyhow::ensure!(
        rows.len() <= MAX_OPERATION_AUDIENCE,
        "MUC admin batch occupancy snapshot exceeds configured operation bound"
    );
    let occupancies = rows.iter().map(occupancy_from_row).collect::<Vec<_>>();
    let Some(actor_current) = occupancies.iter().find(|occupancy| {
        occupancy.state == "active"
            && exact_target_matches_row(actor_target, occupancy)
            && occupancy.full_jid == actor_full_jid
            && principal_matches_occupancy(batch.actor, occupancy)
    }) else {
        tx.rollback().await?;
        return Ok(Outcome::Unauthorized);
    };
    let actor_affiliation = affiliation_in_tx(&mut tx, batch.room_id, batch.actor)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if actor_affiliation == "outcast" {
        tx.rollback().await?;
        return Ok(Outcome::Unauthorized);
    }

    let mut prepared = Vec::with_capacity(batch.changes.len());
    let mut keys = HashSet::new();
    let mut touched = HashSet::new();
    for change in batch.changes {
        match change {
            ClusterMucAdminChange::Affiliation {
                target,
                affiliation,
                reason,
            } => {
                if !matches!(actor_affiliation.as_str(), "owner" | "admin") {
                    tx.rollback().await?;
                    return Ok(Outcome::Unauthorized);
                }
                anyhow::ensure!(
                    matches!(
                        affiliation.as_str(),
                        "owner" | "admin" | "member" | "outcast" | "none"
                    ),
                    "invalid MUC affiliation"
                );
                let (key, subject, bare_jid) = match target {
                    super::super::muc::MucAffiliationTarget::LocalUsername(username) => {
                        anyhow::ensure!(
                            crate::jid::prepare_localpart(username)? == *username,
                            "noncanonical MUC local affiliation target"
                        );
                        let Some(user_id) =
                            sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE username=$1")
                                .bind(username)
                                .fetch_optional(&mut *tx)
                                .await?
                        else {
                            tx.rollback().await?;
                            return Ok(Outcome::MissingTarget);
                        };
                        (
                            format!("local:{user_id}"),
                            Subject::Local(user_id),
                            format!("{username}@{local_domain}"),
                        )
                    }
                    super::super::muc::MucAffiliationTarget::FederatedBareJid(jid) => {
                        let canonical = crate::jid::CanonicalJid::parse_bare(jid)?;
                        anyhow::ensure!(
                            canonical.localpart().is_some()
                                && canonical.to_string() == *jid
                                && canonical.domainpart() != local_domain,
                            "noncanonical or local federated MUC affiliation target"
                        );
                        (
                            format!("federated:{jid}"),
                            Subject::Federated(jid.clone()),
                            jid.clone(),
                        )
                    }
                };
                if !keys.insert(key.clone()) {
                    tx.rollback().await?;
                    return Ok(Outcome::DuplicateTarget);
                }
                let affected = occupancies
                    .iter()
                    .filter(|occupancy| match &subject {
                        Subject::Local(user_id) => occupancy.local_user_id == Some(*user_id),
                        Subject::Federated(jid) => {
                            occupancy.identity_kind == "federated" && occupancy.bare_jid == *jid
                        }
                    })
                    .map(ClusterMucOccupancyTarget::from)
                    .collect::<Vec<_>>();
                for occupant in &affected {
                    if !touched.insert(occupant.occupant_incarnation) {
                        tx.rollback().await?;
                        return Ok(Outcome::DuplicateTarget);
                    }
                }
                prepared.push(Prepared::Affiliation {
                    key,
                    subject,
                    bare_jid,
                    affiliation: affiliation.clone(),
                    previous: None,
                    reason: reason.clone(),
                    affected,
                });
            }
            ClusterMucAdminChange::Role {
                target_nick,
                role,
                reason,
            } => {
                anyhow::ensure!(
                    matches!(
                        role.as_str(),
                        "moderator" | "participant" | "visitor" | "none"
                    ),
                    "invalid MUC role"
                );
                anyhow::ensure!(
                    crate::services::xml_util::prepare_muc_nick(target_nick)? == *target_nick,
                    "noncanonical MUC role target nick"
                );
                if !keys.insert(format!("nick:{target_nick}")) {
                    tx.rollback().await?;
                    return Ok(Outcome::DuplicateTarget);
                }
                let Some(occupancy) = occupancies.iter().find(|row| row.nick == *target_nick)
                else {
                    tx.rollback().await?;
                    return Ok(Outcome::MissingTarget);
                };
                if !touched.insert(occupancy.occupant_incarnation) {
                    tx.rollback().await?;
                    return Ok(Outcome::DuplicateTarget);
                }
                prepared.push(Prepared::Role {
                    target: ClusterMucOccupancyTarget::from(occupancy),
                    role: role.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }

    // Sort affiliation keys independently of IQ order; row locks are then
    // acquired in one canonical order, while effects retain IQ order below.
    let mut affiliations = BTreeMap::<String, Option<String>>::new();
    for item in &prepared {
        if let Prepared::Affiliation { key, .. } = item {
            affiliations.insert(key.clone(), None);
        }
    }
    for (key, previous) in &mut affiliations {
        let value = if let Some(user_id) = key.strip_prefix("local:") {
            sqlx::query_scalar::<_, String>(
                "SELECT affiliation FROM muc_affiliations
                  WHERE room_id=$1 AND user_id=$2 FOR SHARE",
            )
            .bind(batch.room_id)
            .bind(Uuid::parse_str(user_id)?)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            sqlx::query_scalar::<_, String>(
                "SELECT affiliation FROM muc_external_affiliations
                  WHERE room_id=$1 AND jid=$2 FOR SHARE",
            )
            .bind(batch.room_id)
            .bind(
                key.strip_prefix("federated:")
                    .context("invalid MUC target key")?,
            )
            .fetch_optional(&mut *tx)
            .await?
        };
        *previous = value;
    }
    let mut owner_delta = 0_i64;
    let mut projection_count = 0_usize;
    for item in &mut prepared {
        match item {
            Prepared::Affiliation {
                key,
                affiliation,
                previous,
                affected,
                ..
            } => {
                *previous = affiliations.get(key).cloned().flatten();
                if actor_affiliation == "admin"
                    && (matches!(previous.as_deref(), Some("owner" | "admin"))
                        || matches!(affiliation.as_str(), "owner" | "admin"))
                {
                    tx.rollback().await?;
                    return Ok(Outcome::Unauthorized);
                }
                if previous.as_deref() == Some("owner") && affiliation != "owner" {
                    owner_delta -= 1;
                } else if previous.as_deref() != Some("owner") && affiliation == "owner" {
                    owner_delta += 1;
                }
                projection_count += if affected.is_empty() {
                    usize::from(room.non_anonymous)
                } else {
                    affected.len()
                };
            }
            Prepared::Role { target, role, .. } => {
                let occupancy = occupancies
                    .iter()
                    .find(|row| exact_target_matches_row(target, row))
                    .context("locked MUC role target disappeared")?;
                let target_principal = if let Some(user_id) = occupancy.local_user_id {
                    ClusterMucPrincipal::Local {
                        user_id,
                        bare_jid: occupancy.bare_jid.clone(),
                    }
                } else {
                    ClusterMucPrincipal::Federated {
                        bare_jid: occupancy.bare_jid.clone(),
                        authenticated_domain: occupancy
                            .authenticated_domain
                            .clone()
                            .context("federated MUC occupant lacks authenticated domain")?,
                    }
                };
                let target_affiliation =
                    affiliation_in_tx(&mut tx, batch.room_id, &target_principal).await?;
                if !(matches!(actor_affiliation.as_str(), "owner" | "admin")
                    || actor_current.role == "moderator")
                    || (actor_affiliation == "admin"
                        && matches!(target_affiliation.as_deref(), Some("owner" | "admin")))
                    || (!matches!(actor_affiliation.as_str(), "owner" | "admin")
                        && (role == "moderator"
                            || occupancy.role == "moderator"
                            || matches!(target_affiliation.as_deref(), Some("owner" | "admin"))))
                {
                    tx.rollback().await?;
                    return Ok(Outcome::Unauthorized);
                }
                projection_count += 1;
            }
        }
    }
    if projection_count > 63 {
        tx.rollback().await?;
        return Ok(Outcome::TooManyProjections);
    }
    let existing_owners: i64 = sqlx::query_scalar(
        "SELECT
             (SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND affiliation='owner') +
             (SELECT COUNT(*) FROM muc_external_affiliations WHERE room_id=$1 AND affiliation='owner')",
    )
    .bind(batch.room_id)
    .fetch_one(&mut *tx)
    .await?;
    if existing_owners + owner_delta < 1 {
        tx.rollback().await?;
        return Ok(Outcome::LastOwner);
    }
    let audience = active_audience(&mut tx, batch.room_id).await?;
    let mut effects = Vec::<Value>::with_capacity(projection_count);
    for item in &prepared {
        match item {
            Prepared::Affiliation {
                subject,
                bare_jid,
                affiliation,
                reason,
                affected,
                ..
            } => {
                match subject {
                    Subject::Local(user_id) => {
                        if affiliation == "none" {
                            sqlx::query(
                                "DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2",
                            )
                            .bind(batch.room_id)
                            .bind(user_id)
                            .execute(&mut *tx)
                            .await?;
                        } else {
                            sqlx::query(
                                "INSERT INTO muc_affiliations(room_id,user_id,affiliation)
                                 VALUES($1,$2,$3) ON CONFLICT(room_id,user_id)
                                 DO UPDATE SET affiliation=EXCLUDED.affiliation",
                            )
                            .bind(batch.room_id)
                            .bind(user_id)
                            .bind(affiliation)
                            .execute(&mut *tx)
                            .await?;
                        }
                    }
                    Subject::Federated(jid) => {
                        if affiliation == "none" {
                            sqlx::query(
                                "DELETE FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2",
                            )
                            .bind(batch.room_id)
                            .bind(jid)
                            .execute(&mut *tx)
                            .await?;
                        } else {
                            sqlx::query(
                                "INSERT INTO muc_external_affiliations(room_id,jid,affiliation)
                                 VALUES($1,$2,$3) ON CONFLICT(room_id,jid)
                                 DO UPDATE SET affiliation=EXCLUDED.affiliation",
                            )
                            .bind(batch.room_id)
                            .bind(jid)
                            .bind(affiliation)
                            .execute(&mut *tx)
                            .await?;
                        }
                    }
                }
                if affected.is_empty() && room.non_anonymous {
                    effects.push(json!({
                        "kind":"offline_affiliation","bare_jid":bare_jid,
                        "affiliation":affiliation,"nick":Value::Null,"reason":reason,
                    }));
                }
                for target in affected {
                    let terminal =
                        affiliation == "outcast" || (affiliation == "none" && room.members_only);
                    let status = if affiliation == "outcast" {
                        Some(301_u16)
                    } else if terminal {
                        Some(321_u16)
                    } else {
                        None
                    };
                    let changed = sqlx::query(
                        "UPDATE cluster_muc_occupancies SET affiliation=$9,
                           role=CASE WHEN $9='outcast' OR ($10 AND $9='none') THEN 'none'
                                     WHEN $9 IN ('owner','admin') THEN 'moderator'
                                     WHEN $11 AND $9='none' THEN 'visitor' ELSE 'participant' END,
                           state=CASE WHEN $9='outcast' OR ($10 AND $9='none') THEN 'revoked' ELSE state END,
                           lease_until=CASE WHEN $9='outcast' OR ($10 AND $9='none') THEN clock_timestamp() ELSE lease_until END,
                           ended_at=CASE WHEN $9='outcast' OR ($10 AND $9='none') THEN clock_timestamp() ELSE ended_at END,
                           updated_at=clock_timestamp()
                          WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
                            AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
                            AND connection_uuid=$7 AND connection_epoch=$8
                            AND state IN ('active','suspended')",
                    )
                    .bind(target.room_id).bind(target.room_epoch)
                    .bind(target.occupant_incarnation).bind(target.occupancy_epoch)
                    .bind(&target.full_jid).bind(&target.nick)
                    .bind(target.connection_uuid).bind(target.connection_epoch)
                    .bind(affiliation).bind(room.members_only).bind(room.moderated)
                    .execute(&mut *tx).await?.rows_affected();
                    anyhow::ensure!(
                        changed == 1,
                        "exact MUC affiliation target changed concurrently"
                    );
                    let row = sqlx::query(
                        "SELECT * FROM cluster_muc_occupancies
                          WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3",
                    )
                    .bind(target.room_id)
                    .bind(target.occupant_incarnation)
                    .bind(target.occupancy_epoch)
                    .fetch_one(&mut *tx)
                    .await?;
                    effects.push(json!({
                        "kind":"presence","target":target,
                        "snapshot":ClusterMucPolicySnapshot::from(&occupancy_from_row(&row)),
                        "status":status,"reason":reason,
                    }));
                }
            }
            Prepared::Role {
                target,
                role,
                reason,
            } => {
                let terminal = role == "none";
                let changed = sqlx::query(
                    "UPDATE cluster_muc_occupancies SET role=$9,
                       state=CASE WHEN $9='none' THEN 'revoked' ELSE state END,
                       lease_until=CASE WHEN $9='none' THEN clock_timestamp() ELSE lease_until END,
                       ended_at=CASE WHEN $9='none' THEN clock_timestamp() ELSE ended_at END,
                       updated_at=clock_timestamp()
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
                .bind(role)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                anyhow::ensure!(changed == 1, "exact MUC role target changed concurrently");
                let row = sqlx::query(
                    "SELECT * FROM cluster_muc_occupancies
                      WHERE room_id=$1 AND occupant_incarnation=$2 AND occupancy_epoch=$3",
                )
                .bind(target.room_id)
                .bind(target.occupant_incarnation)
                .bind(target.occupancy_epoch)
                .fetch_one(&mut *tx)
                .await?;
                effects.push(json!({
                    "kind":"presence","target":target,
                    "snapshot":ClusterMucPolicySnapshot::from(&occupancy_from_row(&row)),
                    "status":if terminal { Some(307_u16) } else { None },
                    "reason":reason,
                }));
            }
        }
    }
    let (_unused, event_sequence) = allocate_room_epochs(&mut tx, batch.room_id, false).await?;
    let authorization = json!({
        "actor":batch.actor,"actor_full_jid":actor_full_jid,
        "actor_target":actor_target,"durable_affiliation":actor_affiliation,
        "live_role":actor_current.role,"room_epoch":room.room_epoch,
        "config_version":room.config_version,
    });
    let details = json!({
        "non_anonymous":room.non_anonymous,
        "request_change_count":batch.changes.len(),
        "changes":effects,
    });
    insert_operation_and_outbox(
        &mut tx,
        OperationRecord {
            operation_id: batch.operation_id,
            room_id: batch.room_id,
            room_epoch: room.room_epoch,
            kind: "admin_batch",
            digest: &digest,
            actor_bare_jid: Some(batch.actor.bare_jid()),
            actor_full_jid: Some(&actor_full_jid),
            actor_affiliation: Some(&actor_affiliation),
            authorization_source: if matches!(batch.actor, ClusterMucPrincipal::Local { .. }) {
                "local_database"
            } else {
                "federated_verified"
            },
            authorization_snapshot: &authorization,
            target: None,
            config_version_before: room.config_version,
            config_version_after: room.config_version,
            event_sequence,
            event_id: batch.operation_id,
            audience: &audience,
            details: &details,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Outcome::Applied)
}
