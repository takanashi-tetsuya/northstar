//! Apply atomic affiliation batches and read authorized room administration snapshots.

use super::*;

/// Apply every affiliation item from one MUC admin IQ in one transaction.
///
/// XEP-0045 permits multiple `<item/>` children in an admin request.  Applying
/// them through the single-item helpers can otherwise expose a committed
/// prefix when a later item is invalid or would remove the final owner.  The
/// room advisory lock is shared with the single-item paths, so concurrent
/// local and federated administrators observe one serial order.
pub async fn set_muc_affiliations_batch(
    pool: &PgPool,
    room_id: Uuid,
    changes: &[MucAffiliationChange],
) -> Result<MucAffiliationBatchOutcome> {
    if changes.is_empty() {
        return Ok(MucAffiliationBatchOutcome::Applied);
    }

    enum ResolvedTarget {
        Local(Uuid),
        Federated(String),
    }
    struct ResolvedChange {
        target: ResolvedTarget,
        affiliation: String,
    }

    let mut transaction = pool.begin().await?;
    lock_muc_affiliation_namespace(&mut transaction, room_id).await?;

    let mut seen = std::collections::HashSet::with_capacity(changes.len());
    let mut resolved = Vec::with_capacity(changes.len());
    let mut owner_delta = 0_i64;
    for change in changes {
        anyhow::ensure!(
            matches!(
                change.affiliation.as_str(),
                "owner" | "admin" | "member" | "outcast" | "none"
            ),
            "invalid MUC affiliation in atomic batch"
        );
        let (key, target, current) = match &change.target {
            MucAffiliationTarget::LocalUsername(username) => {
                let user_id: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM users WHERE username=$1 AND NOT is_disabled",
                )
                .bind(username)
                .fetch_optional(&mut *transaction)
                .await?;
                let Some(user_id) = user_id else {
                    transaction.rollback().await?;
                    return Ok(MucAffiliationBatchOutcome::MissingTarget);
                };
                let name_matches: bool =
                    sqlx::query_scalar("SELECT northstar_lock_enabled_user_name($1,$2)")
                        .bind(user_id)
                        .bind(username)
                        .fetch_one(&mut *transaction)
                        .await?;
                if !name_matches {
                    transaction.rollback().await?;
                    return Ok(MucAffiliationBatchOutcome::MissingTarget);
                }
                let current: Option<String> = sqlx::query_scalar(
                    "SELECT affiliation FROM muc_affiliations
                      WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
                )
                .bind(room_id)
                .bind(user_id)
                .fetch_optional(&mut *transaction)
                .await?;
                (
                    format!("local:{user_id}"),
                    ResolvedTarget::Local(user_id),
                    current,
                )
            }
            MucAffiliationTarget::FederatedBareJid(jid) => {
                let jid = crate::jid::CanonicalJid::parse_bare(jid)?;
                anyhow::ensure!(
                    jid.localpart().is_some(),
                    "a federated MUC affiliation requires a user bare JID"
                );
                let jid = jid.to_string();
                let current: Option<String> = sqlx::query_scalar(
                    "SELECT affiliation FROM muc_external_affiliations
                      WHERE room_id=$1 AND jid=$2 FOR UPDATE",
                )
                .bind(room_id)
                .bind(&jid)
                .fetch_optional(&mut *transaction)
                .await?;
                (
                    format!("federated:{jid}"),
                    ResolvedTarget::Federated(jid),
                    current,
                )
            }
        };
        if !seen.insert(key) {
            transaction.rollback().await?;
            return Ok(MucAffiliationBatchOutcome::DuplicateTarget);
        }
        if current.as_deref() == Some("owner") && change.affiliation != "owner" {
            owner_delta -= 1;
        } else if current.as_deref() != Some("owner") && change.affiliation == "owner" {
            owner_delta += 1;
        }
        resolved.push(ResolvedChange {
            target,
            affiliation: change.affiliation.clone(),
        });
    }

    let owners: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM muc_affiliations
                  WHERE room_id=$1 AND affiliation='owner')
              + (SELECT COUNT(*) FROM muc_external_affiliations
                  WHERE room_id=$1 AND affiliation='owner')",
    )
    .bind(room_id)
    .fetch_one(&mut *transaction)
    .await?;
    if owners + owner_delta < 1 {
        transaction.rollback().await?;
        return Ok(MucAffiliationBatchOutcome::LastOwner);
    }

    for change in resolved {
        match change.target {
            ResolvedTarget::Local(user_id) => {
                if change.affiliation == "none" {
                    sqlx::query("DELETE FROM muc_affiliations WHERE room_id=$1 AND user_id=$2")
                        .bind(room_id)
                        .bind(user_id)
                        .execute(&mut *transaction)
                        .await?;
                } else {
                    sqlx::query(
                        "INSERT INTO muc_affiliations
                           (room_id, user_id, affiliation, updated_at)
                         VALUES ($1, $2, $3, NOW())
                         ON CONFLICT (room_id, user_id) DO UPDATE SET
                           affiliation = EXCLUDED.affiliation,
                           reserved_nick = CASE WHEN EXCLUDED.affiliation='outcast'
                                                THEN NULL ELSE muc_affiliations.reserved_nick END,
                           updated_at = NOW()",
                    )
                    .bind(room_id)
                    .bind(user_id)
                    .bind(&change.affiliation)
                    .execute(&mut *transaction)
                    .await?;
                }
            }
            ResolvedTarget::Federated(jid) => {
                if change.affiliation == "none" {
                    sqlx::query(
                        "DELETE FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2",
                    )
                    .bind(room_id)
                    .bind(&jid)
                    .execute(&mut *transaction)
                    .await?;
                } else {
                    sqlx::query(
                        "INSERT INTO muc_external_affiliations
                           (room_id, jid, affiliation, updated_at)
                         VALUES ($1, $2, $3, NOW())
                         ON CONFLICT (room_id, jid) DO UPDATE SET
                           affiliation = EXCLUDED.affiliation,
                           reserved_nick = CASE WHEN EXCLUDED.affiliation='outcast'
                                                THEN NULL ELSE muc_external_affiliations.reserved_nick END,
                           updated_at = NOW()",
                    )
                    .bind(room_id)
                    .bind(&jid)
                    .bind(&change.affiliation)
                    .execute(&mut *transaction)
                    .await?;
                }
            }
        }
    }
    transaction.commit().await?;
    Ok(MucAffiliationBatchOutcome::Applied)
}

pub(super) enum LocalAdminPrincipalCheck {
    Authorized {
        members_only: bool,
        non_anonymous: bool,
    },
    Unauthorized,
    Stale,
}

pub(super) async fn lock_local_admin_principal(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    user_id: Uuid,
    actor_scope: &str,
    local_domain: &str,
) -> Result<LocalAdminPrincipalCheck> {
    let local_domain = crate::jid::prepare_domainpart(local_domain)?;
    // Namespace 29 precedes every room/affiliation row lock.  See
    // `lock_muc_actor_authority` for the global writer lock order.
    lock_muc_affiliation_namespace(transaction, room_id).await?;
    let room = sqlx::query(
        "SELECT room_epoch,members_only,non_anonymous,destroyed_at,configuration_state
           FROM muc_rooms WHERE id=$1 FOR UPDATE",
    )
    .bind(room_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(room) = room else {
        return Ok(LocalAdminPrincipalCheck::Stale);
    };
    if room
        .get::<Option<DateTime<Utc>>, _>("destroyed_at")
        .is_some()
        || room.get::<String, _>("configuration_state") != "active"
        || room.get::<Uuid, _>("room_epoch") != expected_room_epoch
    {
        return Ok(LocalAdminPrincipalCheck::Stale);
    }
    let actor = crate::jid::CanonicalJid::parse_bare(actor_scope)?;
    let name_matches: bool = sqlx::query_scalar("SELECT northstar_lock_enabled_user_name($1,$2)")
        .bind(user_id)
        .bind(actor.localpart().unwrap_or_default())
        .fetch_one(&mut **transaction)
        .await?;
    if !name_matches
        || actor.domainpart() != local_domain
        || actor.resourcepart().is_some()
        || actor.to_string() != actor_scope
    {
        return Ok(LocalAdminPrincipalCheck::Unauthorized);
    }
    Ok(LocalAdminPrincipalCheck::Authorized {
        members_only: room.get("members_only"),
        non_anonymous: room.get("non_anonymous"),
    })
}

pub(super) async fn lock_local_admin_affiliation(
    transaction: &mut Transaction<'_, Postgres>,
    room_id: Uuid,
    user_id: Uuid,
) -> Result<String> {
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations
          WHERE room_id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(room_id)
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(affiliation.unwrap_or_else(|| "none".to_owned()))
}

#[allow(clippy::too_many_arguments)]
pub async fn authorized_muc_admin_role_list(
    pool: &PgPool,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    user_id: Uuid,
    actor_scope: &str,
    local_domain: &str,
    asserted_local_role: &str,
    actor_target: Option<&super::super::cluster_muc::ClusterMucOccupancyTarget>,
    clustered: bool,
    requested_role: &str,
) -> Result<MucAdminSnapshot<MucAdminRoleList>> {
    anyhow::ensure!(
        matches!(requested_role, "moderator" | "participant" | "visitor"),
        "invalid MUC admin role list"
    );
    anyhow::ensure!(
        matches!(
            asserted_local_role,
            "moderator" | "participant" | "visitor" | "none"
        ),
        "invalid asserted MUC requester role"
    );
    let actor_scope = canonical_history_actor(actor_scope)?;
    let mut transaction = pool.begin().await?;
    #[cfg(test)]
    maybe_pause_muc_authorization_for_test("admin_role").await;
    let non_anonymous = match lock_local_admin_principal(
        &mut transaction,
        room_id,
        expected_room_epoch,
        user_id,
        &actor_scope,
        local_domain,
    )
    .await?
    {
        LocalAdminPrincipalCheck::Authorized { non_anonymous, .. } => non_anonymous,
        LocalAdminPrincipalCheck::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MucAdminSnapshot::Unauthorized);
        }
        LocalAdminPrincipalCheck::Stale => {
            transaction.rollback().await?;
            return Ok(MucAdminSnapshot::Stale);
        }
    };

    let clustered_actor = if clustered {
        if let Some(target) = actor_target {
            if target.room_id != room_id || target.room_epoch != expected_room_epoch {
                transaction.rollback().await?;
                return Ok(MucAdminSnapshot::Unauthorized);
            }
            let row = sqlx::query(
                "SELECT role,affiliation FROM cluster_muc_occupancies
                  WHERE room_id=$1 AND room_epoch=$2 AND occupant_incarnation=$3
                    AND occupancy_epoch=$4 AND full_jid=$5 AND nick=$6
                    AND connection_uuid=$7 AND connection_epoch=$8
                    AND identity_kind='local' AND local_user_id=$9
                    AND bare_jid=$10 AND state='active'
                    AND lease_until>clock_timestamp() FOR UPDATE",
            )
            .bind(target.room_id)
            .bind(target.room_epoch)
            .bind(target.occupant_incarnation)
            .bind(target.occupancy_epoch)
            .bind(&target.full_jid)
            .bind(&target.nick)
            .bind(target.connection_uuid)
            .bind(target.connection_epoch)
            .bind(user_id)
            .bind(&actor_scope)
            .fetch_optional(&mut *transaction)
            .await?;
            row.map(|row| {
                (
                    row.get::<String, _>("role"),
                    row.get::<String, _>("affiliation"),
                )
            })
        } else {
            None
        }
    } else {
        None
    };
    let affiliation = lock_local_admin_affiliation(&mut transaction, room_id, user_id).await?;
    let requester_role = if clustered {
        match clustered_actor {
            Some((role, occupancy_affiliation)) => {
                if occupancy_affiliation != affiliation {
                    transaction.rollback().await?;
                    return Ok(MucAdminSnapshot::Unauthorized);
                }
                role
            }
            // Owners/admins may issue admin IQs without joining the room.  A
            // missing asserted target is therefore represented by role=none;
            // a supplied-but-stale target remains fail closed.
            None if actor_target.is_none() => "none".to_owned(),
            None => {
                transaction.rollback().await?;
                return Ok(MucAdminSnapshot::Unauthorized);
            }
        }
    } else {
        asserted_local_role.to_owned()
    };
    if affiliation == "outcast" {
        transaction.rollback().await?;
        return Ok(MucAdminSnapshot::Unauthorized);
    }
    if requester_role != "moderator" && !matches!(affiliation.as_str(), "owner" | "admin") {
        transaction.rollback().await?;
        return Ok(MucAdminSnapshot::Unauthorized);
    }

    let entries = if clustered {
        sqlx::query(
            "SELECT nick,role,bare_jid FROM cluster_muc_occupancies
              WHERE room_id=$1 AND room_epoch=$2 AND role=$3
                AND state IN ('active','suspended')
                AND lease_until>clock_timestamp()
              ORDER BY nick,occupancy_epoch FOR SHARE",
        )
        .bind(room_id)
        .bind(expected_room_epoch)
        .bind(requested_role)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| MucAdminRoleEntry {
            nick: row.get("nick"),
            role: row.get("role"),
            bare_jid: row.get("bare_jid"),
        })
        .collect()
    } else {
        Vec::new()
    };
    transaction.commit().await?;
    Ok(MucAdminSnapshot::Authorized(MucAdminRoleList {
        requester_role,
        non_anonymous,
        entries,
    }))
}

pub async fn authorized_muc_admin_affiliation_list(
    pool: &PgPool,
    room_id: Uuid,
    expected_room_epoch: Uuid,
    user_id: Uuid,
    actor_scope: &str,
    requested_affiliation: &str,
    local_domain: &str,
) -> Result<MucAdminSnapshot<Vec<MucAdminAffiliationEntry>>> {
    anyhow::ensure!(
        matches!(
            requested_affiliation,
            "owner" | "admin" | "member" | "outcast"
        ),
        "invalid MUC admin affiliation list"
    );
    let local_domain = crate::jid::prepare_domainpart(local_domain)?;
    let actor_scope = canonical_history_actor(actor_scope)?;
    let mut transaction = pool.begin().await?;
    #[cfg(test)]
    maybe_pause_muc_authorization_for_test("admin_affiliation").await;
    let (members_only, non_anonymous) = match lock_local_admin_principal(
        &mut transaction,
        room_id,
        expected_room_epoch,
        user_id,
        &actor_scope,
        &local_domain,
    )
    .await?
    {
        LocalAdminPrincipalCheck::Authorized {
            members_only,
            non_anonymous,
        } => (members_only, non_anonymous),
        LocalAdminPrincipalCheck::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MucAdminSnapshot::Unauthorized);
        }
        LocalAdminPrincipalCheck::Stale => {
            transaction.rollback().await?;
            return Ok(MucAdminSnapshot::Stale);
        }
    };
    let requester_affiliation =
        lock_local_admin_affiliation(&mut transaction, room_id, user_id).await?;
    let authorized = matches!(requester_affiliation.as_str(), "owner" | "admin")
        || (requester_affiliation == "member"
            && members_only
            && non_anonymous
            && matches!(requested_affiliation, "owner" | "admin" | "member"));
    if !authorized {
        transaction.rollback().await?;
        return Ok(MucAdminSnapshot::Unauthorized);
    }
    let mut entries = sqlx::query(
        "SELECT users.username FROM muc_affiliations affiliation
          JOIN users ON users.id=affiliation.user_id
         WHERE affiliation.room_id=$1 AND affiliation.affiliation=$2
         ORDER BY users.username FOR SHARE OF affiliation",
    )
    .bind(room_id)
    .bind(requested_affiliation)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|row| MucAdminAffiliationEntry {
        bare_jid: format!("{}@{}", row.get::<String, _>("username"), local_domain),
        affiliation: requested_affiliation.to_owned(),
    })
    .collect::<Vec<_>>();
    entries.extend(
        sqlx::query(
            "SELECT jid FROM muc_external_affiliations
              WHERE room_id=$1 AND affiliation=$2 ORDER BY jid FOR SHARE",
        )
        .bind(room_id)
        .bind(requested_affiliation)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| MucAdminAffiliationEntry {
            bare_jid: row.get("jid"),
            affiliation: requested_affiliation.to_owned(),
        }),
    );
    transaction.commit().await?;
    Ok(MucAdminSnapshot::Authorized(entries))
}

pub async fn get_federated_muc_affiliations(
    pool: &PgPool,
    room_id: Uuid,
    affiliation: &str,
) -> Result<Vec<String>> {
    sqlx::query_scalar(
        "SELECT jid FROM muc_external_affiliations WHERE room_id = $1 AND affiliation = $2 ORDER BY jid",
    )
    .bind(room_id)
    .bind(affiliation)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

pub async fn get_muc_affiliations(
    pool: &PgPool,
    room_id: Uuid,
    affiliation: &str,
) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT u.username FROM muc_affiliations a JOIN users u ON a.user_id = u.id WHERE a.room_id = $1 AND a.affiliation = $2",
    )
    .bind(room_id)
    .bind(affiliation)
    .fetch_all(pool)
    .await?;
    let mut usernames = Vec::with_capacity(rows.len());
    for row in rows {
        usernames.push(row.get::<String, _>("username"));
    }
    Ok(usernames)
}
