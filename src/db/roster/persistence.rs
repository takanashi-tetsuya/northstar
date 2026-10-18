//! Read and mutate roster items, clean up dependent PEP authorization, and persist versioned change-journal snapshots.

use super::*;

pub(super) async fn begin_authorized_roster_mutation<'a>(
    pool: &'a PgPool,
    owner_id: Uuid,
    expected_auth_generation: i64,
) -> Result<Option<Transaction<'a, Postgres>>> {
    let mut transaction = pool.begin().await?;
    let eligible = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled FOR UPDATE",
    )
    .bind(owner_id)
    .bind(expected_auth_generation)
    .fetch_optional(&mut *transaction)
    .await?;
    if eligible.is_none() {
        transaction.rollback().await?;
        return Ok(None);
    }
    Ok(Some(transaction))
}

pub async fn roster(
    pool: &PgPool,
    owner_id: Uuid,
) -> Result<Vec<(String, Option<String>, String, Option<String>)>> {
    let rows = sqlx::query("SELECT contact_jid, display_name, subscription, ask FROM roster_items WHERE owner_id = $1 ORDER BY contact_jid")
        .bind(owner_id).fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get("contact_jid"),
                r.get("display_name"),
                r.get("subscription"),
                r.get("ask"),
            )
        })
        .collect())
}

pub async fn roster_item(
    pool: &PgPool,
    owner_id: Uuid,
    jid: &str,
) -> Result<Option<(String, Option<String>, String, Option<String>)>> {
    let jid = crate::jid::canonicalize_bare(jid)?;
    let row = sqlx::query(
        "SELECT contact_jid, display_name, subscription, ask FROM roster_items WHERE owner_id = $1 AND contact_jid = $2",
    )
    .bind(owner_id)
    .bind(&jid)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        (
            row.get("contact_jid"),
            row.get("display_name"),
            row.get("subscription"),
            row.get("ask"),
        )
    }))
}

/// Apply a client-originated roster mutation only while the exact
/// authenticated credential generation remains enabled. The shared owner-row
/// lock serializes this commit against password changes and administrative
/// disablement.
pub async fn upsert_roster_authorized(
    pool: &PgPool,
    owner_id: Uuid,
    expected_auth_generation: i64,
    jid: &str,
    name: Option<&str>,
    groups: &[String],
) -> Result<Option<RosterChange>> {
    let Some(mut transaction) =
        begin_authorized_roster_mutation(pool, owner_id, expected_auth_generation).await?
    else {
        return Ok(None);
    };
    let change =
        upsert_roster_in_transaction(&mut transaction, owner_id, jid, name, groups).await?;
    transaction.commit().await?;
    Ok(Some(change))
}

pub(super) async fn upsert_roster_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    jid: &str,
    name: Option<&str>,
    groups: &[String],
) -> Result<RosterChange> {
    let jid = crate::jid::canonicalize_bare(jid)?;
    sqlx::query("INSERT INTO roster_items (owner_id, contact_jid, display_name, groups) VALUES ($1, $2, $3, $4) ON CONFLICT (owner_id, contact_jid) DO UPDATE SET display_name = EXCLUDED.display_name, groups = EXCLUDED.groups, updated_at = NOW()")
        .bind(owner_id).bind(&jid).bind(name).bind(serde_json::to_value(groups)?).execute(&mut **transaction).await?;
    cancel_inaccessible_pep_subscriptions(transaction, owner_id, &jid).await?;
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(owner_id)
        .fetch_one(&mut **transaction)
        .await?;
    record_roster_change(transaction, owner_id, version, &jid, false).await
}

pub async fn remove_roster_item_authorized(
    pool: &PgPool,
    owner_id: Uuid,
    expected_auth_generation: i64,
    jid: &str,
    route: RosterRemovalRoute<'_>,
) -> Result<AuthorizedRosterRemoval> {
    let transaction = pool.begin().await?;
    remove_roster_item_in_transaction(
        transaction,
        owner_id,
        Some(expected_auth_generation),
        jid,
        route,
    )
    .await
}

pub(super) async fn remove_roster_item_in_transaction(
    mut transaction: Transaction<'_, Postgres>,
    owner_id: Uuid,
    expected_auth_generation: Option<i64>,
    jid: &str,
    route: RosterRemovalRoute<'_>,
) -> Result<AuthorizedRosterRemoval> {
    let jid = crate::jid::canonicalize_bare(jid)?;

    // Resolve the local account incarnation inside the same transaction which
    // locks and mutates both rosters. The protocol layer must not perform a
    // pre-transaction username lookup which can be invalidated by
    // delete/recreate before commit.
    let local_contact_candidate = match route {
        RosterRemovalRoute::Local {
            contact_username: Some(username),
            ..
        } => sqlx::query("SELECT id,username,auth_generation FROM users WHERE username=$1")
            .bind(username)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| {
                Ok::<_, sqlx::Error>(LocalRosterContact {
                    id: row.try_get("id")?,
                    username: row.try_get("username")?,
                    auth_generation: row.try_get("auth_generation")?,
                })
            })
            .transpose()?,
        RosterRemovalRoute::Local {
            contact_username: None,
            ..
        }
        | RosterRemovalRoute::Remote { .. } => None,
    };
    let mut lock_ids = vec![owner_id];
    if let Some(contact) = local_contact_candidate
        .as_ref()
        .filter(|contact| contact.id != owner_id)
    {
        lock_ids.push(contact.id);
        lock_ids.sort_unstable();
    }
    let locked = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE",
    )
    .bind(&lock_ids)
    .fetch_all(&mut *transaction)
    .await?;
    if !locked.contains(&owner_id) {
        transaction.rollback().await?;
        return Ok(AuthorizedRosterRemoval::Missing);
    }
    if let Some(expected_auth_generation) = expected_auth_generation {
        let authorized = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled)",
        )
        .bind(owner_id)
        .bind(expected_auth_generation)
        .fetch_one(&mut *transaction)
        .await?;
        if !authorized {
            transaction.rollback().await?;
            return Ok(AuthorizedRosterRemoval::Unauthorized);
        }
    }
    let local_contact = if let Some(candidate) =
        local_contact_candidate.filter(|contact| locked.contains(&contact.id))
    {
        sqlx::query(
            "SELECT id,username,auth_generation FROM users
              WHERE id=$1 AND username=$2 AND NOT is_disabled",
        )
        .bind(candidate.id)
        .bind(&candidate.username)
        .fetch_optional(&mut *transaction)
        .await?
        .map(|row| LocalRosterContact {
            id: row.get("id"),
            username: row.get("username"),
            auth_generation: row.get("auth_generation"),
        })
    } else {
        None
    };

    let owner_row = sqlx::query(
        "SELECT subscription,ask FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
    )
    .bind(owner_id)
    .bind(&jid)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(owner_row) = owner_row else {
        transaction.commit().await?;
        return Ok(AuthorizedRosterRemoval::Missing);
    };
    let owner_subscription: String = owner_row.try_get("subscription")?;
    let owner_ask: Option<String> = owner_row.try_get("ask")?;

    let (pending_outbound, pending_inbound) = match (&route, local_contact.as_ref()) {
        (RosterRemovalRoute::Local { .. }, Some(contact)) if contact.id != owner_id => {
            let pending_outbound = sqlx::query_scalar::<_, i32>(
                "SELECT 1 FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2 FOR UPDATE",
            )
            .bind(owner_id)
            .bind(contact.id)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
            let pending_inbound = sqlx::query_scalar::<_, i32>(
                "SELECT 1 FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2 FOR UPDATE",
            )
            .bind(contact.id)
            .bind(owner_id)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
            (pending_outbound, pending_inbound)
        }
        (RosterRemovalRoute::Remote { .. }, _) => {
            let pending_inbound = sqlx::query_scalar::<_, i32>(
                "SELECT 1 FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2 FOR UPDATE",
            )
            .bind(owner_id)
            .bind(&jid)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
            (owner_ask.as_deref() == Some("subscribe"), pending_inbound)
        }
        _ => (owner_ask.as_deref() == Some("subscribe"), false),
    };
    let send_unsubscribe = matches!(owner_subscription.as_str(), "to" | "both")
        || owner_ask.as_deref() == Some("subscribe")
        || pending_outbound;
    let send_unsubscribed =
        matches!(owner_subscription.as_str(), "from" | "both") || pending_inbound;

    let mut contact_change = None;
    if let (RosterRemovalRoute::Local { owner_jid, .. }, Some(contact)) =
        (route, local_contact.as_ref())
    {
        let contact_id = contact.id;
        if contact_id != owner_id && locked.contains(&contact_id) {
            let owner_jid = crate::jid::canonicalize_bare(owner_jid)?;
            let contact_row = sqlx::query(
                "SELECT subscription,ask,approved FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
            )
            .bind(contact_id)
            .bind(&owner_jid)
            .fetch_optional(&mut *transaction)
            .await?;
            let contact_subscription = contact_row
                .as_ref()
                .map(|row| row.try_get::<String, _>("subscription"))
                .transpose()?
                .unwrap_or_else(|| "none".to_owned());
            let contact_ask = contact_row
                .as_ref()
                .map(|row| row.try_get::<Option<String>, _>("ask"))
                .transpose()?
                .flatten();
            let contact_approved = contact_row
                .as_ref()
                .map(|row| row.try_get::<bool, _>("approved"))
                .transpose()?
                .unwrap_or(false);
            let mut next_subscription = contact_subscription.clone();
            let mut next_ask = contact_ask.clone();
            if send_unsubscribe {
                next_subscription =
                    remove_subscription_direction(&next_subscription, "from").to_owned();
            }
            if send_unsubscribed {
                next_subscription =
                    remove_subscription_direction(&next_subscription, "to").to_owned();
                next_ask = None;
            }
            let changed = contact_row.as_ref().is_some_and(|_| {
                next_subscription != contact_subscription || next_ask != contact_ask
            });
            if changed {
                contact_change = Some(
                    update_subscription_in_transaction(
                        &mut transaction,
                        contact_id,
                        &owner_jid,
                        &next_subscription,
                        next_ask.as_deref(),
                        Some(contact_approved),
                    )
                    .await?,
                );
            }
            if send_unsubscribe {
                sqlx::query(
                    "DELETE FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2",
                )
                .bind(owner_id)
                .bind(contact_id)
                .execute(&mut *transaction)
                .await?;
            }
            if send_unsubscribed {
                sqlx::query(
                    "DELETE FROM pending_presence_subscriptions WHERE requester_id=$1 AND recipient_id=$2",
                )
                .bind(contact_id)
                .bind(owner_id)
                .execute(&mut *transaction)
                .await?;
            }
        }
    }

    if let RosterRemovalRoute::Remote {
        target_domain,
        unsubscribe_stanza,
        unsubscribed_stanza,
        bounce_to,
        policy,
    } = route
    {
        if send_unsubscribe {
            super::super::enqueue_s2s_outbox_in_transaction(
                &mut transaction,
                target_domain,
                unsubscribe_stanza,
                bounce_to,
                policy,
            )
            .await?;
        }
        if send_unsubscribed {
            super::super::enqueue_s2s_outbox_in_transaction(
                &mut transaction,
                target_domain,
                unsubscribed_stanza,
                bounce_to,
                policy,
            )
            .await?;
            sqlx::query(
                "DELETE FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid=$2",
            )
            .bind(owner_id)
            .bind(&jid)
            .execute(&mut *transaction)
            .await?;
        }
    }

    sqlx::query("DELETE FROM roster_items WHERE owner_id=$1 AND contact_jid=$2")
        .bind(owner_id)
        .bind(&jid)
        .execute(&mut *transaction)
        .await?;
    cancel_inaccessible_pep_subscriptions(&mut transaction, owner_id, &jid).await?;
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(owner_id)
        .fetch_one(&mut *transaction)
        .await?;
    let owner_change =
        record_roster_change(&mut transaction, owner_id, version, &jid, true).await?;
    transaction.commit().await?;
    Ok(AuthorizedRosterRemoval::Removed(Box::new(
        RosterRemovalTransition {
            owner_change,
            contact_change,
            local_contact,
            send_unsubscribe,
            send_unsubscribed,
        },
    )))
}

pub(in crate::db) async fn update_subscription_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    jid: &str,
    subscription: &str,
    ask: Option<&str>,
    approved: Option<bool>,
) -> Result<RosterChange> {
    let jid = crate::jid::canonicalize_bare(jid)?;
    sqlx::query("INSERT INTO roster_items (owner_id, contact_jid, subscription, ask, approved) VALUES ($1, $2, $3, $4, COALESCE($5, FALSE)) ON CONFLICT (owner_id, contact_jid) DO UPDATE SET subscription = $3, ask = $4, approved = COALESCE($5, roster_items.approved), updated_at = NOW()")
        .bind(owner_id)
        .bind(&jid)
        .bind(subscription)
        .bind(ask)
        .bind(approved)
        .execute(&mut **transaction)
        .await?;
    cancel_inaccessible_pep_subscriptions(transaction, owner_id, &jid).await?;
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(owner_id)
        .fetch_one(&mut **transaction)
        .await?;
    record_roster_change(transaction, owner_id, version, &jid, false).await
}

/// XEP-0163 section 7.1 requires a PEP service to cancel explicit
/// subscriptions when a presence subscription or roster group change removes
/// the subscriber's access. Keeping this in the roster transaction prevents a
/// committed roster state from retaining stale durable authorization.
pub(super) async fn cancel_inaccessible_pep_subscriptions(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    contact_jid: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM pep_subscriptions ps USING pep_nodes pn
         WHERE ps.owner_id=$1
           AND split_part(ps.subscriber_jid, '/', 1)=$2
           AND pn.owner_id=ps.owner_id
           AND pn.node=ps.node
           AND (
             (pn.access_model='presence' AND NOT EXISTS (
                SELECT 1 FROM roster_items r
                 WHERE r.owner_id=$1 AND r.contact_jid=$2
                   AND r.subscription IN ('from','both')
             ))
             OR
             (pn.access_model='roster' AND NOT EXISTS (
                SELECT 1 FROM roster_items r,
                     jsonb_array_elements_text(r.groups) AS g(name)
                 WHERE r.owner_id=$1 AND r.contact_jid=$2
                   AND r.subscription IN ('from','both')
                   AND g.name=ANY(pn.roster_groups_allowed)
             ))
           )",
    )
    .bind(owner_id)
    .bind(contact_jid)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(in crate::db) async fn record_roster_change(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner_id: Uuid,
    version: i64,
    jid: &str,
    removed: bool,
) -> Result<RosterChange> {
    let jid = crate::jid::canonicalize_bare(jid)?;
    if removed {
        sqlx::query("INSERT INTO roster_change_log (owner_id, version, contact_jid, removed) VALUES ($1, $2, $3, TRUE)")
            .bind(owner_id).bind(version).bind(&jid).execute(&mut **transaction).await?;
    } else {
        sqlx::query("INSERT INTO roster_change_log (owner_id, version, contact_jid, display_name, subscription, ask, groups, approved, removed) SELECT owner_id, $3, contact_jid, display_name, subscription, ask, groups, approved, FALSE FROM roster_items WHERE owner_id = $1 AND contact_jid = $2")
            .bind(owner_id).bind(&jid).bind(version).execute(&mut **transaction).await?;
    }
    sqlx::query("DELETE FROM roster_change_log WHERE owner_id = $1 AND version <= $2 - 10000")
        .bind(owner_id)
        .bind(version)
        .execute(&mut **transaction)
        .await?;
    let row = sqlx::query(
        "SELECT version, contact_jid, display_name, subscription, ask, groups, approved, removed FROM roster_change_log WHERE owner_id=$1 AND version=$2",
    )
    .bind(owner_id)
    .bind(version)
    .fetch_one(&mut **transaction)
    .await?;
    roster_change_from_row(&row)
}

pub(super) fn roster_change_from_row(row: &sqlx::postgres::PgRow) -> Result<RosterChange> {
    Ok(RosterChange {
        version: row.try_get("version")?,
        contact_jid: row.try_get("contact_jid")?,
        display_name: row.try_get("display_name")?,
        subscription: row.try_get("subscription")?,
        ask: row.try_get("ask")?,
        groups: serde_json::from_value(row.try_get("groups")?)?,
        approved: row.try_get("approved")?,
        removed: row.try_get("removed")?,
    })
}

pub(super) async fn roster_changes_since_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    requested_version: i64,
    current_version: i64,
) -> Result<Option<Vec<RosterChange>>> {
    if requested_version < 0 || requested_version > current_version {
        return Ok(None);
    }
    if requested_version == current_version {
        return Ok(Some(Vec::new()));
    }
    let earliest: Option<i64> =
        sqlx::query_scalar("SELECT MIN(version) FROM roster_change_log WHERE owner_id = $1")
            .bind(owner_id)
            .fetch_one(&mut **transaction)
            .await?;
    if earliest.is_none_or(|version| requested_version < version - 1) {
        return Ok(None);
    }
    let rows = sqlx::query(
        "SELECT version, contact_jid, display_name, subscription, ask, groups, approved, removed FROM (SELECT DISTINCT ON (contact_jid) version, contact_jid, display_name, subscription, ask, groups, approved, removed FROM roster_change_log WHERE owner_id=$1 AND version>$2 AND version<=$3 ORDER BY contact_jid, version DESC) latest ORDER BY version",
    )
    .bind(owner_id)
    .bind(requested_version)
    .bind(current_version)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(Some(
        rows.iter()
            .map(roster_change_from_row)
            .collect::<Result<Vec<_>>>()?,
    ))
}

/// Reads the newest immutable journal snapshot for integration paths whose
/// surrounding transaction is owned by another database module (currently
/// remote MIX/PAM completion and administrative MIX removals).
pub async fn latest_roster_change_for_contact(
    pool: &PgPool,
    owner_id: Uuid,
    contact_jid: &str,
) -> Result<Option<RosterChange>> {
    let contact_jid = crate::jid::canonicalize_bare(contact_jid)?;
    let row = sqlx::query(
        "SELECT version, contact_jid, display_name, subscription, ask, groups, approved, removed FROM roster_change_log WHERE owner_id=$1 AND contact_jid=$2 ORDER BY version DESC LIMIT 1",
    )
    .bind(owner_id)
    .bind(contact_jid)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(roster_change_from_row).transpose()
}
