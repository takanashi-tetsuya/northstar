//! Read and mutate roster items, clean up dependent PEP authorization, and persist versioned change-journal snapshots.

use super::*;

mod journal;
mod removal;

pub use self::journal::{
    latest_roster_change_for_contact, read_roster_gap, record_roster_change,
    roster_change_from_row, roster_changes_since_in_transaction, RosterGapAnnotationProof,
};
pub use self::removal::{remove_roster_item_authorized, remove_roster_item_in_transaction};

pub async fn begin_authorized_roster_mutation<'a>(
    pool: &'a PgPool,
    owner_id: Uuid,
    expected_auth_generation: i64,
) -> Result<Option<Transaction<'a, Postgres>>> {
    let mut transaction = pool.begin().await?;
    // The runtime role has no UPDATE on users, so the exclusive account lock
    // goes through the reviewed row-lock capability.
    let eligible = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM northstar_lock_user_rows_update(ARRAY[$1::uuid]) locked
          WHERE locked.auth_generation=$2 AND NOT locked.is_disabled",
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
    roster_page_after(pool, owner_id, None, i64::MAX).await
}

/// Lists roster entries in contact order on the supplied read connection.
pub async fn roster_page_after<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<(String, Option<String>, String, Option<String>)>> {
    let rows = sqlx::query(
        "SELECT contact_jid, display_name, subscription, ask FROM roster_items
         WHERE owner_id = $1 AND ($2::text IS NULL OR contact_jid > $2)
         ORDER BY contact_jid LIMIT $3",
    )
    .bind(owner_id)
    .bind(after)
    .bind(limit)
    .fetch_all(executor)
    .await?;
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

pub async fn roster_item<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    jid: &str,
) -> Result<Option<(String, Option<String>, String, Option<String>)>> {
    let jid = northstar_xmpp_types::jid::canonicalize_bare(jid)?;
    let row = sqlx::query(
        "SELECT contact_jid, display_name, subscription, ask FROM roster_items WHERE owner_id = $1 AND contact_jid = $2",
    )
    .bind(owner_id)
    .bind(&jid)
    .fetch_optional(executor)
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
pub async fn upsert_roster_authorized<E: RosterTransactionEffects>(
    effects: &E,
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
    let mut change =
        upsert_roster_in_transaction(effects, &mut transaction, owner_id, jid, name, groups)
            .await?;
    change.owner_authority = Some((owner_id, expected_auth_generation));
    transaction.commit().await?;
    Ok(Some(change))
}

pub async fn upsert_roster_in_transaction<E: RosterTransactionEffects>(
    effects: &E,
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    jid: &str,
    name: Option<&str>,
    groups: &[String],
) -> Result<RosterChange> {
    let jid = northstar_xmpp_types::jid::canonicalize_bare(jid)?;
    sqlx::query("INSERT INTO roster_items (owner_id, contact_jid, display_name, groups) VALUES ($1, $2, $3, $4) ON CONFLICT (owner_id, contact_jid) DO UPDATE SET display_name = EXCLUDED.display_name, groups = EXCLUDED.groups, updated_at = NOW()")
        .bind(owner_id).bind(&jid).bind(name).bind(serde_json::to_value(groups)?).execute(&mut **transaction).await?;
    effects
        .cancel_inaccessible_pep_subscriptions(transaction, owner_id, &jid)
        .await?;
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(owner_id)
        .fetch_one(&mut **transaction)
        .await?;
    record_roster_change(transaction, owner_id, version, &jid, false).await
}

pub async fn update_subscription_in_transaction<E: RosterTransactionEffects>(
    effects: &E,
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    jid: &str,
    subscription: &str,
    ask: Option<&str>,
    approved: Option<bool>,
) -> Result<RosterChange> {
    let jid = northstar_xmpp_types::jid::canonicalize_bare(jid)?;
    sqlx::query("INSERT INTO roster_items (owner_id, contact_jid, subscription, ask, approved) VALUES ($1, $2, $3, $4, COALESCE($5, FALSE)) ON CONFLICT (owner_id, contact_jid) DO UPDATE SET subscription = $3, ask = $4, approved = COALESCE($5, roster_items.approved), updated_at = NOW()")
        .bind(owner_id)
        .bind(&jid)
        .bind(subscription)
        .bind(ask)
        .bind(approved)
        .execute(&mut **transaction)
        .await?;
    effects
        .cancel_inaccessible_pep_subscriptions(transaction, owner_id, &jid)
        .await?;
    let version: i64 = sqlx::query_scalar("SELECT northstar_user_bump_roster_version($1)")
        .bind(owner_id)
        .fetch_one(&mut **transaction)
        .await?;
    record_roster_change(transaction, owner_id, version, &jid, false).await
}
