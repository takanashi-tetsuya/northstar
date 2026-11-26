use super::*;

pub async fn record_roster_change(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner_id: Uuid,
    version: i64,
    jid: &str,
    removed: bool,
) -> Result<RosterChange> {
    let jid = northstar_xmpp_types::jid::canonicalize_bare(jid)?;
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

pub fn roster_change_from_row(row: &sqlx::postgres::PgRow) -> Result<RosterChange> {
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

pub async fn roster_changes_since_in_transaction(
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
    let contact_jid = northstar_xmpp_types::jid::canonicalize_bare(contact_jid)?;
    let row = sqlx::query(
        "SELECT version, contact_jid, display_name, subscription, ask, groups, approved, removed FROM roster_change_log WHERE owner_id=$1 AND contact_jid=$2 ORDER BY version DESC LIMIT 1",
    )
    .bind(owner_id)
    .bind(contact_jid)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(roster_change_from_row).transpose()
}
