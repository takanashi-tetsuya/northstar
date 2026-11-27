use super::*;
use northstar_roster_core::RosterGap;

mod annotation_proof;

pub use self::annotation_proof::RosterGapAnnotationProof;

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
        "SELECT log.version, log.contact_jid, log.display_name, log.subscription, log.ask,
                log.groups, log.approved, log.removed, owner.auth_generation
           FROM roster_change_log log JOIN users owner ON owner.id=log.owner_id
          WHERE log.owner_id=$1 AND log.version=$2",
    )
    .bind(owner_id)
    .bind(version)
    .fetch_one(&mut **transaction)
    .await?;
    let mut change = roster_change_from_row(&row)?;
    change.owner_authority = Some((owner_id, row.try_get("auth_generation")?));
    Ok(change)
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
        owner_authority: None,
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
    let changes = read_journal_range(
        transaction,
        owner_id,
        requested_version,
        current_version,
        false,
    )
    .await?;
    Ok(Some(changes))
}

async fn read_journal_range(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    after: i64,
    through: i64,
    version_complete: bool,
) -> Result<Vec<RosterChange>> {
    let rows = sqlx::query(
        "SELECT version, contact_jid, display_name, subscription, ask, groups, approved, removed
           FROM (SELECT DISTINCT ON (contact_jid, CASE WHEN $4 THEN version END)
                        version, contact_jid, display_name, subscription, ask, groups, approved, removed
                   FROM roster_change_log WHERE owner_id=$1 AND version>$2 AND version<=$3
                  ORDER BY contact_jid, CASE WHEN $4 THEN version END, version DESC) latest
          ORDER BY version",
    )
    .bind(owner_id)
    .bind(after)
    .bind(through)
    .bind(version_complete)
    .fetch_all(&mut **transaction)
    .await?;
    rows.iter().map(roster_change_from_row).collect()
}

/// Prove every version in a bounded push gap using one read-only snapshot.
pub async fn read_roster_gap(
    effects: &impl RosterGapAnnotationProof,
    pool: &PgPool,
    (owner_id, auth_generation): (Uuid, i64),
    gap: RosterGap,
    annotations_requested: bool,
) -> Result<Option<RosterReadSnapshot>> {
    let Some(count) = gap.bounded_count() else {
        return Ok(None);
    };
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let head: Option<i64> = sqlx::query_scalar(
        "SELECT roster_version FROM users WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled",
    )
    .bind(owner_id)
    .bind(auth_generation)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(head) = head else {
        return Ok(None);
    };
    let (after, through) = (gap.after.0, gap.through.0);
    if through > head {
        return Ok(None);
    }
    let changes = read_journal_range(&mut transaction, owner_id, after, through, true).await?;
    if changes.len() != count
        || !changes
            .iter()
            .zip(after + 1..=through)
            .all(|(change, version)| change.version == version)
    {
        return Ok(None);
    }
    let mix_participants = if annotations_requested && changes.iter().any(|change| !change.removed)
    {
        let mut later = HashSet::new();
        if through != head
            || changes
                .iter()
                .rev()
                .any(|change| !later.insert(&change.contact_jid) && !change.removed)
        {
            return Ok(None);
        }
        if !effects
            .annotations_proven(&mut transaction, owner_id, gap)
            .await?
        {
            return Ok(None);
        }
        effects.mix_participants(&mut transaction, owner_id).await?
    } else {
        HashMap::new()
    };
    transaction.commit().await?;
    Ok(Some(RosterReadSnapshot {
        version: through,
        items: Vec::new(),
        changes: Some(changes),
        mix_participants,
    }))
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
